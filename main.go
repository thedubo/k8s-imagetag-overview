package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// DeploymentVersion represents the version information for a single deployment
type DeploymentVersion struct {
	Images map[string]string `json:"images" yaml:"images"`
}

// NamespaceVersions represents all deployments and their versions in a namespace
type NamespaceVersions struct {
	Namespace   string                       `json:"namespace" yaml:"namespace"`
	Deployments map[string]DeploymentVersion `json:",inline" yaml:",inline"`
}

// WebServer holds the web server configuration
type WebServer struct {
	clientset   *kubernetes.Clientset
	port        string
	rateLimiter *RateLimiter
}

// HTTP Content-Type constants
const (
	contentTypeJSON   = "application/json"
	contentTypeYAML   = "text/plain"
	headerContentType = "Content-Type"
)

// Error messages
const (
	internalServerError = "Internal server error"
)

// Rate limiting constants
const (
	maxRequestsPerIP = 60
	rateLimitWindow  = time.Minute
)

// getEnvWithDefault returns the value of the environment variable or a default value if not set
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// RateLimiter holds rate limiting data
type RateLimiter struct {
	requests map[string][]time.Time
	mutex    sync.RWMutex
}

// validateNamespace validates Kubernetes namespace naming rules
func validateNamespace(ns string) error {
	if len(ns) > 63 || len(ns) == 0 {
		return errors.New("namespace must be 1-63 characters long")
	}

	// Kubernetes namespace naming rules: lowercase alphanumeric and hyphens
	// Must start and end with alphanumeric
	matched, err := regexp.MatchString("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", ns)
	if err != nil {
		return err
	}
	if !matched {
		return errors.New("namespace must contain only lowercase letters, numbers, and hyphens, and start/end with alphanumeric")
	}

	// Reserved namespaces
	reserved := []string{"kube-system", "kube-public", "kube-node-lease"}
	for _, r := range reserved {
		if ns == r {
			return fmt.Errorf("namespace '%s' is reserved", ns)
		}
	}

	return nil
}

// setSecurityHeaders adds security headers to HTTP response
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
	}
}

// Allow checks if a request from the given IP should be allowed
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()

	// Clean up old requests
	if requests, exists := rl.requests[ip]; exists {
		var validRequests []time.Time
		for _, reqTime := range requests {
			if now.Sub(reqTime) <= rateLimitWindow {
				validRequests = append(validRequests, reqTime)
			}
		}
		rl.requests[ip] = validRequests
	}

	// Check if limit exceeded
	if len(rl.requests[ip]) >= maxRequestsPerIP {
		return false
	}

	// Add current request
	rl.requests[ip] = append(rl.requests[ip], now)
	return true
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

func main() {
	// Create Kubernetes client
	clientset, err := createKubernetesClient("")
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	server := &WebServer{
		clientset:   clientset,
		port:        getEnvWithDefault("VERSIONAPP_PORT", "3304"),
		rateLimiter: NewRateLimiter(),
	}

	// Set up HTTP routes
	http.HandleFunc("/", server.handleRoot)
	http.HandleFunc("/health", server.handleHealth)

	defaultNamespace := getEnvWithDefault("VERSIONAPP_NAMESPACE", "default")
	log.Printf("Starting Kubernetes Version Monitor web server on port %s", server.port)
	log.Printf("Open http://localhost:%s in your browser", server.port)
	log.Printf("Monitoring namespace: %s (set via VERSIONAPP_NAMESPACE or defaults to 'default')", defaultNamespace)
	log.Fatal(http.ListenAndServe(":"+server.port, nil))
}

func (ws *WebServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set security headers
	setSecurityHeaders(w)

	// Rate limiting
	clientIP := getClientIP(r)
	if !ws.rateLimiter.Allow(clientIP) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	namespace := getEnvWithDefault("VERSIONAPP_NAMESPACE", "default")

	// Validate namespace
	if err := validateNamespace(namespace); err != nil {
		http.Error(w, "Invalid namespace: "+err.Error(), http.StatusBadRequest)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	// Validate format parameter
	validFormats := map[string]bool{"json": true, "yaml": true}
	if !validFormats[format] {
		http.Error(w, "Invalid format parameter", http.StatusBadRequest)
		return
	}

	// Get deployment versions
	versions, err := ws.getDeploymentVersions(namespace)
	if err != nil {
		log.Printf("Error getting deployment versions for namespace %s: %v", namespace, err)
		http.Error(w, internalServerError, http.StatusInternalServerError)
		return
	}

	switch format {
	case "json":
		ws.renderJSON(w, versions)
	case "yaml":
		ws.renderYAML(w, versions)
	default:
		ws.renderJSON(w, versions) // Default to JSON
	}
}

func (ws *WebServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set security headers
	setSecurityHeaders(w)

	// Rate limiting
	clientIP := getClientIP(r)
	if !ws.rateLimiter.Allow(clientIP) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	response := map[string]string{
		"status":  "healthy",
		"service": "kubernetes-version-monitor",
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Health check JSON encoding error: %v", err)
		http.Error(w, internalServerError, http.StatusInternalServerError)
		return
	}
}

func (ws *WebServer) renderJSON(w http.ResponseWriter, versions *NamespaceVersions) {
	// Create simplified output structure
	output := make(map[string]interface{})
	output["namespace"] = versions.Namespace

	for deploymentName, deploymentInfo := range versions.Deployments {
		output[deploymentName] = map[string]interface{}{
			"images": deploymentInfo.Images,
		}
	}

	// Marshal JSON first to catch errors before writing headers
	jsonData, err := json.Marshal(output)
	if err != nil {
		log.Printf("JSON encoding error: %v", err)
		http.Error(w, internalServerError, http.StatusInternalServerError)
		return
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	if _, err := w.Write(jsonData); err != nil {
		log.Printf("JSON write error: %v", err)
	}
}

func (ws *WebServer) renderYAML(w http.ResponseWriter, versions *NamespaceVersions) {
	// Create simplified output structure
	output := make(map[string]interface{})
	output["namespace"] = versions.Namespace

	for deploymentName, deploymentInfo := range versions.Deployments {
		output[deploymentName] = map[string]interface{}{
			"images": deploymentInfo.Images,
		}
	}

	yamlData, err := yaml.Marshal(output)
	if err != nil {
		log.Printf("YAML encoding error: %v", err)
		http.Error(w, internalServerError, http.StatusInternalServerError)
		return
	}

	w.Header().Set(headerContentType, contentTypeYAML)
	if _, err := w.Write(yamlData); err != nil {
		log.Printf("YAML write error: %v", err)
	}
}

// createKubernetesClient creates a Kubernetes clientset
// Prioritizes in-cluster service account configuration when running inside Kubernetes
func createKubernetesClient(kubeconfig string) (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error

	// First, try to use in-cluster config (service account)
	// This is preferred when running inside a Kubernetes cluster
	config, err = rest.InClusterConfig()
	if err == nil {
		log.Println("Using in-cluster configuration (service account)")
		// Successfully created in-cluster config, create clientset
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create clientset with in-cluster config: %w", err)
		}
		return clientset, nil
	}

	log.Printf("In-cluster config not available (%v), trying kubeconfig", err)

	// If in-cluster config fails, fall back to kubeconfig
	if kubeconfig == "" {
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
	}

	if kubeconfig != "" {
		log.Printf("Using kubeconfig file: %s", kubeconfig)
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build config from kubeconfig %s: %w", kubeconfig, err)
		}
	} else {
		return nil, fmt.Errorf("no kubeconfig file found and in-cluster config unavailable")
	}

	// Create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	return clientset, nil
}

// getDeploymentVersions retrieves all deployments and their image versions from a namespace
func (ws *WebServer) getDeploymentVersions(namespace string) (*NamespaceVersions, error) {
	ctx := context.TODO()

	// Get all deployments in the namespace
	deployments, err := ws.clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list deployments in namespace %s: %w", namespace, err)
	}

	versions := &NamespaceVersions{
		Namespace:   namespace,
		Deployments: make(map[string]DeploymentVersion),
	}

	// Extract version information from each deployment
	for _, deployment := range deployments.Items {
		depVersion := DeploymentVersion{
			Images: make(map[string]string),
		}

		// Extract images and versions from containers
		for _, container := range deployment.Spec.Template.Spec.Containers {
			_, imageVersion := parseImage(container.Image)
			depVersion.Images[container.Name] = imageVersion
		}

		// Also check init containers if any
		for _, initContainer := range deployment.Spec.Template.Spec.InitContainers {
			_, imageVersion := parseImage(initContainer.Image)
			depVersion.Images[fmt.Sprintf("init-%s", initContainer.Name)] = imageVersion
		}

		versions.Deployments[deployment.Name] = depVersion
	}

	return versions, nil
}

// parseImage splits an image string into name and version/tag
// Handles registry URLs with ports correctly (e.g., registry.com:5000/org/image:tag)
func parseImage(image string) (name, version string) {
	name, version = splitImageAndTag(image)
	name = extractImageName(name)
	return name, version
}

// splitImageAndTag separates the image path from the tag
func splitImageAndTag(image string) (imagePath, tag string) {
	// Look for tag separator by finding the last colon that's not part of a port
	lastColonIndex := findTagSeparator(image)

	if lastColonIndex != -1 {
		return image[:lastColonIndex], image[lastColonIndex+1:]
	}

	return image, "latest"
}

// findTagSeparator finds the colon that separates the tag from the image path
func findTagSeparator(image string) int {
	// Start from the end and look for a colon that's not a port number
	for i := len(image) - 1; i >= 0; i-- {
		if image[i] == ':' {
			afterColon := image[i+1:]

			// Check if there's a slash after this colon (indicates it's not a tag)
			if strings.Contains(afterColon, "/") {
				// This colon has a slash after it, likely part of registry:port/path
				continue
			}

			// No slash after colon, this is likely the tag separator
			return i
		}
	}

	return -1
}

// extractImageName gets the final component of the image path
func extractImageName(imagePath string) string {
	parts := strings.Split(imagePath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return imagePath
}
