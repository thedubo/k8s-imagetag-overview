package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
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

// HTMLTemplateData holds data for HTML template
type HTMLTemplateData struct {
	Namespace   string
	Deployments map[string]DeploymentVersion
	Error       string
}

// HTTP Content-Type constants
const (
	contentTypeJSON   = "application/json"
	contentTypeHTML   = "text/html"
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

const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Kubernetes Version Monitor</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        .namespace-info {
            background: #e8f4fd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
        }
        .deployment {
            margin-bottom: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
        }
        .deployment-header {
            background: #326ce5;
            color: white;
            padding: 15px;
            font-weight: bold;
            font-size: 16px;
        }
        .images {
            padding: 15px;
        }
        .image-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }
        .image-row:last-child {
            border-bottom: none;
        }
        .image-name {
            font-weight: 500;
            color: #555;
        }
        .image-version {
            font-family: 'Monaco', 'Menlo', monospace;
            background: #f8f9fa;
            padding: 4px 8px;
            border-radius: 3px;
            color: #d73a49;
            font-size: 14px;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .format-links {
            text-align: center;
            margin-bottom: 20px;
        }
        .format-links a {
            margin: 0 10px;
            padding: 8px 16px;
            text-decoration: none;
            background: #6c757d;
            color: white;
            border-radius: 4px;
            font-size: 14px;
        }
        .format-links a:hover {
            background: #545b62;
        }
        .no-deployments {
            text-align: center;
            color: #666;
            padding: 40px;
            font-style: italic;
        }
        .namespace-form {
            text-align: center;
            margin-bottom: 20px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .namespace-form input {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-right: 10px;
            font-size: 14px;
            width: 200px;
        }
        .namespace-form button {
            padding: 8px 16px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .namespace-form button:hover {
            background: #0056b3;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Kubernetes Version Monitor</h1>
        
        <div class="namespace-form">
            <form method="GET">
                <input type="text" name="namespace" placeholder="Enter namespace..." value="{{.Namespace | html}}" />
                <button type="submit">Monitor Namespace</button>
            </form>
        </div>
        
        {{if .Error}}
        <div class="error">
            <strong>Error:</strong> {{.Error | html}}
        </div>
        {{else}}
        <div class="namespace-info">
            <strong>Namespace:</strong> {{.Namespace | html}}
        </div>
        
        <div class="format-links">
            <a href="?namespace={{.Namespace | urlquery}}&format=html">HTML View</a>
            <a href="?namespace={{.Namespace | urlquery}}&format=json">JSON (Default)</a>
            <a href="?namespace={{.Namespace | urlquery}}&format=yaml">YAML</a>
            <a href="?namespace={{.Namespace | urlquery}}">Refresh</a>
        </div>
        
        {{if .Deployments}}
        {{range $deploymentName, $deployment := .Deployments}}
        <div class="deployment">
            <div class="deployment-header">
                📦 {{$deploymentName | html}}
            </div>
            <div class="images">
                {{range $containerName, $version := $deployment.Images}}
                <div class="image-row">
                    <span class="image-name">{{$containerName | html}}</span>
                    <span class="image-version">{{$version | html}}</span>
                </div>
                {{end}}
            </div>
        </div>
        {{end}}
        {{else}}
        <div class="no-deployments">
            No deployments found in this namespace.
        </div>
        {{end}}
        {{end}}
    </div>
</body>
</html>
`

func main() {
	// Create Kubernetes client
	clientset, err := createKubernetesClient("")
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	server := &WebServer{
		clientset:   clientset,
		port:        "3304",
		rateLimiter: NewRateLimiter(),
	}

	// Set up HTTP routes
	http.HandleFunc("/", server.handleRoot)
	http.HandleFunc("/health", server.handleHealth)

	log.Printf("Starting Kubernetes Version Monitor web server on port %s", server.port)
	log.Printf("Open http://localhost:%s in your browser", server.port)
	log.Printf("Add ?namespace=your-namespace to monitor specific namespaces")
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

	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "default"
	}

	// Validate namespace
	if err := validateNamespace(namespace); err != nil {
		format := r.URL.Query().Get("format")
		if format == "html" {
			ws.renderHTML(w, &HTMLTemplateData{
				Namespace: namespace,
				Error:     "Invalid namespace: " + err.Error(),
			})
		} else {
			http.Error(w, "Invalid namespace: "+err.Error(), http.StatusBadRequest)
		}
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	// Validate format parameter
	validFormats := map[string]bool{"json": true, "yaml": true, "html": true}
	if !validFormats[format] {
		http.Error(w, "Invalid format parameter", http.StatusBadRequest)
		return
	}

	// Get deployment versions
	versions, err := ws.getDeploymentVersions(namespace)
	if err != nil {
		log.Printf("Error getting deployment versions for namespace %s: %v", namespace, err)
		if format == "html" {
			ws.renderHTML(w, &HTMLTemplateData{
				Namespace: namespace,
				Error:     "Unable to retrieve deployment information",
			})
		} else {
			http.Error(w, internalServerError, http.StatusInternalServerError)
		}
		return
	}

	switch format {
	case "json":
		ws.renderJSON(w, versions)
	case "yaml":
		ws.renderYAML(w, versions)
	default:
		ws.renderHTML(w, &HTMLTemplateData{
			Namespace:   versions.Namespace,
			Deployments: versions.Deployments,
		})
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

func (ws *WebServer) renderHTML(w http.ResponseWriter, data *HTMLTemplateData) {
	tmpl, err := template.New("index").Parse(htmlTemplate)
	if err != nil {
		log.Printf("Template parsing error: %v", err)
		http.Error(w, internalServerError, http.StatusInternalServerError)
		return
	}

	w.Header().Set(headerContentType, contentTypeHTML)
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
		// Can't send error response after headers are written, just log it
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
