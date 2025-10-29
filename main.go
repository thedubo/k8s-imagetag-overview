package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// DeploymentVersion represents the version information for a single deployment
type DeploymentVersion struct {
	Images map[string]string `json:"images"`
}

// NamespaceVersions represents all deployments and their versions in a namespace
type NamespaceVersions struct {
	Deployments map[string]DeploymentVersion `json:",inline"`
}

// WebServer holds the web server configuration
type WebServer struct {
	clientset *kubernetes.Clientset
	port      string
}

// HTTP Content-Type constants
const (
	contentTypeJSON   = "application/json"
	headerContentType = "Content-Type"
)

// getEnvWithDefault returns the value of the environment variable or a default value if not set
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	// Create Kubernetes client
	clientset, err := createKubernetesClient("")
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	server := &WebServer{
		clientset: clientset,
		port:      getEnvWithDefault("VERSIONAPP_PORT", "3304"),
	}

	// Set up HTTP routes
	http.HandleFunc("/", server.handleRoot)

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

	namespace := getEnvWithDefault("VERSIONAPP_NAMESPACE", "default")

	// Get deployment versions
	versions, err := ws.getDeploymentVersions(namespace)
	if err != nil {
		log.Printf("Error getting deployment versions for namespace %s: %v", namespace, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ws.renderJSON(w, versions)
}

func (ws *WebServer) renderJSON(w http.ResponseWriter, versions *NamespaceVersions) {
    // Create simplified output structure
    deployments := make([]map[string]interface{}, 0)
    for deploymentName, deploymentInfo := range versions.Deployments {
        applications := make([]map[string]string, 0)
        for applicationName, applicationVersion := range deploymentInfo.Images {
            applications = append(applications, map[string]string{
                "name":    applicationName,
                "version": applicationVersion,
            })
        }
        deployments = append(deployments, map[string]interface{}{
            "deployment": deploymentName,
            "applications":     applications,
        })
    }

    output := map[string]interface{}{
        "deployments": deployments,
    }

	// Marshal JSON first to catch errors before writing headers
	jsonData, err := json.Marshal(output)
	if err != nil {
		log.Printf("JSON encoding error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	if _, err := w.Write(jsonData); err != nil {
		log.Printf("JSON write error: %v", err)
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
