package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/yaml"
)

var (
	portForwardCmds  = make(map[string]*exec.Cmd)
	portForwardMutex sync.Mutex
)

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Start the UI server",
	Long:  `Start the UI server to manage your Kubernetes application.`,
	Run: func(cmd *cobra.Command, args []string) {
		StartUIServer()
	},
}

func init() {
	rootCmd.AddCommand(uiCmd)
}

func StartUIServer() {
	dir := "./frontend/dist"
	fs := http.FileServer(http.Dir(dir))

	// Serve static assets
	http.Handle("/assets/", fs)

	// API endpoints
	http.HandleFunc("/api/kubeconfig", handleKubeConfig)
	http.HandleFunc("/api/check-multims", handleCheckMultims)
	http.HandleFunc("/api/load-kube-config", loadKubeConfigHandler)
	http.HandleFunc("/api/clusters", getClustersHandler)
	http.HandleFunc("/api/start-port-forward", startPortForwardHandler)
	http.HandleFunc("/api/stop-port-forward", stopPortForwardHandler) // New endpoint to stop port forwarding
	http.HandleFunc("/api/start-external-port-forward", startExternalPortForwardHandler)
	http.HandleFunc("/api/namespaces", getNamespacesHandler) // New endpoint
	http.HandleFunc("/api/services", getServicesHandler)     // New endpoint
	http.HandleFunc("/ws", handleWebSocket)

	// Catch-all handler to serve index.html for any non-asset route
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			fs.ServeHTTP(w, r)
		} else {
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
		}
	})

	port := "9000"
	fmt.Printf("Starting UI server on port %s...\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Printf("Failed to start UI server: %v\n", err)
		os.Exit(1)
	}
}

var cachedConfig *api.Config

func loadKubeConfigHandler(w http.ResponseWriter, r *http.Request) {
	kubeconfigPath := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	config, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		http.Error(w, "Failed to load kube config", http.StatusInternalServerError)
		return
	}

	cachedConfig = config
	clusters := []map[string]string{}
	for name, cluster := range cachedConfig.Clusters {
		clusters = append(clusters, map[string]string{
			"name":   name,
			"server": cluster.Server,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"clusters": clusters})
}

func getClustersHandler(w http.ResponseWriter, r *http.Request) {
	if cachedConfig == nil {
		http.Error(w, "Kube config not loaded", http.StatusBadRequest)
		return
	}

	clusters := []map[string]string{}
	for name, cluster := range cachedConfig.Clusters {
		clusters = append(clusters, map[string]string{
			"name":   name,
			"server": cluster.Server,
		})
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"clusters": clusters})
}

func startPortForwardHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Namespace string `json:"namespace"`
		Service   string `json:"service"`
		LocalPort int    `json:"localPort"`
		Cluster   struct {
			Name string `json:"name"`
			User string `json:"user"`
		} `json:"cluster"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Fetch the target port of the service
	cmdGetPort := exec.Command("kubectl", "--kubeconfig", filepath.Join(os.Getenv("HOME"), ".kube", "config"), "get", "svc", req.Service, "-n", req.Namespace, "-o", "jsonpath='{.spec.ports[0].port}'")
	portOutput, err := cmdGetPort.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get service port: %v - %s", err, string(portOutput)), http.StatusInternalServerError)
		return
	}

	// Remove surrounding single quotes from portOutput
	targetPort := strings.Trim(string(portOutput), "'")

	cmd := exec.Command("kubectl", "--kubeconfig", filepath.Join(os.Getenv("HOME"), ".kube", "config"), "port-forward", fmt.Sprintf("svc/%s", req.Service), fmt.Sprintf("%d:%s", req.LocalPort, targetPort), "-n", req.Namespace)
	err = cmd.Start()
	if err != nil {
		stdoutStderr, _ := cmd.CombinedOutput()
		log.Printf("Failed to start port forward: %v - %s", err, string(stdoutStderr))
		http.Error(w, fmt.Sprintf("Failed to start port forward: %v - %s", err, string(stdoutStderr)), http.StatusInternalServerError)
		return
	}

	log.Printf("Port forward command: %s", strings.Join(cmd.Args, " "))

	// Store the command in the map
	portForwardMutex.Lock()
	portForwardCmds[fmt.Sprintf("%s-%s-%d", req.Namespace, req.Service, req.LocalPort)] = cmd
	portForwardMutex.Unlock()

	go cmd.Wait() // Run command in the background

	w.WriteHeader(http.StatusOK)
}

func stopPortForwardHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Namespace string `json:"namespace"`
		Service   string `json:"service"`
		LocalPort int    `json:"localPort"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	key := fmt.Sprintf("%s-%s-%d", req.Namespace, req.Service, req.LocalPort)
	portForwardMutex.Lock()
	cmd, exists := portForwardCmds[key]
	portForwardMutex.Unlock()

	if !exists {
		http.Error(w, "Port forward not found", http.StatusNotFound)
		return
	}

	if err := cmd.Process.Kill(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to stop port forward: %v", err), http.StatusInternalServerError)
		return
	}

	portForwardMutex.Lock()
	delete(portForwardCmds, key)
	portForwardMutex.Unlock()

	log.Printf("Port forward stopped: %s", key)

	w.WriteHeader(http.StatusOK)
}

func startExternalPortForwardHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host         string `json:"host"`
		ExternalPort int    `json:"externalPort"`
		LocalPort    int    `json:"localPort"`
		Cluster      struct {
			Name string `json:"name"`
			User string `json:"user"`
		} `json:"cluster"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Logic to start external port forwarding
	w.WriteHeader(http.StatusOK)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade WebSocket connection: %v", err)
		return
	}
	defer conn.Close()

	currentDir := ""

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Error reading WebSocket message: %v", err)
			break
		}

		command := strings.TrimSpace(string(msg))
		if command == "" {
			continue
		}
		log.Printf("Received command: %s", command)

		go func(command string) {
			if strings.HasPrefix(command, "cd ") {
				newDir := strings.TrimSpace(command[3:])
				if newDir == ".." {
					currentDir = filepath.Dir(currentDir)
				} else {
					currentDir = filepath.Join(currentDir, newDir)
				}
				conn.WriteMessage(websocket.TextMessage, []byte(""))
				return
			}

			output, err := executeCommand(command, currentDir)
			if err != nil {
				output = fmt.Sprintf("Failed to execute command: %v\n", err)
			}

			output = strings.TrimSpace(output)
			conn.WriteMessage(websocket.TextMessage, []byte(output+"\n"))
		}(command)
	}
}

func executeCommand(command, dir string) (string, error) {
	cmd := exec.Command("sh", "-c", command)
	if dir != "" {
		cmd.Dir = dir
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %s", err, output)
	}
	return string(output), nil
}

func handleCheckMultims(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat("multims.yaml"); err == nil {
		http.Error(w, "multims.yaml found", http.StatusOK)
		return
	} else if os.IsNotExist(err) {
		http.Error(w, "multims.yaml not found", http.StatusNotFound)
		return
	} else {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleKubeConfig(w http.ResponseWriter, r *http.Request) {
	kubeconfigPath := filepath.Join(os.Getenv("HOME"), ".kube", "config")

	data, err := ioutil.ReadFile(kubeconfigPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading kubeconfig: %v", err), http.StatusBadRequest)
		return
	}

	var config api.Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error parsing kubeconfig: %v", err), http.StatusBadRequest)
		return
	}

	// Extract cluster information
	clusters := make(map[string]api.Cluster)
	for clusterName, clusterData := range config.Clusters {
		clusters[clusterName] = *clusterData
	}

	// Convert to JSON format
	jsonData, err := json.Marshal(clusters)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error converting kubeconfig to JSON: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func getNamespacesHandler(w http.ResponseWriter, r *http.Request) {
	if cachedConfig == nil {
		http.Error(w, "Kube config not loaded", http.StatusBadRequest)
		return
	}

	kubeconfigPath := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	cmd := exec.Command("kubectl", "--kubeconfig", kubeconfigPath, "get", "ns", "-o", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to execute kubectl command: %v", err), http.StatusInternalServerError)
		return
	}

	var namespaces struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}

	if err := json.Unmarshal(output, &namespaces); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse kubectl output: %v", err), http.StatusInternalServerError)
		return
	}

	var nsList []string
	for _, ns := range namespaces.Items {
		nsList = append(nsList, ns.Metadata.Name)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"namespaces": nsList})
}

func getServicesHandler(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		http.Error(w, "Namespace is required", http.StatusBadRequest)
		return
	}

	kubeconfigPath := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	cmd := exec.Command("kubectl", "--kubeconfig", kubeconfigPath, "get", "svc", "-n", namespace, "-o", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to execute kubectl command: %v", err), http.StatusInternalServerError)
		return
	}

	var services struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec struct {
				Ports []struct {
					Port int `json:"port"`
				} `json:"ports"`
			} `json:"spec"`
		} `json:"items"`
	}

	if err := json.Unmarshal(output, &services); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse kubectl output: %v", err), http.StatusInternalServerError)
		return
	}

	var svcList []map[string]interface{}
	for _, svc := range services.Items {
		for _, port := range svc.Spec.Ports {
			svcList = append(svcList, map[string]interface{}{
				"name":   svc.Metadata.Name,
				"port":   port.Port,
				"labels": svc.Metadata.Labels,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"services": svcList})
}
