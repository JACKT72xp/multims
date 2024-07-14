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

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/yaml"
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
	http.HandleFunc("/api/start-external-port-forward", startExternalPortForwardHandler)
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
	// Logic to start port forwarding
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
