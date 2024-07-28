package cmd

import (
	"database/sql"
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
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3" // Importa el paquete SQLite
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/yaml"
)

var (
	portForwardCmds  = make(map[string]*exec.Cmd)
	portForwardMutex sync.Mutex
	db               *sql.DB
)

// Función para eliminar la tabla portforwardsv4
func deleteTableHandler(w http.ResponseWriter, r *http.Request) {
	_, err := db.Exec("DROP TABLE IF EXISTS portforwardsv4")
	if err != nil {
		log.Printf("Failed to delete table: %v", err)
		http.Error(w, "Failed to delete table", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Table deleted successfully")
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./portforwardsv4.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	sqlStmt := `
		CREATE TABLE IF NOT EXISTS portforwardsv4 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            localPort INTEGER NOT NULL,
            podName TEXT NOT NULL,
            pid INTEGER,
            status TEXT NOT NULL,
            namespace TEXT NOT NULL
        );
	`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}
}

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Start the UI server",
	Long:  `Start the UI server to manage your Kubernetes application.`,
	Run: func(cmd *cobra.Command, args []string) {
		initDB()
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
	http.HandleFunc("/api/stop-port-forward", stopPortForwardHandler)
	http.HandleFunc("/api/start-external-port-forward", startExternalPortForwardHandler)
	http.HandleFunc("/api/stop-external-port-forward", stopExternalPortForwardHandler)
	http.HandleFunc("/api/delete-external-port-forward", deleteExternalPortForwardHandler)
	http.HandleFunc("/api/validate-external-service", validateExternalServiceHandler)
	http.HandleFunc("/api/namespaces", getNamespacesHandler)
	http.HandleFunc("/api/services", getServicesHandler)
	http.HandleFunc("/api/sessions", getSessionsHandler)
	http.HandleFunc("/api/delete-table", deleteTableHandler)
	http.HandleFunc("/api/register-external-port-forward", registerExternalPortForwardHandler)
	http.HandleFunc("/ws", handleWebSocket)
	http.HandleFunc("/api/load-kube-config-default", loadKubeConfigDefaultHandler)

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

type Cluster struct {
	Name   string `json:"name"`
	Server string `json:"server"`
}

type Response struct {
	Clusters []Cluster `json:"clusters"`
}

func loadKubeConfigDefaultHandler(w http.ResponseWriter, r *http.Request) {
	home, err := os.UserHomeDir()
	if err != nil {
		http.Error(w, "Failed to get home directory: "+err.Error(), http.StatusInternalServerError)
		return
	}

	kubeConfigPath := filepath.Join(home, ".kube", "config")
	fileBytes, err := ioutil.ReadFile(kubeConfigPath)
	if err != nil {
		http.Error(w, "Failed to read kubeconfig: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var kubeConfig KubeConfig
	if err := yaml.Unmarshal(fileBytes, &kubeConfig); err != nil {
		http.Error(w, "Failed to parse kubeconfig: "+err.Error(), http.StatusInternalServerError)
		return
	}

	contexts := []map[string]string{}
	for _, context := range kubeConfig.Contexts {
		contexts = append(contexts, map[string]string{
			"name":    context.Name,
			"cluster": context.Context.Cluster,
		})
	}

	response := map[string]interface{}{
		"contexts": contexts,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
	}
}

type KubeConfig struct {
	Clusters []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server string `yaml:"server"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
		} `yaml:"context"`
	} `yaml:"contexts"`
}

func loadKubeConfigHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("kubeconfig")
	if err != nil {
		http.Error(w, "Failed to get form file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var kubeConfig KubeConfig
	if err := yaml.Unmarshal(fileBytes, &kubeConfig); err != nil {
		http.Error(w, "Failed to parse kubeconfig: "+err.Error(), http.StatusInternalServerError)
		return
	}

	contexts := []map[string]string{}
	for _, context := range kubeConfig.Contexts {
		contexts = append(contexts, map[string]string{
			"name":    context.Name,
			"cluster": context.Context.Cluster,
		})
	}

	response := map[string]interface{}{
		"contexts": contexts,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
	}
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
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	portForwardCmd := exec.Command("kubectl", "port-forward", fmt.Sprintf("svc/%s", req.Service), fmt.Sprintf("%d:%d", req.LocalPort, req.LocalPort), "-n", req.Namespace)
	if err := portForwardCmd.Start(); err != nil {
		stdoutStderr, _ := portForwardCmd.CombinedOutput()
		log.Printf("Failed to start port forward: %v - %s", err, string(stdoutStderr))
		http.Error(w, fmt.Sprintf("Failed to start port forward: %v - %s", err, string(stdoutStderr)), http.StatusInternalServerError)
		return
	}

	pid := portForwardCmd.Process.Pid

	portForwardMutex.Lock()
	portForwardCmds[fmt.Sprintf("%s-%d", req.Service, req.LocalPort)] = portForwardCmd
	portForwardMutex.Unlock()

	go func() {
		portForwardCmd.Wait()
		portForwardMutex.Lock()
		delete(portForwardCmds, fmt.Sprintf("%s-%d", req.Service, req.LocalPort))
		portForwardMutex.Unlock()
	}()

	_, err := db.Exec("INSERT INTO portforwardsv4 (host, port, localPort, pid, status) VALUES (?, ?, ?, ?, ?)", req.Service, req.LocalPort, req.LocalPort, pid, "running")
	if err != nil {
		log.Printf("Failed to insert record into database: %v", err)
		http.Error(w, "Failed to record session in database", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func stopPortForwardHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Service   string `json:"service"`
		LocalPort int    `json:"localPort"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	key := fmt.Sprintf("%s-%d", req.Service, req.LocalPort)
	portForwardMutex.Lock()
	cmd, exists := portForwardCmds[key]
	portForwardMutex.Unlock()

	if !exists {
		var pid int
		err := db.QueryRow("SELECT pid FROM portforwardsv4 WHERE host = ? AND localPort = ?", req.Service, req.LocalPort).Scan(&pid)
		if err != nil {
			http.Error(w, "Port forward not found", http.StatusNotFound)
			return
		}

		process, err := os.FindProcess(pid)
		if err == nil {
			err = process.Kill()
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to stop port forward: %v", err), http.StatusInternalServerError)
				return
			}
		}

		_, err = db.Exec("DELETE FROM portforwardsv4 WHERE host = ? AND localPort = ?", req.Service, req.LocalPort)
		if err != nil {
			log.Printf("Failed to delete record from database: %v", err)
			http.Error(w, "Failed to delete session from database", http.StatusInternalServerError)
			return
		}

		http.Error(w, "Port forward not found and removed from database", http.StatusNotFound)
		return
	}

	if err := cmd.Process.Kill(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to stop port forward: %v", err), http.StatusInternalServerError)
		return
	}

	portForwardMutex.Lock()
	delete(portForwardCmds, key)
	portForwardMutex.Unlock()

	_, err := db.Exec("UPDATE portforwardsv4 SET status = ? WHERE host = ? AND localPort = ?", "stopped", req.Service, req.LocalPort)
	if err != nil {
		log.Printf("Failed to update record in database: %v", err)
		http.Error(w, "Failed to update session in database", http.StatusInternalServerError)
		return
	}

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

func validateExternalServiceHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		Context     string `json:"context"`
		ClusterName string `json:"clusterName"`
		Kubeconfig  string `json:"kubeconfig"` // Añadir ruta del kubeconfig si es proporcionado
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Usar kubeconfig proporcionado o el predeterminado
	kubeconfigPath := req.Kubeconfig
	if kubeconfigPath == "" {
		kubeconfigPath = filepath.Join(os.Getenv("HOME"), ".kube", "config")
	}

	// Crear un archivo temporal de kubeconfig
	tmpFile, err := ioutil.TempFile(os.TempDir(), "kubeconfig-*.yaml")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create temp file: %v", err), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpFile.Name())

	kubeconfigData, err := ioutil.ReadFile(kubeconfigPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read kubeconfig: %v", err), http.StatusInternalServerError)
		return
	}

	if _, err := tmpFile.Write(kubeconfigData); err != nil {
		http.Error(w, fmt.Sprintf("Failed to write to temp file: %v", err), http.StatusInternalServerError)
		return
	}
	tmpFile.Close()

	// Cambiar el contexto usando kubectl
	cmd := exec.Command("kubectl", "--kubeconfig", tmpFile.Name(), "config", "use-context", req.Context)
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to change context: %v", err)
		http.Error(w, fmt.Sprintf("Failed to change context: %v", err), http.StatusInternalServerError)
		return
	}

	// Ejecutar el comando kubectl usando el archivo temporal de kubeconfig
	cmd = exec.Command("kubectl", "--kubeconfig", tmpFile.Name(), "run", "--rm", "-i", "temp-pod", "--image=busybox", "--restart=Never", "--", "sh", "-c", fmt.Sprintf("nc -zv %s %d", req.Host, req.Port))
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to validate external service: %v - %s", err, string(stdoutStderr))
		http.Error(w, fmt.Sprintf("Failed to validate external service: %v - %s", err, string(stdoutStderr)), http.StatusInternalServerError)
		return
	}

	log.Printf("Validation command output: %s", string(stdoutStderr))

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "External service validated successfully")
}

// func startExternalPortForwardHandler(w http.ResponseWriter, r *http.Request) {
// 	var req struct {
// 		Host      string `json:"host"`
// 		Port      int    `json:"port"`
// 		LocalPort int    `json:"localPort"`
// 	}
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	podName := fmt.Sprintf("temp-pod-forward-%d", req.LocalPort)

// 	// YAML para el pod efímero
// 	podYaml := fmt.Sprintf(`
// apiVersion: v1
// kind: Pod
// metadata:
//   name: %s
// spec:
//   containers:
//   - name: socat
//     image: alpine/socat
//     args: ["tcp-listen:%d,reuseaddr,fork", "tcp-connect:%s:%d"]
//     ports:
//     - containerPort: %d
//   restartPolicy: Never
// `, podName, req.LocalPort, req.Host, req.Port, req.LocalPort)

// 	// Aplicar el pod en el cluster
// 	cmd := exec.Command("kubectl", "apply", "-f", "-")
// 	cmd.Stdin = strings.NewReader(podYaml)
// 	stdoutStderr, err := cmd.CombinedOutput()
// 	if err != nil {
// 		log.Printf("Failed to create pod: %v - %s", err, string(stdoutStderr))
// 		http.Error(w, fmt.Sprintf("Failed to create pod: %v - %s", err, string(stdoutStderr)), http.StatusInternalServerError)
// 		return
// 	}

// 	// Esperar a que el pod esté listo
// 	time.Sleep(10 * time.Second) // Ajustar según sea necesario

// 	// Configurar el port-forward
// 	portForwardCmd := exec.Command("kubectl", "port-forward", fmt.Sprintf("pod/%s", podName), fmt.Sprintf("%d:%d", req.LocalPort, req.LocalPort))
// 	err = portForwardCmd.Start()
// 	if err != nil {
// 		stdoutStderr, _ := portForwardCmd.CombinedOutput()
// 		log.Printf("Failed to start port forward: %v - %s", err, string(stdoutStderr))
// 		http.Error(w, fmt.Sprintf("Failed to start port forward: %v - %s", err, string(stdoutStderr)), http.StatusInternalServerError)
// 		return
// 	}

// 	// Almacenar el comando en el mapa
// 	portForwardMutex.Lock()
// 	portForwardCmds[fmt.Sprintf("%s-%d", req.Host, req.LocalPort)] = portForwardCmd
// 	portForwardMutex.Unlock()

// 	go portForwardCmd.Wait() // Ejecutar el comando en segundo plano

// 	w.WriteHeader(http.StatusOK)
// }

// func stopExternalPortForwardHandler(w http.ResponseWriter, r *http.Request) {
// 	var req struct {
// 		Host      string `json:"host"`
// 		Port      int    `json:"port"`
// 		LocalPort int    `json:"localPort"`
// 	}
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	key := fmt.Sprintf("%s-%d", req.Host, req.LocalPort)
// 	portForwardMutex.Lock()
// 	cmd, exists := portForwardCmds[key]
// 	portForwardMutex.Unlock()

// 	if !exists {
// 		http.Error(w, "Port forward not found", http.StatusNotFound)
// 		return
// 	}

// 	if err := cmd.Process.Kill(); err != nil {
// 		http.Error(w, fmt.Sprintf("Failed to stop port forward: %v", err), http.StatusInternalServerError)
// 		return
// 	}

// 	portForwardMutex.Lock()
// 	delete(portForwardCmds, key)
// 	portForwardMutex.Unlock()

// 	// Eliminar el pod
// 	deleteCmd := exec.Command("kubectl", "delete", "pod", fmt.Sprintf("temp-pod-forward-%d", req.LocalPort))
// 	stdoutStderr, err := deleteCmd.CombinedOutput()
// 	if err != nil {
// 		log.Printf("Failed to delete pod: %v - %s", err, string(stdoutStderr))
// 		http.Error(w, fmt.Sprintf("Failed to delete pod: %v - %s", err, string(stdoutStderr)), http.StatusInternalServerError)
// 		return
// 	}

// 	w.WriteHeader(http.StatusOK)
// }

func registerExternalPortForwardHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host      string `json:"host"`
		Port      int    `json:"port"`
		LocalPort int    `json:"localPort"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	podUUID := uuid.New().String()
	podName := fmt.Sprintf("temp-pod-forward-%s", podUUID)

	_, err := db.Exec("INSERT INTO portforwardsv4 (host, port, localPort, podName, status) VALUES (?, ?, ?, ?, ?)", req.Host, req.Port, req.LocalPort, podName, "registered")
	if err != nil {
		log.Printf("Failed to insert record into database: %v", err)
		http.Error(w, "Failed to record session in database", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Port forward registered successfully")
}

func startExternalPortForwardHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host        string `json:"host"`
		LocalPort   int    `json:"localPort"`
		Port        int    `json:"port"`
		Context     string `json:"context"`
		ClusterName string `json:"clusterName"`
		Namespace   string `json:"namespace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Set default namespace if not provided
	if req.Namespace == "" {
		req.Namespace = "default"
	}

	// Cambiar el contexto usando kubectl
	cmd := exec.Command("kubectl", "config", "use-context", req.Context)
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to change context: %v", err)
		http.Error(w, fmt.Sprintf("Failed to change context: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate a unique pod name using UUID
	podUUID := uuid.New().String()
	podName := fmt.Sprintf("external-port-%s", podUUID[:8])

	// Insert the podName into the database without pid
	_, err := db.Exec("INSERT INTO portforwardsv4 (host, port, localPort, podName, namespace, status) VALUES (?, ?, ?, ?, ?, ?)", req.Host, req.Port, req.LocalPort, podName, req.Namespace, "pending")
	if err != nil {
		log.Printf("Failed to insert record into database: %v", err)
		http.Error(w, "Failed to insert pod name into database", http.StatusInternalServerError)
		return
	}

	// Create a YAML definition for the pod
	podYaml := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  activeDeadlineSeconds: 43200
  containers:
  - name: socat
    image: alpine/socat
    command: ["socat"]
    args: ["tcp-listen:%d,reuseaddr,fork", "tcp-connect:%s:%d"]
    ports:
    - containerPort: %d
  restartPolicy: Never
`, podName, req.Namespace, req.LocalPort, req.Host, req.Port, req.LocalPort)

	// Apply the pod YAML
	cmd = exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(podYaml)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to create pod: %v - %s", err, string(stdoutStderr))
		http.Error(w, fmt.Sprintf("Failed to create pod: %v - %s", err, string(stdoutStderr)), http.StatusInternalServerError)
		return
	}

	// Wait for the pod to be ready
	time.Sleep(15 * time.Second)

	// Check the pod status
	cmd = exec.Command("kubectl", "get", "pod", podName, "-n", req.Namespace, "-o", "jsonpath={.status.phase}")
	podStatus, err := cmd.CombinedOutput()
	if err != nil || string(podStatus) != "Running" {
		log.Printf("Pod is not running: %s", string(podStatus))
		http.Error(w, fmt.Sprintf("Pod is not running: %s", string(podStatus)), http.StatusInternalServerError)
		return
	}

	// Start port forwarding in a goroutine
	go func() {
		portForwardCmd := exec.Command("kubectl", "port-forward", fmt.Sprintf("pod/%s", podName), fmt.Sprintf("%d:%d", req.LocalPort, req.LocalPort), "-n", req.Namespace)
		output, err := portForwardCmd.CombinedOutput()
		if err != nil {
			log.Printf("Failed to start port forward: %v - %s", err, string(output))
		} else {
			log.Printf("Port forward started successfully: %s", string(output))
		}
	}()

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Port forward started successfully")
}

func stopExternalPortForwardHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host      string `json:"host"`
		LocalPort int    `json:"localPort"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var pid int
	err := db.QueryRow("SELECT pid FROM portforwardsv4 WHERE host = ? AND localPort = ?", req.Host, req.LocalPort).Scan(&pid)
	if err != nil {
		log.Printf("Failed to query pid from database: %v", err)
		http.Error(w, "Failed to query pid from database", http.StatusInternalServerError)
		return
	}

	key := fmt.Sprintf("%s-%d", req.Host, req.LocalPort)
	portForwardMutex.Lock()
	cmd, exists := portForwardCmds[key]
	portForwardMutex.Unlock()

	if exists {
		if err := cmd.Process.Kill(); err != nil {
			http.Error(w, fmt.Sprintf("Failed to stop port forward: %v", err), http.StatusInternalServerError)
			return
		}

		portForwardMutex.Lock()
		delete(portForwardCmds, key)
		portForwardMutex.Unlock()
	} else {
		process, err := os.FindProcess(pid)
		if err == nil {
			err = process.Kill()
			if err != nil {
				log.Printf("Failed to kill process with pid %d: %v", pid, err)
				http.Error(w, fmt.Sprintf("Failed to kill process: %v", err), http.StatusInternalServerError)
				return
			}
		} else {
			log.Printf("Failed to find process with pid %d: %v", pid, err)
		}
	}

	_, err = db.Exec("UPDATE portforwardsv4 SET status = ? WHERE host = ? AND localPort = ?", "stopped", req.Host, req.LocalPort)
	if err != nil {
		log.Printf("Failed to update record in database: %v", err)
		http.Error(w, "Failed to update session in database", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Port forward stopped successfully")
}

func deleteExternalPortForwardHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host      string `json:"host"`
		LocalPort int    `json:"localPort"`
		Context   string `json:"context"`
		Namespace string `json:"namespace"`
		PodName   string `json:"podName"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Usar "default" si no se proporciona un namespace
	if req.Namespace == "" {
		req.Namespace = "default"
	}

	var podName string
	var pid sql.NullInt64
	err := db.QueryRow("SELECT podName, pid, namespace FROM portforwardsv4 WHERE host = ? AND localPort = ?", req.Host, req.LocalPort).Scan(&podName, &pid, &req.Namespace)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("No rows found for host %s and localPort %d, using provided podName: %s", req.Host, req.LocalPort, req.PodName)
			// Si no se encuentra una fila, usar el podName de la solicitud
			podName = req.PodName
		} else {
			log.Printf("Failed to query pod name and pid from database: %v", err)
			http.Error(w, fmt.Sprintf("Failed to query pod name and pid from database: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		log.Printf("Query succeeded: podName=%s, pid=%v", podName, pid)
	}

	// Asegurarse de que podName no esté vacío
	if podName == "" {
		http.Error(w, "Pod name is empty", http.StatusBadRequest)
		log.Println("Pod name is empty")
		return
	}

	key := fmt.Sprintf("%s-%d", req.Host, req.LocalPort)
	portForwardMutex.Lock()
	cmd, exists := portForwardCmds[key]
	portForwardMutex.Unlock()

	if exists {
		if err := cmd.Process.Kill(); err != nil && !strings.Contains(err.Error(), "process already finished") {
			log.Printf("Failed to kill process: %v", err)
			http.Error(w, fmt.Sprintf("Failed to stop port forward: %v", err), http.StatusInternalServerError)
			return
		}
		portForwardMutex.Lock()
		delete(portForwardCmds, key)
		portForwardMutex.Unlock()
	} else if pid.Valid {
		process, err := os.FindProcess(int(pid.Int64))
		if err == nil {
			err = process.Kill()
			if err != nil && !strings.Contains(err.Error(), "process already finished") && !strings.Contains(err.Error(), "process not initialized") {
				log.Printf("Failed to kill process with pid %d: %v", pid.Int64, err)
				http.Error(w, fmt.Sprintf("Failed to kill process: %v", err), http.StatusInternalServerError)
				return
			}
		} else {
			log.Printf("Failed to find process with pid %d: %v", pid.Int64, err)
		}
	}

	_, err = db.Exec("DELETE FROM portforwardsv4 WHERE host = ? AND localPort = ?", req.Host, req.LocalPort)
	if err != nil {
		log.Printf("Failed to delete record from database: %v", err)
		http.Error(w, "Failed to delete session from database", http.StatusInternalServerError)
		return
	}

	// Verificar si el pod existe solo si podName no está vacío
	if podName != "" {
		checkPodCmd := exec.Command("kubectl", "get", "pod", podName, "--namespace", req.Namespace, "--context", req.Context)
		if output, err := checkPodCmd.CombinedOutput(); err != nil {
			log.Printf("Pod check failed: %v - %s", err, output)
		} else {
			log.Printf("Pod exists: %s", output)

			// Eliminar el pod usando el contexto especificado
			deleteCmd := exec.Command("kubectl", "delete", "pod", podName, "--namespace", req.Namespace, "--context", req.Context)
			stdoutStderr, err := deleteCmd.CombinedOutput()
			if err != nil && !strings.Contains(string(stdoutStderr), "NotFound") {
				log.Printf("Failed to delete pod: %v - %s", err, string(stdoutStderr))
				http.Error(w, fmt.Sprintf("Failed to delete pod: %v - %s", err, string(stdoutStderr)), http.StatusInternalServerError)
				return
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Pod and port forward deleted successfully")
}

func getSessionsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, host, port, localPort, podName, startedAt, status FROM portforwardsv4")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to query sessions: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var sessions []map[string]interface{}
	for rows.Next() {
		var id int
		var host, podName, status string
		var port, localPort int
		var startedAt time.Time

		if err := rows.Scan(&id, &host, &port, &localPort, &podName, &startedAt, &status); err != nil {
			http.Error(w, fmt.Sprintf("Failed to scan session: %v", err), http.StatusInternalServerError)
			return
		}

		session := map[string]interface{}{
			"id":        id,
			"host":      host,
			"port":      port,
			"localPort": localPort,
			"podName":   podName,
			"startedAt": startedAt,
			"status":    status,
		}
		sessions = append(sessions, session)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sessions); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode sessions: %v", err), http.StatusInternalServerError)
	}
}
