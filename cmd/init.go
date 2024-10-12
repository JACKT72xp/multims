package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"multims/operations"
	"multims/pkg/client"
	"multims/pkg/config"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "k8s-cli is a CLI tool for managing Kubernetes",
	Long:  `Welcome to MULTIMS by JT. A CLI tool to interact with Kubernetes.`,
	Run: func(cmd *cobra.Command, args []string) {
		showWelcomeBanner()

		// Verificar si ya existe el archivo ~/.multims con las credenciales
		if checkExistingCredentials() {
			color.Green("✔ Login complete. Using existing credentials.\n")
		} else {
			// Sincronizar con la nube si no existen credenciales guardadas
			if askSyncToCloud() {
				cloudCredentials := operations.GetCloudCredentials()
				if cloudCredentials == nil {
					color.Red("❌ Error: Cloud credentials are required.")
					return
				}
				handleCloudSync(cloudCredentials)
			}
		}

		// Continuar con el flujo normal
		runNormalFlow()
	},
}

// Función para verificar si ya existen credenciales guardadas
func checkExistingCredentials() bool {
	configDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error finding home directory:", err)
		return false
	}
	configPath := filepath.Join(configDir, ".multims")

	// Verificar si el archivo existe
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return false // No existe el archivo, se requiere login
	}

	// Leer y validar el contenido del archivo
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		fmt.Println("Error reading credentials file:", err)
		return false
	}

	// Verificar si el contenido tiene el formato esperado
	var credentials operations.CloudCredentials
	if err := json.Unmarshal(data, &credentials); err != nil || credentials.AccessKey == "" || credentials.SecretKey == "" {
		return false // Formato incorrecto o credenciales incompletas
	}

	return true // El archivo existe y tiene el formato correcto
}

func handleCloudSync(credentials *operations.CloudCredentials) {
	loadedCredentials, err := operations.LoadCredentials()
	if err != nil {
		// Si no se pueden cargar las credenciales, solicita al usuario
		credentials = operations.GetCloudCredentials()
		if credentials == nil {
			color.Red("❌ Error: Cloud credentials are required.")
			return
		}
	} else {
		// Usar credenciales guardadas si están disponibles
		credentials = loadedCredentials
	}

	// Spinner de sincronización con la nube
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	s.Suffix = " Syncing with cloud services..."
	s.Start()
	time.Sleep(2 * time.Second)
	s.Stop()

	color.Green("\n✔ Cloud synchronization completed successfully!\n")
}

// Función para mostrar el banner de bienvenida
func showWelcomeBanner() {
	color.New(color.FgHiMagenta, color.Bold).Println("\n╔══════════════════════════════════════════╗")
	color.New(color.FgHiMagenta, color.Bold).Println("║           WELCOME TO MULTIMS             ║")
	color.New(color.FgHiMagenta, color.Bold).Println("╚══════════════════════════════════════════╝")
	fmt.Println()
	color.New(color.FgHiYellow).Println("Your all-in-one tool for managing Kubernetes clusters effectively and effortlessly!")
	color.New(color.FgHiCyan).Println("-----------------------------------------------------------------------")
	time.Sleep(1 * time.Second)
}

// Función para preguntar si se desea sincronizar con la nube
func askSyncToCloud() bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Do you want to sync to the cloud? (yes/no): ")
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "yes"
}

func printHeader(title string) {
	fmt.Println()
	color.New(color.FgHiCyan).Add(color.Bold).Printf("╔════════════════════════════════╗\n")
	color.New(color.FgHiCyan).Add(color.Bold).Printf("║ %-30s ║\n", title)
	color.New(color.FgHiCyan).Add(color.Bold).Printf("╚════════════════════════════════╝\n")
	color.Yellow("Your all-in-one tool for managing Kubernetes with style!\n")
}
func printSection(title string) {
	fmt.Println()
	color.New(color.FgHiWhite).Add(color.Bold).Printf("╔═ %s ═╗\n", title)
	color.New(color.FgHiWhite).Printf("╚══════════════════════════════════════════╝\n\n")
}

// Flujo normal de inicialización
func runNormalFlow() {
	// Cargar kubeconfig
	printSection("Kubernetes Configuration")
	useDefaultKubeConfig, kubeConfigPath := config.ChooseKubeConfig()
	ctx, err := config.ChooseContext(kubeConfigPath)
	if err != nil {
		log.Fatalf(color.RedString("Error choosing context: %v"), err)
	}

	namespace := operations.SelectNamespace(kubeConfigPath, ctx)
	color.Magenta("🗂 Selected namespace: '%s'", namespace)

	printSection("Technology Selection")
	technology := operations.SelectTechnology()
	if technology == "Cancel" {
		color.Yellow("⚠ Operation cancelled by the user.")
		return
	}
	color.Cyan("💻 You have selected: %s\n", technology)

	// Manejar login al registro
	registry := operations.SelectRegistry()
	operations.HandleRegistryLogin(registry)

	// Obtener comando y puerto
	command := operations.GetCommand("node index.js")
	port, err := operations.GetPort("3000")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Port:", port)

	dirName, err := os.Getwd()
	if err != nil {
		log.Fatalf("Error getting current directory: %v", err)
	}
	dirName2 := filepath.Base(dirName)
	fmt.Printf("Your appName: %s\n", dirName2)

	// Crear directorio MULTIMS
	operations.CreateMultimsDirectory()

	// Manejar endpoint de AWS ECR
	ecrEndpoint := operations.HandleAWSECREndpoint(registry)

	// Configuración de base de datos
	dbConfig := operations.ConfigureDatabase()

	// Comandos de instalación
	installationCommands := operations.AskForInstallationCommands()

	// Guardar configuración a archivo
	configFilePath := filepath.Join(dirName, "multims.yml")
	if _, err := os.Stat(configFilePath); err == nil {
		fmt.Println("A multims.yml file already exists in this directory.")
		fmt.Print("Do you want to overwrite the existing configuration? (yes/no): ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(answer)
		if strings.ToLower(answer) != "yes" {
			fmt.Println("Operation cancelled by the user.")
			return
		}
	}
	operations.SaveConfigurationToFile(technology, ecrEndpoint, ctx, namespace, useDefaultKubeConfig, kubeConfigPath, dirName2, registry, command, port, dbConfig, installationCommands, dirName)
	fmt.Println("Files generated")
	// Validar existencia de la aplicación
	if !validateOrCreateApplication(dirName2) {
		fmt.Println("Process terminated.")
		return
	}
	// Configurar conexión a Kubernetes
	client.SetupKubernetesConnection(kubeConfigPath, ctx, namespace)
}

// CheckApplicationExists verifica si la aplicación ya existe llamando a la API de listar aplicaciones por userId
func CheckApplicationExists(appName string) bool {
	apiURL := fmt.Sprintf("http://localhost:3000/api/v1/applications/user")

	resp, err := http.Get(apiURL)
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var applications []struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&applications); err != nil {
			fmt.Println("Error decoding JSON response:", err)
			return false
		}

		// Verificar si la aplicación con el nombre dado ya existe
		for _, app := range applications {
			if app.Name == appName {
				return true
			}
		}
	}

	return false
}

// // CreateApplication crea una nueva aplicación llamando al endpoint API
// func CreateApplication(appName string) bool {
// 	data := map[string]interface{}{
// 		"name": appName,
// 	}
// 	jsonData, err := json.Marshal(data)
// 	if err != nil {
// 		fmt.Println("Error encoding JSON:", err)
// 		return false
// 	}

// 	// Enviar la solicitud POST a la API de creación de aplicaciones
// 	req, err := http.NewRequest("POST", "http://localhost:3000/api/v1/applications/create", bytes.NewBuffer(jsonData))
// 	req.Header.Set("Content-Type", "application/json")
// 	// Añadir autenticación si es necesario
// 	req.Header.Set("AuthorizationCli", "Base64EncodedCredentials")

// 	client := &http.Client{}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		fmt.Println("Error making HTTP request:", err)
// 		return false
// 	}
// 	defer resp.Body.Close()

// 	return resp.StatusCode == http.StatusOK
// }

func validateOrCreateApplication(appName string) bool {
	// Consultar la existencia de la aplicación
	exists := CheckApplicationExists(appName)
	if exists {
		color.Green("✔ Application '%s' exists. Continuing...\n", appName)
		return true
	}

	// Preguntar si se desea crear la aplicación
	fmt.Printf("Application '%s' does not exist. Do you want to create it? (yes/no): ", appName)
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "yes" {
		fmt.Println("Operation cancelled by the user.")
		return false
	}

	// Crear la aplicación
	if operations.CreateApplication(appName) {
		color.Green("✔ Application '%s' created successfully.\n", appName)
		return true
	}

	color.Red("❌ Failed to create application '%s'.", appName)
	return false
}
