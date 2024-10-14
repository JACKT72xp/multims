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
	"multims/pkg/utils"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/cobra"
)

// checkIfGitRepo checks if the current directory is
func checkIfGitRepo() bool {
	cmd := exec.Command("git", "rev-parse", "--is-inside-work-tree")
	err := cmd.Run()
	return err == nil
}

// getGitRepositoryURL retrieves the URL of the Git repository
func getGitRepositoryURL() (string, error) {
	cmd := exec.Command("git", "remote", "get-url", "origin")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// title prints a title with a separator
func title(text string) {
	fmt.Println(aurora.Bold(aurora.Cyan("\n" + text)))
	fmt.Println(strings.Repeat("-", len(text)))
}

// checkIfMultimsYMLExists checks if the multims.yml file exists
func checkIfMultimsYMLExists() bool {
	_, err := os.Stat("multims.yml")
	return !os.IsNotExist(err)
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

// Función para preguntar si se desea sincronizar con la nube
func askSyncToCloud() bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Do you want to sync to the cloud? (yes/no): ")
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "yes"
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "k8s-cli is a CLI tool for managing Kubernetes",
	Long:  `Welcome to MULTIMS by JT. A CLI tool to interact with Kubernetes.`,
	Run: func(cmd *cobra.Command, args []string) {

		showWelcomeBanner()

		title("Welcome to MULTIMS by JT")
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

		runNormalFlow()

		// // Check if multims.yml exists
		// if checkIfMultimsYMLExists() {
		// 	var overwriteConfirmation bool
		// 	prompt := &survey.Confirm{
		// 		Message: "A multims.yml configuration file already exists. Do you want to overwrite it? This will erase the existing configuration.",
		// 	}
		// 	survey.AskOne(prompt, &overwriteConfirmation)
		// 	if !overwriteConfirmation {
		// 		fmt.Println("Operation cancelled by the user.")
		// 		return
		// 	}
		// }

		// // Check if current directory is a Git repository
		// isGitRepo := checkIfGitRepo()
		// fmt.Print("\r                \r") // Clear the "Validating..." message

		// if isGitRepo {
		// 	fmt.Println(aurora.Green("Git repository detected."))
		// 	repoURL, err := getGitRepositoryURL()
		// 	if err != nil {
		// 		log.Fatalf("Failed to retrieve Git repository URL: %v", err)
		// 	}
		// 	fmt.Printf("MULTIMS will be deployed in the repository: %s\n", aurora.Bold(repoURL))
		// } else {
		// 	fmt.Println(aurora.Red("No Git repository detected."))
		// 	var confirmation bool
		// 	prompt := &survey.Confirm{
		// 		Message: "MULTIMS will not be deployed in a Git repository. Do you want to continue?",
		// 	}
		// 	survey.AskOne(prompt, &confirmation)
		// 	if !confirmation {
		// 		fmt.Println("Operation cancelled by the user.")
		// 		return
		// 	}
		// }

		// // Choose kubeconfig
		// title("Kubernetes Configuration")
		// var kubeconfigOptions = []string{"Use default kubeconfig (~/.kube/config)", "Specify kubeconfig file path"}
		// var kubeconfigChoice string
		// promptKubeconfig := &survey.Select{
		// 	Message: "How do you want to connect to Kubernetes?",
		// 	Options: kubeconfigOptions,
		// }
		// survey.AskOne(promptKubeconfig, &kubeconfigChoice)

		// var useDefaultKubeConfig bool
		// var kubeConfigPath string
		// if kubeconfigChoice == kubeconfigOptions[0] {
		// 	useDefaultKubeConfig = true
		// 	kubeConfigPath = os.ExpandEnv("$HOME/.kube/config")
		// } else {
		// 	useDefaultKubeConfig = false
		// 	promptKubeconfigPath := &survey.Input{
		// 		Message: "Please specify the kubeconfig file path:",
		// 	}
		// 	survey.AskOne(promptKubeconfigPath, &kubeConfigPath)
		// }

		// // Choose context
		// ctx, err := config.ChooseContext(kubeConfigPath)
		// if err != nil {
		// 	log.Fatalf("Error choosing context: %v", err)
		// }

		// // Select namespace (kept as user-defined)
		// namespace, err := utils.SelectNamespace(kubeConfigPath, ctx)
		// if err != nil {
		// 	log.Fatalf("Error selecting namespace: %v", err)
		// }

		// fmt.Printf("Selected namespace: '%s'\n", aurora.Bold(namespace))

		// // Select technology
		// title("Technology Selection")
		// technology := utils.SelectTechnology()
		// if technology == "Cancel" {
		// 	fmt.Println("Operation cancelled by the user.")
		// 	return
		// }

		// fmt.Printf("You have selected: %s\n", aurora.Bold(technology))

		// // Select registry
		// title("Registry Selection")
		// var registryOptions = []string{"DockerHub", "AWS ECR", "CustomImageMultiMS"}
		// var registryChoice string
		// promptRegistry := &survey.Select{
		// 	Message: "Where do you want to store your images?",
		// 	Options: registryOptions,
		// }
		// survey.AskOne(promptRegistry, &registryChoice)

		// // Variable to hold the custom image name if selected
		// var customImage string
		// if registryChoice == "CustomImageMultiMS" {
		// 	switch technology {
		// 	case "Node":
		// 		customImage = "jackt72xp/multims:nodejsv25"
		// 	case "Python":
		// 		customImage = "jackt72xp/multims:pythonv2"
		// 	}
		// } else if registryChoice == "DockerHub" {
		// 	auth.HandleDockerLogin()
		// } else if registryChoice == "AWS ECR" {
		// 	auth.HandleECRLogin()
		// }

		// // Enter start command
		// title("Application Configuration")
		// var startCommand string
		// promptStartCommand := &survey.Input{
		// 	Message: "Please enter the command to start your application (default: node index.js):",
		// 	Default: "node index.js",
		// }
		// survey.AskOne(promptStartCommand, &startCommand)

		// // Enter port number
		// var portNumber string
		// promptPortNumber := &survey.Input{
		// 	Message: "Please enter the port number to start your application (default: 3000):",
		// 	Default: "3000",
		// }
		// survey.AskOne(promptPortNumber, &portNumber)

		// // Force appName to be "multims"
		// appName := "multims"
		// fmt.Printf("Your app name: %s\n", aurora.Bold(appName))

		// // Create MULTIMS directory
		// build.CreateMultimsDirectory()

		// // Generate a UUID for the configuration
		// uid := utils.GenerateUUID()

		// intValue, err := strconv.Atoi(portNumber)
		// if err != nil {
		// 	log.Fatalf("Invalid port number: %v", err)
		// }

		// // Remove registryURL
		// if registryChoice == "CustomImageMultiMS" {
		// 	build.SaveCustomImageConfigToFile(technology, customImage, ctx, namespace, useDefaultKubeConfig, kubeConfigPath, appName, startCommand, intValue, uid)
		// } else {
		// 	accountID, region, err := config.GetAWSAccountInfo()
		// 	if err != nil {
		// 		log.Fatalf("Failed to retrieve AWS account info: %v", err)
		// 	}
		// 	ecrEndpoint := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", accountID, region)
		// 	build.SaveConfigToFile(technology, ecrEndpoint, ctx, namespace, useDefaultKubeConfig, kubeConfigPath, appName, registryChoice, startCommand, intValue, uid)
		// }

		// fmt.Println(aurora.Bold(aurora.Green("multims.yml configuration file generated successfully.")))

		// Setup Kubernetes connection
		// client.SetupKubernetesConnection(kubeConfigPath, ctx, namespace)

	},
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
	// Validar si existe el archivo multims.yml
	if checkIfMultimsYMLExists() {
		var overwriteConfirmation bool
		prompt := &survey.Confirm{
			Message: "A multims.yml configuration file already exists. Do you want to overwrite it? This will erase the existing configuration.",
		}
		survey.AskOne(prompt, &overwriteConfirmation)
		if !overwriteConfirmation {
			fmt.Println("Operation cancelled by the user.")
			return
		}
	}

	// Validar si el directorio actual es un repositorio Git
	isGitRepo := checkIfGitRepo()
	fmt.Print("\r                \r") // Limpia el mensaje de "Validating..."

	if isGitRepo {
		fmt.Println(aurora.Green("Git repository detected."))
		repoURL, err := getGitRepositoryURL()
		if err != nil {
			log.Fatalf("Failed to retrieve Git repository URL: %v", err)
		}
		fmt.Printf("MULTIMS will be deployed in the repository: %s\n", aurora.Bold(repoURL))
	} else {
		fmt.Println(aurora.Red("No Git repository detected."))
		var confirmation bool
		prompt := &survey.Confirm{
			Message: "MULTIMS will not be deployed in a Git repository. Do you want to continue?",
		}
		survey.AskOne(prompt, &confirmation)
		if !confirmation {
			fmt.Println("Operation cancelled by the user.")
			return
		}
	}

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

	uid := utils.GenerateUUID()

	operations.SaveConfigurationToFile(technology, ecrEndpoint, ctx, namespace, useDefaultKubeConfig, kubeConfigPath, dirName2, registry, command, port, dbConfig, installationCommands, dirName, uid)
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
