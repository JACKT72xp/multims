package operations

import (
	"bufio"
	"fmt"
	"log"
	"multims/pkg/auth"
	"multims/pkg/build"
	"multims/pkg/config"
	"multims/pkg/utils"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/fatih/color"
)

// Función para sincronizar con la nube (por ahora, solo devuelve un mensaje)
func SyncWithCloud(credentials *CloudCredentials) {
	fmt.Println("Hello, World! from SyncWithCloud")
}

func SelectNamespace(kubeConfigPath string, ctx string) string {
	namespace, err := utils.SelectNamespace(kubeConfigPath, ctx)
	if err != nil {
		log.Fatalf("Error selecting namespace: %v", err)
	}
	return namespace
}

func SelectTechnology() string {
	return utils.SelectTechnology()
}

func SelectRegistry() string {
	return utils.SlectRegistry()
}

// checkECRLogin verifica el token de autorización de AWS ECR
func checkECRLogin() bool {
	sess, err := session.NewSession()
	if err != nil {
		log.Println("Error creating AWS session:", err)
		return false
	}

	svc := ecr.New(sess)
	_, err = svc.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		log.Println("Failed to authenticate to AWS ECR:", err)
		return false
	}
	return true
}

// HandleRegistryLogin maneja el login al registro seleccionado
func HandleRegistryLogin(registry string) {
	for {
		switch registry {
		case "DockerHub":
			if auth.HandleDockerLogin() {
				return // Salir del bucle tras login exitoso
			}
			color.Red("❌ Docker Hub login failed. Please try again or choose another option.")
		case "AWS ECR":
			if auth.HandleECRLogin() {
				return // Salir del bucle tras login exitoso
			}
			color.Red("❌ AWS ECR login failed. Please try again or choose another option.")
		case "Sin Registry":
			color.Cyan("ℹ️  No registry selected. Proceeding without container registry login.")
			return // Continuar sin seleccionar un registro
		case "Cancel":
			color.Yellow("Operation cancelled by the user.")
			return
		default:
			color.Red("❌ Invalid option selected.")
		}

		// Repetir el proceso de selección del registro
		registry = SelectRegistry()
	}
}

func AskForInstallationCommands() []string {
	fmt.Println("Would you like to add installation commands to the APK image?")
	fmt.Println("Please enter the commands (separated by commas) or press Enter to skip:")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	commands := strings.Split(input, ",")
	for i := range commands {
		commands[i] = strings.TrimSpace(commands[i])
	}
	return commands
}

func GetCommand(defaultCommand string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Please enter the command to start your application (default: %s): ", defaultCommand)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input:", err)
		return defaultCommand
	}
	input = strings.TrimSpace(input)
	if input == "" {
		input = defaultCommand
	}
	return input
}

func GetPort(defaultPort string) (int, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Please enter the number of port to start your application (default: %s): ", defaultPort)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input:", err)
		return 0, err
	}
	input = strings.TrimSpace(input)
	port, err := strconv.Atoi(strings.TrimSuffix(input, "\n"))
	if err != nil {
		fmt.Printf("Error converting port to integer: %s\n", err)
		return 0, err
	}
	return port, nil
}

func GetCurrentDirectoryName() string {
	currentDir, err := os.Getwd()
	fmt.Println("Current directory:", currentDir)
	if err != nil {
		log.Fatalf("Error getting current directory: %v", err)
	}
	return filepath.Base(currentDir)
}

func CreateMultimsDirectory() {
	build.CreateMultimsDirectory()
}

func HandleAWSECREndpoint(registry string) string {
	if registry == "AWS ECR" {
		accountID, region, err := config.GetAWSAccountInfo()
		if err != nil {
			fmt.Printf("Error getting AWS account info: %s\n", err)
			return ""
		}
		return fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", accountID, region)
	}
	return ""
}

func ConfigureDatabase() config.DatabaseConfig {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Do you need a database for testing in your namespace? (yes/no)")
	dbResponse, _ := reader.ReadString('\n')
	dbResponse = strings.TrimSpace(dbResponse)
	dbConfig := config.DatabaseConfig{}

	if strings.ToLower(dbResponse) == "yes" {
		fmt.Println("Select the type of database:")
		fmt.Println("1. MySQL")
		fmt.Println("2. PostgreSQL")
		fmt.Println("3. MongoDB")
		fmt.Print("Enter your choice (1/2/3): ")
		choiceStr, _ := reader.ReadString('\n')
		choiceStr = strings.TrimSpace(choiceStr)

		choice, err := strconv.Atoi(choiceStr)
		if err != nil || choice < 1 || choice > 3 {
			fmt.Println("Invalid choice. Please enter a valid option.")
			return dbConfig
		}

		var dbType string
		switch choice {
		case 1:
			dbType = "mysql"
		case 2:
			dbType = "postgres"
		case 3:
			dbType = "mongo"
		}

		switch dbType {
		case "mysql":
			return config.DatabaseConfig{
				Type:     "mysql",
				Active:   true,
				DB:       "mysql",
				User:     "root",
				Password: "password",
				Name:     "mydb",
				External: true,
			}
		case "postgres":
			return config.DatabaseConfig{
				Type:     "postgres",
				Active:   true,
				DB:       "postgres",
				User:     "postgres",
				Password: "password",
				Name:     "mydb",
				External: true,
			}
		case "mongo":
			return config.DatabaseConfig{
				Type:     "mongo",
				Active:   true,
				DB:       "mongo",
				User:     "admin",
				Password: "password",
				Name:     "mydb",
				External: true,
			}
		default:
			fmt.Println("Database type not supported.")
		}
	}
	return dbConfig
}

func SaveConfigurationToFile(technology string, ecrEndpoint string, ctx string, namespace string, useDefaultKubeConfig bool, kubeConfigPath string, dirName string, registry string, command string, port int, dbConfig config.DatabaseConfig, installationCommands []string, dir string, uid string) {
	build.SaveConfigToFile(technology, ecrEndpoint, ctx, namespace, useDefaultKubeConfig, kubeConfigPath, dirName, registry, command, port, dbConfig, installationCommands, dir, uid)
}
