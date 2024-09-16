package cmd

import (
	"bufio"
	"fmt"
	"log"
	"multims/logging"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Define el comando logging
var loggingCmd = &cobra.Command{
	Use:   "logging",
	Short: "Manage Kubernetes logging",
	Long:  `The logging command allows you to configure and view logs from Kubernetes deployments.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Verificar si el archivo multims.yml existe y contiene el contexto
		if loadKubernetesContext() {
			loggingMenu()
		} else {
			fmt.Println("Error: multims.yml file not found or context not set.")
		}
	},
}

func init() {
	rootCmd.AddCommand(loggingCmd)
}

// Cargar el contexto de Kubernetes desde multims.yml
func loadKubernetesContext() bool {
	viper.SetConfigName("multims")
	viper.SetConfigType("yml")
	viper.AddConfigPath(".") // Buscamos el archivo en el directorio actual

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Error loading multims.yml:", err)
		return false
	}

	// Verificar si el contexto está presente en el archivo
	kubernetesContext := viper.GetString("kubernetesContext")
	if kubernetesContext == "" {
		fmt.Println("kubernetesContext not found in multims.yml.")
		return false
	}

	// Establecer el contexto usando kubectl
	err = setKubernetesContext(kubernetesContext)
	if err != nil {
		fmt.Println("Error setting Kubernetes context:", err)
		return false
	}

	return true
}

// Establecer el contexto de Kubernetes utilizando kubectl
func setKubernetesContext(context string) error {
	cmd := exec.Command("kubectl", "config", "use-context", context)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error setting Kubernetes context: %v, output: %s", err, string(output))
	}
	fmt.Printf("Using Kubernetes context: %s\n", context)
	return nil
}

// loggingMenu muestra el menú principal para manejar el agente de logging
func loggingMenu() {
	reader := bufio.NewReader(os.Stdin)

	for {
		// Detectar si el agente está instalado en algún namespace antes de cada interacción
		installedAgents := logging.CheckIfAgentInstalled()

		fmt.Println("\nKubernetes Logging Management")
		fmt.Println("-----------------------------")

		if len(installedAgents) > 0 {
			fmt.Println("Logging agent is already installed in the following namespaces:")
			for _, ns := range installedAgents {
				fmt.Printf("- %s\n", ns)
			}
		} else {
			fmt.Println("No logging agents installed.")
		}

		// Mostrar opciones al usuario
		if len(installedAgents) > 0 {
			fmt.Println("\nWhat would you like to do?")
			fmt.Println("1. Uninstall logging agent")
			fmt.Println("2. Validate agent status")
			fmt.Println("3. Exit to main menu")
		} else {
			fmt.Println("\nNo logging agents installed.")
			fmt.Println("What would you like to do?")
			fmt.Println("1. Install logging agent")
			fmt.Println("2. Exit to main menu")
		}

		fmt.Print("\nChoose an option: ")
		option, _ := reader.ReadString('\n')
		option = strings.TrimSpace(option)

		switch option {
		case "1":
			if len(installedAgents) > 0 {
				// Listar los namespaces con logging agents instalados
				fmt.Println("Select the namespace to uninstall the logging agent:")
				namespace := selectNamespace(installedAgents)

				logging.UninstallLoggingAgent(namespace) // Desinstalar el agente de logging
			} else {
				// Listar todos los namespaces disponibles para la instalación
				fmt.Println("Select the namespace to install the logging agent:")
				namespaces := listNamespaces()
				namespace := selectNamespace(namespaces)

				logging.InstallLoggingAgent(namespace) // Instalar el agente
			}
		case "2":
			if len(installedAgents) > 0 {
				// Validar el estado del agente para los namespaces donde esté instalado
				logging.ValidateAgentStatus(installedAgents)
			} else {
				fmt.Println("Returning to main menu...")
				return
			}
		case "3":
			fmt.Println("Returning to main menu...")
			return
		default:
			fmt.Println("Invalid option. Please try again.")
		}
	}
}

// Función para listar todos los namespaces disponibles
func listNamespaces() []string {
	cmd := exec.Command("kubectl", "get", "namespaces", "-o", "custom-columns=:metadata.name")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Error listing namespaces: %v\nOutput: %s", err, string(output))
	}

	namespaces := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(namespaces) == 0 {
		fmt.Println("No namespaces found.")
		os.Exit(1)
	}
	return namespaces
}

// Función para seleccionar un namespace desde una lista
func selectNamespace(namespaces []string) string {
	for i, ns := range namespaces {
		fmt.Printf("%d. %s\n", i+1, ns)
	}

	fmt.Print("Choose a namespace by number: ")
	var selection int
	fmt.Scanln(&selection)

	if selection < 1 || selection > len(namespaces) {
		fmt.Println("Invalid selection.")
		os.Exit(1)
	}

	return namespaces[selection-1]
}

// Convertir la selección del usuario a índice
func toIndex(option string) int {
	index, err := strconv.Atoi(option)
	if err != nil {
		return -1
	}
	return index
}

func ViewPodLogs() {
	// Pedir al usuario que seleccione el namespace
	namespaces := listNamespaces()
	fmt.Println("Select the namespace where the pod is running:")
	namespace := selectNamespace(namespaces)

	// Listar los pods en el namespace usando kubectl
	cmd := exec.Command("kubectl", "get", "pods", "-n", namespace, "-o", "custom-columns=:metadata.name")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Error listing pods in namespace %s: %v\nOutput: %s", namespace, err, string(output))
	}

	// Dividir el resultado en líneas para mostrar los pods
	pods := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(pods) == 0 {
		fmt.Printf("No pods found in namespace: %s\n", namespace)
		return
	}

	fmt.Println("Pods available:")
	for i, pod := range pods {
		fmt.Printf("%d. %s\n", i+1, pod)
	}

	// Preguntar qué pod seleccionar
	fmt.Println("Enter the number of the pod to view logs:")
	var podChoice int
	fmt.Scanln(&podChoice)

	if podChoice < 1 || podChoice > len(pods) {
		fmt.Println("Invalid pod choice.")
		return
	}

	selectedPod := pods[podChoice-1]

	// Ejecutar kubectl logs para ver los logs del pod seleccionado
	cmd = exec.Command("kubectl", "logs", selectedPod, "-n", namespace)
	output, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error getting logs for pod %s: %v\n", selectedPod, err)
		return
	}

	fmt.Printf("Logs for pod %s:\n%s\n", selectedPod, string(output))
}
