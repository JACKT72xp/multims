package cmd

import (
	"bufio"
	"fmt"
	"multims/security"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Kubernetes Security Tool",
	Long:  `A tool to analyze your Kubernetes cluster security with different levels of analysis.`,
	Example: `
  # Run a basic security analysis
  multims security --basic

  # Run an advanced security analysis on a specific namespace
  multims security --advanced --namespace default

  # Use third-party tools for security analysis
  multims security --third-party`,
	Run: func(cmd *cobra.Command, args []string) {
		mainMenu()
	},
}

func init() {
	rootCmd.AddCommand(securityCmd)
}

// Main menu
func mainMenu() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("\nKubernetes Security Tool")
	fmt.Println("-------------------------")
	fmt.Println("1. Basic analysis")
	fmt.Println("2. Advanced analysis")
	fmt.Println("3. Third-party security tools")
	fmt.Println("4. Exit")

	fmt.Print("\nChoose an option: ")
	option, _ := reader.ReadString('\n')
	option = strings.TrimSpace(option)

	switch option {
	case "1":
		security.BasicAnalysisMenu(mainMenu) // Pasamos mainMenu como función de retorno
	case "2":
		security.AdvancedAnalysisMenu(mainMenu) // Pasamos mainMenu como función de retorno
	case "3":
		security.ThirdPartyMenu(mainMenu) // Pasamos mainMenu como función de retorno
	case "4":
		fmt.Println("Exiting application. Goodbye!")
		os.Exit(0)
	default:
		fmt.Println("Invalid option. Please try again.")
		mainMenu()
	}
}

// Comando para el análisis básico
var basicCmd = &cobra.Command{
	Use:   "basic",
	Short: "Run a basic Kubernetes security analysis",
	Long:  `This will perform a basic security scan of your Kubernetes cluster or a specific namespace.`,
	Example: `
  # Run a basic analysis for the entire cluster
  multims security basic --entire-cluster

  # Run a basic analysis for a specific namespace
  multims security basic --namespace default`,
	Run: func(cmd *cobra.Command, args []string) {
		security.BasicAnalysisMenu(mainMenu)
	},
}

// Comando para el análisis avanzado
var advancedCmd = &cobra.Command{
	Use:   "advanced",
	Short: "Run an advanced Kubernetes security analysis",
	Long:  `This will perform an advanced security scan that includes checking for OWASP best practices and scanning container images.`,
	Example: `
  # Run an advanced analysis for the entire cluster
  multims security advanced --entire-cluster

  # Run an advanced analysis for a specific namespace
  multims security advanced --namespace default`,
	Run: func(cmd *cobra.Command, args []string) {
		security.AdvancedAnalysisMenu(mainMenu)
	},
}

// Comando para las herramientas de terceros
var thirdPartyCmd = &cobra.Command{
	Use:   "third-party",
	Short: "Run third-party security tools",
	Long:  `This will allow you to run third-party tools like Trivy, Kube-bench, and Kube-hunter for additional security scanning.`,
	Example: `
  # Run Trivy scan for vulnerabilities
  multims security third-party --tool trivy`,
	Run: func(cmd *cobra.Command, args []string) {
		security.ThirdPartyMenu(mainMenu)
	},
}

func init() {
	// Añadir subcomandos para el comando security
	securityCmd.AddCommand(basicCmd)
	securityCmd.AddCommand(advancedCmd)
	securityCmd.AddCommand(thirdPartyCmd)

	// Definir flags específicos para cada tipo de análisis
	basicCmd.Flags().Bool("entire-cluster", false, "Run basic analysis on the entire cluster")
	basicCmd.Flags().String("namespace", "", "Run basic analysis on a specific namespace")

	advancedCmd.Flags().Bool("entire-cluster", false, "Run advanced analysis on the entire cluster")
	advancedCmd.Flags().String("namespace", "", "Run advanced analysis on a specific namespace")

	thirdPartyCmd.Flags().String("tool", "", "Specify the third-party tool to use (e.g., trivy, kube-hunter, kube-bench)")
}
