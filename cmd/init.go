package cmd

import (
	"fmt"
	"log"
	"multims/pkg/auth"
	"multims/pkg/build"
	"multims/pkg/client"
	"multims/pkg/config"
	"multims/pkg/utils"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
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

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "k8s-cli is a CLI tool for managing Kubernetes",
	Long:  `Welcome to MULTIMS by JT. A CLI tool to interact with Kubernetes.`,
	Run: func(cmd *cobra.Command, args []string) {
		title("Welcome to MULTIMS by JT")
		fmt.Println(aurora.Bold(aurora.Cyan("Manage your Kubernetes clusters effectively.")))

		fmt.Print(aurora.BrightYellow("Validating..."))
		time.Sleep(2 * time.Second) // Simulate loading time

		// Check if multims.yml exists
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

		// Check if current directory is a Git repository
		isGitRepo := checkIfGitRepo()
		fmt.Print("\r                \r") // Clear the "Validating..." message

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

		// Choose kubeconfig
		title("Kubernetes Configuration")
		var kubeconfigOptions = []string{"Use default kubeconfig (~/.kube/config)", "Specify kubeconfig file path"}
		var kubeconfigChoice string
		promptKubeconfig := &survey.Select{
			Message: "How do you want to connect to Kubernetes?",
			Options: kubeconfigOptions,
		}
		survey.AskOne(promptKubeconfig, &kubeconfigChoice)

		var useDefaultKubeConfig bool
		var kubeConfigPath string
		if kubeconfigChoice == kubeconfigOptions[0] {
			useDefaultKubeConfig = true
			kubeConfigPath = os.ExpandEnv("$HOME/.kube/config")
		} else {
			useDefaultKubeConfig = false
			promptKubeconfigPath := &survey.Input{
				Message: "Please specify the kubeconfig file path:",
			}
			survey.AskOne(promptKubeconfigPath, &kubeConfigPath)
		}

		// Choose context
		ctx, err := config.ChooseContext(kubeConfigPath)
		if err != nil {
			log.Fatalf("Error choosing context: %v", err)
		}

		// Select namespace (kept as user-defined)
		namespace, err := utils.SelectNamespace(kubeConfigPath, ctx)
		if err != nil {
			log.Fatalf("Error selecting namespace: %v", err)
		}

		fmt.Printf("Selected namespace: '%s'\n", aurora.Bold(namespace))

		// Select technology
		title("Technology Selection")
		technology := utils.SelectTechnology()
		if technology == "Cancel" {
			fmt.Println("Operation cancelled by the user.")
			return
		}

		fmt.Printf("You have selected: %s\n", aurora.Bold(technology))

		// Select registry
		title("Registry Selection")
		var registryOptions = []string{"DockerHub", "AWS ECR", "CustomImageMultiMS"}
		var registryChoice string
		promptRegistry := &survey.Select{
			Message: "Where do you want to store your images?",
			Options: registryOptions,
		}
		survey.AskOne(promptRegistry, &registryChoice)

		// Variable to hold the custom image name if selected
		var customImage string
		if registryChoice == "CustomImageMultiMS" {
			switch technology {
			case "Node":
				customImage = "jackt72xp/multims:nodejsv25"
			case "Python":
				customImage = "jackt72xp/multims:pythonv2"
			}
		} else if registryChoice == "DockerHub" {
			auth.HandleDockerLogin()
		} else if registryChoice == "AWS ECR" {
			auth.HandleECRLogin()
		}

		// Enter start command
		title("Application Configuration")
		var startCommand string
		promptStartCommand := &survey.Input{
			Message: "Please enter the command to start your application (default: node index.js):",
			Default: "node index.js",
		}
		survey.AskOne(promptStartCommand, &startCommand)

		// Enter port number
		var portNumber string
		promptPortNumber := &survey.Input{
			Message: "Please enter the port number to start your application (default: 3000):",
			Default: "3000",
		}
		survey.AskOne(promptPortNumber, &portNumber)

		// Force appName to be "multims"
		appName := "multims"
		fmt.Printf("Your app name: %s\n", aurora.Bold(appName))

		// Create MULTIMS directory
		build.CreateMultimsDirectory()

		// Generate a UUID for the configuration
		uid := utils.GenerateUUID()

		intValue, err := strconv.Atoi(portNumber)
		if err != nil {
			log.Fatalf("Invalid port number: %v", err)
		}

		// Remove registryURL
		if registryChoice == "CustomImageMultiMS" {
			build.SaveCustomImageConfigToFile(technology, customImage, ctx, namespace, useDefaultKubeConfig, kubeConfigPath, appName, startCommand, intValue, uid)
		} else {
			accountID, region, err := config.GetAWSAccountInfo()
			if err != nil {
				log.Fatalf("Failed to retrieve AWS account info: %v", err)
			}
			ecrEndpoint := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", accountID, region)
			build.SaveConfigToFile(technology, ecrEndpoint, ctx, namespace, useDefaultKubeConfig, kubeConfigPath, appName, registryChoice, startCommand, intValue, uid)
		}

		fmt.Println(aurora.Bold(aurora.Green("multims.yml configuration file generated successfully.")))

		// Setup Kubernetes connection
		client.SetupKubernetesConnection(kubeConfigPath, ctx)
	},
}
