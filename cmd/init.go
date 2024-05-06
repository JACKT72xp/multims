package cmd

import (
	"bufio"
	"fmt"
	"log"
	"multims/operations"
	"multims/pkg/client"
	"multims/pkg/config"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "k8s-cli is a CLI tool for managing Kubernetes",
	Long:  `Welcome to MULTIMS by JT. A CLI tool to interact with Kubernetes.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Welcome to MULTIMS by JT. Manage your Kubernetes clusters effectively.")

		// Load kubeconfig
		useDefaultKubeConfig, kubeConfigPath := config.ChooseKubeConfig()
		ctx, err := config.ChooseContext(kubeConfigPath)
		if err != nil {
			log.Fatalf("Error choosing context: %v", err)
		}

		// Select namespace
		namespace := operations.SelectNamespace(kubeConfigPath, ctx)
		fmt.Printf("Selected namespace: '%s'\n", namespace)

		// Select technology
		technology := operations.SelectTechnology()
		if technology == "Cancel" {
			fmt.Println("Operation cancelled by the user.")
			return
		}
		fmt.Printf("You have selected: %s\n", technology)

		// Handle registry login
		registry := operations.SelectRegistry()
		operations.HandleRegistryLogin(registry)

		// Get command and port
		command := operations.GetCommand("node index.js")
		port, err := operations.GetPort("3000")
		if err != nil {
			fmt.Println("Error:", err)
			// handle the error, possibly using the default port or returning
			// from the function
			return
		}
		// Continue with port value
		fmt.Println("Port:", port)

		dirName, err := os.Getwd()
		if err != nil {
			log.Fatalf("Error getting current directory: %v", err)
		}

		dirName2 := filepath.Base(dirName)
		// Get current directory name
		fmt.Printf("You appName: %s\n", dirName2)

		// Create MULTIMS directory
		operations.CreateMultimsDirectory()

		// Handle AWS ECR endpoint
		ecrEndpoint := operations.HandleAWSECREndpoint(registry)

		// Database configuration
		dbConfig := operations.ConfigureDatabase()

		installationCommands := operations.AskForInstallationCommands()

		configFilePath := filepath.Join(dirName, "multims.yml")

		// Check if multims.yml already exists
		if _, err := os.Stat(configFilePath); err == nil {
			// File exists, ask user if they want to overwrite
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

		// Save configuration to file
		operations.SaveConfigurationToFile(technology, ecrEndpoint, ctx, namespace, useDefaultKubeConfig, kubeConfigPath, dirName2, registry, command, port, dbConfig, installationCommands, dirName)
		fmt.Println("Files generated")

		// Setup Kubernetes connection
		client.SetupKubernetesConnection(kubeConfigPath, ctx)
	},
}
