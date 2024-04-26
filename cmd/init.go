package cmd

import (
	"bufio"
	"fmt"
	"log"
	"multims/pkg/auth"
	"multims/pkg/build"
	"multims/pkg/client"
	"multims/pkg/config"
	"multims/pkg/utils"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "k8s-cli is a CLI tool for managing Kubernetes",
	Long:  `Welcome to MULTIMS by JT. A CLI tool to interact with Kubernetes.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Welcome to MULTIMS by JT. Manage your Kubernetes clusters effectively.")
		//kubeconfig := config.LoadConfig()
		useDefaultKubeConfig, kubeConfigPath := config.ChooseKubeConfig()

		ctx, err := config.ChooseContext(kubeConfigPath)
		if err != nil {
			log.Fatalf("Error choosing context: %v", err)
		}

		namespace, err := utils.SelectNamespace(kubeConfigPath, ctx)
		if err != nil {
			log.Fatalf("Error selecting namespace: %v", err)
		}

		fmt.Printf("Selected namespace: '%s'\n", namespace)

		technology := utils.SelectTechnology()
		if technology == "Cancel" {
			fmt.Println("Operation cancelled by the user.")
			return
		}

		fmt.Printf("You have selected: %s\n", technology)
		registry := utils.SlectRegistry()
		if registry == "DockerHub" {
			auth.HandleDockerLogin()
		} else if registry == "AWS ECR" {
			auth.HandleECRLogin()
		}

		reader := bufio.NewReader(os.Stdin)
		defaultCommand := "node index.js"
		fmt.Printf("Please enter the command to start your application (default: %s): ", defaultCommand)

		// Read the input from user
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading input:", err)
			return
		}

		// Trim space and check if the input is empty
		input = strings.TrimSpace(input)
		if input == "" {
			input = defaultCommand
		}

		reader2 := bufio.NewReader(os.Stdin)
		defaultCommandPort := "3000"
		fmt.Printf("Please enter the number of port to start your application (default: %s): ", defaultCommandPort)
		// Read the input from user
		input2, err2 := reader2.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading input:", err2, input2)
			return
		}

		// Obtener el nombre del directorio actual
		currentDir, err := os.Getwd()
		if err != nil {
			log.Fatalf("Error getting current directory: %v", err)
		}
		dirName := filepath.Base(currentDir) // Esto da el nombre del directorio actual
		fmt.Printf("You appName : %s\n", dirName)
		fmt.Printf("You llega aqui-1 : %s\n", "______________________________")

		build.CreateMultimsDirectory()
		fmt.Printf("You llega aqui0 : %s\n", "______________________________")

		ecrEndpoint := ""
		if registry == "DockerHub" {
			fmt.Printf("You appName ")
		} else if registry == "AWS ECR" {
			accountID, region, err := config.GetAWSAccountInfo()
			if err != nil {
				fmt.Printf("You llega aqui : %s\n", err)
				return
			}
			ecrEndpoint = fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", accountID, region)
			fmt.Printf("You llega aqui2 : %s\n", "______________________________")
		}

		// Obtener el ID de la cuenta de AWS y la región
		fmt.Printf("You llega aqui0.05 : %s\n", "______________________________")

		fmt.Printf("You llega aqui0.1 : %s\n", "______________________________")

		intValue, err := strconv.Atoi(strings.TrimSuffix(input2, "\n"))

		if err != nil {
			fmt.Printf("You llega aqui : %s\n", err)
			return
		}
		fmt.Printf("You llega aqui : %s\n", "______________________________")

		formattedStr := fmt.Sprintf("%08d", intValue)
		fmt.Println(formattedStr)

		fmt.Printf("You llega aqui3 : %s\n", "______________________________")

		build.SaveConfigToFile(technology, ecrEndpoint, ctx, namespace, useDefaultKubeConfig, kubeConfigPath, dirName, registry, input, intValue)

		fmt.Println("Files generated")

		client.SetupKubernetesConnection(kubeConfigPath, ctx)
	},
}
