package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "multims",
	Short: "Multims is a CLI tool for managing Kubernetes",
	Long:  `Multims by JT. A CLI tool to interact with Kubernetes and manage deployments.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}

// Aquí deberías incluir la inicialización de subcomandos
func init() {
	// Aquí añadirías tus subcomandos, por ejemplo:
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(runCmd)
	// Etc...
}

// package cmd

// import (
// 	"encoding/json"
// 	"fmt"
// 	"io/ioutil"
// 	"log"
// 	"multims/pkg/auth"
// 	"multims/pkg/build"
// 	"multims/pkg/client"
// 	"multims/pkg/config"
// 	"path/filepath"

// 	"github.com/manifoldco/promptui"
// 	"github.com/spf13/cobra"
// )

// type packageJSON struct {
// 	Main string `json:"main"`
// }

// var rootCmd = &cobra.Command{
// 	Use:   "k8s-cli",
// 	Short: "k8s-cli is a CLI tool for managing Kubernetes",
// 	Long:  `Welcome to MULTIMS by JT. A CLI tool to interact with Kubernetes.`,
// 	Run: func(cmd *cobra.Command, args []string) {
// 		fmt.Println("Welcome to MULTIMS by JT. Manage your Kubernetes clusters effectively.")
// 		kubeconfig := config.LoadConfig()
// 		ctx := config.ChooseContext(kubeconfig)  // Cambiado a 'ctx' para evitar confusión con el paquete 'context'
// 		namespace := selectNamespace(kubeconfig) // Select namespace after choosing context

// 		technology := selectTechnology()
// 		if technology == "Cancel" {
// 			fmt.Println("Operation cancelled by the user.")
// 			return
// 		}

// 		fmt.Printf("You have selected: %s\n", technology)
// 		registry := selectRegistry()
// 		if registry == "DockerHub" {
// 			auth.HandleDockerLogin()
// 		} else if registry == "AWS ECR" {
// 			auth.HandleECRLogin()
// 		}

// 		build.CreateMultimsDirectory()
// 		build.SaveConfigToFile(technology, registry, ctx, namespace) // Update this function to handle namespace
// 		fmt.Println("Files generated")

// 		client.SetupKubernetesConnection(kubeconfig, ctx)
// 	},
// }

// func isNodeApp() bool {
// 	packagePath := filepath.Join(".", "package.json")
// 	file, err := ioutil.ReadFile(packagePath)
// 	if err != nil {
// 		fmt.Println("No package.json file found:", err)
// 		return false
// 	}

// 	var pkg packageJSON
// 	err = json.Unmarshal(file, &pkg)
// 	if err != nil {
// 		fmt.Println("Error parsing package.json:", err)
// 		return false
// 	}

// 	return pkg.Main == "index.js"
// }

// func selectTechnology() string {
// 	prompt := promptui.Select{
// 		Label: "Select the technology stack for your project",
// 		Items: []string{"Node.js", "Node.js-Typescript", "Cancel"},
// 	}

// 	_, result, err := prompt.Run()
// 	if err != nil {
// 		log.Fatalf("Prompt failed %v\n", err)
// 	}
// 	return result
// }

// func selectRegistry() string {
// 	prompt := promptui.Select{
// 		Label: "Select the container registry to use",
// 		Items: []string{"DockerHub", "AWS ECR", "Cancel"},
// 	}
// 	_, result, err := prompt.Run()
// 	if err != nil {
// 		log.Fatalf("Prompt failed %v\n", err)
// 	}
// 	return result
// }

// func selectNamespace(kubeconfig string) string {
// 	namespaces, err := client.ListNamespaces(kubeconfig)
// 	if err != nil {
// 		log.Fatalf("Failed to list namespaces: %v", err)
// 	}

// 	prompt := promptui.Select{
// 		Label: "Select Kubernetes namespace",
// 		Items: namespaces,
// 	}
// 	_, result, err := prompt.Run()
// 	if err != nil {
// 		log.Fatalf("Prompt failed %v\n", err)
// 	}
// 	return result
// }

// func Execute() {
// 	if err := rootCmd.Execute(); err != nil {
// 		fmt.Println(err)
// 	}
// }
