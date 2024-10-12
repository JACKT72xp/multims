package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/manifoldco/promptui"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type packageJSON struct {
	Main string `json:"main"`
}

func captureKubeConfigDetails() (bool, string) {
	fmt.Println("Use default Kubernetes config (~/.kube/config)? [Y/n]")
	var response string
	fmt.Scanln(&response)
	if strings.ToLower(response) == "n" {
		fmt.Println("Enter the custom path to your kubeconfig:")
		var path string
		fmt.Scanln(&path)
		return false, path
	}
	return true, ""
}

func isNodeApp() bool {
	packagePath := filepath.Join(".", "package.json")
	file, err := ioutil.ReadFile(packagePath)
	if err != nil {
		fmt.Println("No package.json file found:", err)
		return false
	}

	var pkg packageJSON
	err = json.Unmarshal(file, &pkg)
	if err != nil {
		fmt.Println("Error parsing package.json:", err)
		return false
	}

	return pkg.Main == "index.js"
}

func SelectTechnology() string {
	prompt := promptui.Select{
		Label: "Select the technology stack for your project",
		Items: []string{"Node", "Node-Typescript", "Cancel", "Python"},
	}

	_, result, err := prompt.Run()
	if err != nil {
		log.Fatalf("Prompt failed %v\n", err)
	}
	return result
}

// SlectRegistry muestra un prompt para seleccionar el registro de contenedores
func SlectRegistry() string {
	prompt := promptui.Select{
		Label: "Select the container registry to use",
		Items: []string{"DockerHub", "AWS ECR", "Sin Registry", "Cancel"},
	}
	_, result, err := prompt.Run()
	if err != nil {
		log.Fatalf("Prompt failed %v\n", err)
	}
	return result
}

// SelectNamespace muestra un prompt para seleccionar un namespace de Kubernetes
// func SelectNamespace(kubeconfig string) string {
// 	namespaces, err := client.ListNamespaces(kubeconfig)
// 	if err != nil {
// 		log.Fatalf("Failed to list namespaces: %v", err)
// 	}

//		prompt := promptui.Select{
//			Label: "Select Kubernetes namespace",
//			Items: namespaces,
//		}
//		_, result, err := prompt.Run()
//		if err != nil {
//			log.Fatalf("Prompt failed %v", err)
//		}
//		return result
//	}
func SelectNamespace(kubeConfigPath, contextName string) (string, error) {
	// Carga el archivo de configuración especificado
	clientConfigLoadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfigLoadingRules.ExplicitPath = kubeConfigPath
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientConfigLoadingRules,
		&clientcmd.ConfigOverrides{CurrentContext: contextName})

	// Construye la configuración a partir del archivo kubeconfig con el contexto específico
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return "", fmt.Errorf("Cannot build kubeconfig: %v", err)
	}

	// Crea un cliente de Kubernetes con esta configuración
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", fmt.Errorf("Failed to create Kubernetes client: %v", err)
	}

	// Listar namespaces usando el cliente configurado
	namespaces, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("Failed to list namespaces: %v", err)
	}

	// Preparar lista de nombres de namespaces para la interfaz de usuario
	namespaceNames := make([]string, len(namespaces.Items))
	for i, ns := range namespaces.Items {
		namespaceNames[i] = ns.Name
	}

	// Usar promptui para seleccionar un namespace
	prompt := promptui.Select{
		Label: "Select Namespace",
		Items: namespaceNames,
	}

	_, chosenNamespace, err := prompt.Run()
	if err != nil {
		return "", fmt.Errorf("Namespace selection failed: %v", err)
	}

	return chosenNamespace, nil
}
