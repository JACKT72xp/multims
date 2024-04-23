package config

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/manifoldco/promptui"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func LoadConfig() string {
	kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
	prompt := promptui.Select{
		Label: "How do you want to connect to Kubernetes?",
		Items: []string{"Use default kubeconfig", "Specify kubeconfig file path"},
	}

	_, result, err := prompt.Run()
	if err != nil {
		log.Fatalf("Prompt failed %v\n", err)
		return ""
	}

	if result == "Specify kubeconfig file path" {
		prompt := promptui.Prompt{
			Label:   "Enter the path to your kubeconfig file",
			Default: kubeconfig,
		}
		kubeconfig, err = prompt.Run()
		if err != nil {
			log.Fatalf("Prompt failed %v\n", err)
			return ""
		}
	}

	return kubeconfig
}

func ChooseContext(kubeconfig string) (string, error) { // Cambio para retornar un error
	config, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		return "", fmt.Errorf("Failed to load kubeconfig: %v", err)
	}

	contexts := make([]string, 0, len(config.Contexts))
	for context := range config.Contexts {
		contexts = append(contexts, context)
	}

	prompt := promptui.Select{
		Label: "Choose a Kubernetes context",
		Items: contexts,
	}

	_, chosenContext, err := prompt.Run()
	if err != nil {
		return "", fmt.Errorf("Prompt failed: %v", err)
	}

	return chosenContext, nil
}

func chooseKubeConfig() (bool, string) {
	prompt := promptui.Select{
		Label: "How do you want to connect to Kubernetes?",
		Items: []string{"Use default kubeconfig", "Specify kubeconfig file path"},
	}
	_, result, err := prompt.Run()
	if err != nil {
		log.Fatalf("Prompt failed %v\n", err)
	}

	if result == "Specify kubeconfig file path" {
		prompt := promptui.Prompt{
			Label:   "Enter the path to your kubeconfig file",
			Default: filepath.Join(homedir.HomeDir(), ".kube", "config"),
		}
		path, err := prompt.Run()
		if err != nil {
			log.Fatalf("Prompt failed %v\n", err)
		}
		return false, path
	}
	return true, filepath.Join(homedir.HomeDir(), ".kube", "config")
}
