package config

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"

	"path/filepath"

	"gopkg.in/yaml.v2"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/manifoldco/promptui"
	"k8s.io/client-go/util/homedir"
)

type AppInfo struct {
	StartRun string `yaml:"start_run"`
	Port     int    `yaml:"port"`
}

// RegistryConfig represents the registry-specific configuration
type RegistryConfig struct {
	Provider string `yaml:"provider"`
	Image    string `yaml:"image"`
}

type ServiceConfig struct {
	Name  string `yaml:"name"`
	Image string `yaml:"image"`
	Port  int    `yaml:"port"`
}

type Config struct {
	RegistryOrDocker     string          `yaml:"registryOrDocker"`
	Registry             RegistryConfig  `yaml:"registry"`
	Technology           string          `yaml:"technology"`
	KubernetesContext    string          `yaml:"kubernetesContext"`
	Namespace            string          `yaml:"namespace"`
	UseDefaultKubeConfig bool            `yaml:"useDefaultKubeConfig"`
	KubeConfigPath       string          `yaml:"kubeConfigPath"`
	UID                  string          `yaml:"uid"`
	AppName              string          `yaml:"appName"`
	Application          AppInfo         `yaml:"application"`
	Multiservices        []ServiceConfig `yaml:"multiservices"`
	RegistryURL          string          `yaml:"registryURL"`
}

// LoadConfigFromFile loads the configuration from a YAML file
// LoadConfigFromFile loads the configuration from a YAML file
// LoadConfigFromFile carga la configuración desde un archivo YAML
func LoadConfigFromFile(filepath string) (*Config, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

// ChooseAndReturnContext prompts the user to choose a Kubernetes context from the kubeconfig and returns it
func ChooseAndReturnContext(kubeconfig string) string {
	config, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		log.Fatalf("Failed to load kubeconfig: %v", err)
		return ""
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
		log.Fatalf("Prompt failed %v", err)
		return ""
	}

	log.Printf("You have selected the context: %s\n", chosenContext)
	return chosenContext
}

// ChooseKubeConfig interactúa con el usuario para determinar qué configuración de kubeconfig usar y devuelve si es el default y la ruta
func ChooseKubeConfig() (bool, string) {
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

func GetAWSAccountInfo() (accountID, region string, err error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("Error loading AWS config: %v", err)
		return "", "", err
	}

	// Supongamos que tienes una función que puede obtener el ID de la cuenta
	// Esta es una implementación hipotética que necesitas ajustar según tu caso de uso
	stsClient := sts.NewFromConfig(cfg)
	input := &sts.GetCallerIdentityInput{}
	result, err := stsClient.GetCallerIdentity(context.Background(), input)
	if err != nil {
		log.Fatalf("Error getting AWS caller identity: %v", err)
		return "", "", err
	}

	return *result.Account, cfg.Region, nil
}
