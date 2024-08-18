package build

import (
	"embed"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"text/template"

	"gopkg.in/yaml.v2"
)

//go:embed templates/nodejs/*
var templatesFS embed.FS

// Define una nueva estructura para representar un servicio
type ServiceConfig struct {
	Name  string // Nombre del servicio
	Image string // Imagen del contenedor del servicio
	Port  int    // Puerto del servicio
}

type AppInfo struct {
	StartRun string `yaml:"start_run"`
	Port     int    `yaml:"port"`
}

// RegistryConfig represents the registry-specific configuration
type RegistryConfig struct {
	Provider string
	Image    string
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

const multimsTemplate = `kubernetesContext: {{.KubernetesContext}}
registryOrDocker: CustomImageMultiMS
registry: 
  provider: {{.Registry.Provider}}
  image: {{.Registry.Image}}
technology: {{.Technology}}
namespace: {{.Namespace}}
useDefaultKubeConfig: {{.UseDefaultKubeConfig}}
kubeConfigPath: {{.KubeConfigPath}}
uid: {{.UID}}
appName: {{.AppName}}
application:
  start_run: {{.Application.StartRun}}
  port: {{.Application.Port}}
multiservices: []
registryURL: {{.RegistryURL}}
`

// SaveCustomImageConfigToFile saves the configuration to a multims.yml file
func SaveCustomImageConfigToFile(technology, image, kubernetesContext, namespace string, useDefaultKubeConfig bool, kubeConfigPath, appName, startRun string, port int, uid string) {
	config := Config{
		Technology:           technology,
		KubernetesContext:    kubernetesContext,
		Namespace:            namespace,
		UseDefaultKubeConfig: useDefaultKubeConfig,
		KubeConfigPath:       kubeConfigPath,
		AppName:              appName,
		UID:                  uid, // Incluye el UID aquí
		Application: AppInfo{
			StartRun: startRun,
			Port:     port,
		},
		Registry: RegistryConfig{
			Provider: "CustomImageMultiMS",
			Image:    image,
		},
	}

	tmpl, err := template.New("multims").Parse(multimsTemplate)
	if err != nil {
		log.Fatalf("Failed to parse template: %v", err)
	}

	file, err := os.Create("multims.yml")
	if err != nil {
		log.Fatalf("Failed to create multims.yml: %v", err)
	}
	defer file.Close()

	err = tmpl.Execute(file, config)
	if err != nil {
		log.Fatalf("Failed to execute template: %v", err)
	}

	fmt.Println("multims.yml configuration file generated successfully.")
}

func getCurrentDirectory() string {
	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current directory:", err)
		return ""
	}
	return dir
}

// CreateMultimsDirectory crea el directorio .multims en el directorio actual
func CreateMultimsDirectory() error {
	multimsPath := filepath.Join(".", ".multims")
	if err := os.MkdirAll(multimsPath, 0755); err != nil {
		return fmt.Errorf("failed to create .multims directory: %v", err)
	}
	return nil
}

func SaveConfigToFile(technology, registry, context, namespace string, useDefault bool, kubeConfigPath, appName, ecr_docker, input string, port int, uid string) error {
	// Ya no necesitamos generar el uid aquí
	config := Config{
		KubernetesContext:    context,
		Technology:           technology,
		Namespace:            namespace,
		UseDefaultKubeConfig: useDefault,
		KubeConfigPath:       kubeConfigPath,
		UID:                  uid, // Incluye el UID aquí
		AppName:              appName,
		Application: AppInfo{
			StartRun: input,
			Port:     port,
		},
		Multiservices: []ServiceConfig{},
		RegistryURL:   registry,
	}

	configData, err := yaml.Marshal(config)
	if err != nil {
		fmt.Printf("Error marshaling config data: %v\n", err)
		return fmt.Errorf("failed to marshal config data: %v", err)
	}

	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error getting current directory: %v\n", err)
		return fmt.Errorf("failed to get current directory: %v", err)
	}

	configFile := filepath.Join(currentDir, "multims.yml")
	if err := ioutil.WriteFile(configFile, configData, 0644); err != nil {
		fmt.Printf("Error writing config file: %v\n", err)
		return fmt.Errorf("failed to write config file: %v", err)
	}

	if err := processTemplates(currentDir, config); err != nil {
		fmt.Printf("Error processing templates: %v\n", err)
		return fmt.Errorf("failed to process templates: %v", err)
	}

	return nil
}
func processTemplates(dir string, config Config) error {
	// Utiliza el sistema de archivos embebido para cargar las plantillas
	dockerfileTemplate, err := templatesFS.ReadFile("templates/nodejs/Dockerfile.template")
	if err != nil {
		return fmt.Errorf("failed to read Dockerfile template: %v", err)
	}
	deploymentTemplate, err := templatesFS.ReadFile("templates/nodejs/Deployment.yaml.template")
	if err != nil {
		return fmt.Errorf("failed to read Deployment template: %v", err)
	}

	// Procesar cada template
	if err := processTemplate(string(dockerfileTemplate), filepath.Join(dir, ".multims", "Dockerfile"), config); err != nil {
		return err
	}
	if err := processTemplate(string(deploymentTemplate), filepath.Join(dir, ".multims", "Deployment.yaml"), config); err != nil {
		return err
	}

	return nil
}

func processTemplate(templateContent, outputPath string, config Config) error {
	tmpl, err := template.New("template").Parse(templateContent)
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	if err := tmpl.Execute(outputFile, config); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	return nil
}
