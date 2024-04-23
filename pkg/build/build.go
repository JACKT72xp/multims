// pkg/build/build.go
package build

import (
	"embed"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"text/template"

	"gopkg.in/yaml.v2"

	"github.com/google/uuid"
)

//go:embed templates/nodejs/*
var templatesFS embed.FS

type AppInfo struct {
	StartRun string `yaml:"start_run"` // Este campo es ahora parte de una subestructura
}
type Config struct {
	KubernetesContext    string  `yaml:"kubernetesContext"`
	RegistryOrDocker     string  `yaml:"registryOrDocker"`
	RegistryURL          string  `yaml:"registry"`
	Technology           string  `yaml:"technology"`
	Namespace            string  `yaml:"namespace"`
	UseDefaultKubeConfig bool    `yaml:"useDefaultKubeConfig"`
	KubeConfigPath       string  `yaml:"kubeConfigPath"`
	UID                  string  `yaml:"uid"`
	AppName              string  `yaml:"appName"`
	Application          AppInfo `yaml:"application"` // Cambiado para reflejar la jerarquía
	// Este campo debe comenzar con letra mayúscula
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

func SaveConfigToFile(technology, registry, context, namespace string, useDefault bool, kubeConfigPath, appName string, ecr_docker string, input string) error {
	uid := uuid.New().String()
	config := Config{
		KubernetesContext:    context,
		RegistryOrDocker:     ecr_docker,
		RegistryURL:          registry,
		Technology:           technology,
		Namespace:            namespace,
		UseDefaultKubeConfig: useDefault,
		KubeConfigPath:       kubeConfigPath,
		UID:                  uid,
		AppName:              appName,
		Application: AppInfo{
			StartRun: input, // Aquí va el comando de inicio
		}, // Asegúrate de que este campo esté correctamente capitalizado

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
