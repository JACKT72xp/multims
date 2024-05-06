// pkg/build/build.go
package build

import (
	"embed"
	"fmt"
	"multims/pkg/config"
	"os"
	"path/filepath"
	"text/template"

	"gopkg.in/yaml.v2"

	"github.com/google/uuid"
)

//go:embed templates/nodejs/*
var templatesFS embed.FS

// Define una nueva estructura para representar un servicio
type ServiceConfig struct {
	Name  string // Nombre del servicio
	Image string // Imagen del contenedor del servicio
	Port  int    // Puerto del servicio
}

// Define la estructura Config con la propiedad MultiServices
// type Config struct {
// 	KubernetesContext string          // Otros campos existentes
// }

type AppInfo struct {
	StartRun string `yaml:"start_run"`
	Port     int    `yaml:"port"`
	// Este campo es ahora parte de una subestructura
}
type Config struct {
	KubernetesContext    string          `yaml:"kubernetesContext"`
	RegistryOrDocker     string          `yaml:"registryOrDocker"`
	RegistryURL          string          `yaml:"registry"`
	Technology           string          `yaml:"technology"`
	Namespace            string          `yaml:"namespace"`
	UseDefaultKubeConfig bool            `yaml:"useDefaultKubeConfig"`
	KubeConfigPath       string          `yaml:"kubeConfigPath"`
	UID                  string          `yaml:"uid"`
	AppName              string          `yaml:"appName"`
	Application          AppInfo         `yaml:"application"` // Cambiado para reflejar la jerarquía
	MultiServices        []ServiceConfig // Slice de servicios
	Database             config.DatabaseConfig
	InstallationCommands []string
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
func SaveConfigToFile(technology, registry, context, namespace string, useDefault bool, kubeConfigPath, appName string, ecr_docker string, input string, port int, dbConfig config.DatabaseConfig, installationCommands []string, dir string) error {
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
			StartRun: input,
			Port:     port,
		},
		MultiServices:        []ServiceConfig{},
		Database:             dbConfig,
		InstallationCommands: installationCommands,
	}
	configData, err := yaml.Marshal(config)
	if err != nil {
		fmt.Printf("Error marshaling config data: %v\n", err)
		return fmt.Errorf("failed to marshal config data: %v", err)
	}

	// Obtener el directorio donde se está ejecutando el comando
	executableDir := dir
	fmt.Print("Executable directory: ", executableDir)

	// Guardar el archivo en el directorio del comando
	configFile := filepath.Join(executableDir, "multims.yml")
	if err := os.WriteFile(configFile, configData, 0644); err != nil {
		fmt.Printf("Error writing config file: %v\n", err)
		return fmt.Errorf("failed to write config file: %v", err)
	}

	if err := processTemplates(executableDir, config); err != nil {
		fmt.Printf("Error processing templates: %v\n", err)
		return fmt.Errorf("failed to process templates: %v", err)
	}

	return nil
}
func readTemplateFile(filePath string) error {
	// Intentar leer el archivo en la ruta especificada
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file at %s: %v", filePath, err)
	}

	// Procesar los datos del archivo como necesites
	fmt.Println("Data read from file:", string(data))
	return nil
}

func processTemplates(dir string, config Config) error {
	// Definir las rutas de las plantillas en un mapa
	templatesPaths := map[string]map[string]string{
		"Node": {
			"Dockerfile": "/opt/homebrew/etc/multims/templates/nodejs/Dockerfile.template",
			"Deployment": "/opt/homebrew/etc/multims/templates/nodejs/Deployment.yaml.template",
		},
		"Python": {
			"Dockerfile": "/opt/homebrew/etc/multims/templates/python/Dockerfile.template",
			"Deployment": "/opt/homebrew/etc/multims/templates/python/Deployment.yaml.template", // Aquí parece haber un error, debería ser `python/Deployment.yaml.template`
		},
	}

	// Verificar si la tecnología está soportada
	paths, ok := templatesPaths[config.Technology]
	if !ok {
		return fmt.Errorf("technology %s not supported", config.Technology)
	}

	// Procesar cada template definido para la tecnología
	for key, path := range paths {
		templateContent, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s template: %v", key, err)
		}
		outputFile := filepath.Join(dir, ".multims", key+".yaml")
		if err := processTemplate(string(templateContent), outputFile, config); err != nil {
			return err
		}
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
