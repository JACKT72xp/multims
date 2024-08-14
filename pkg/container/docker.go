package container

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

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
}

func runMultims() {
	// Cargar la configuración
	config := loadConfig()

	// Construir y subir la imagen
	buildAndPushImage(config)

	// Actualizar el deployment
	updateKubernetesDeployment(config)
}

func loadConfig() Config {
	var config Config
	yamlFile, err := ioutil.ReadFile("multims.yml")
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		panic(err)
	}
	return config
}

func buildAndPushImage(config Config) {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	imageName := fmt.Sprintf("%s/%s:local%s", config.RegistryURL, filepath.Base(dir), config.UID)
	dockerBuildCmd := exec.Command("docker", "build", "-t", imageName, ".")
	dockerBuildCmd.Stdout = os.Stdout
	dockerBuildCmd.Stderr = os.Stderr
	err = dockerBuildCmd.Run()
	if err != nil {
		panic(err)
	}

	dockerPushCmd := exec.Command("docker", "push", imageName)
	dockerPushCmd.Stdout = os.Stdout
	dockerPushCmd.Stderr = os.Stderr
	err = dockerPushCmd.Run()
	if err != nil {
		panic(err)
	}
}

func updateKubernetesDeployment(config Config) {
	// Aquí deberías usar el cliente de Kubernetes para actualizar el deployment
	// utilizando la nueva imagen
}
