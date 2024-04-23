package container

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

type Config struct {
	KubernetesContext string `yaml:"kubernetesContext"`
	RegistryURL       string `yaml:"registry"`
	Technology        string `yaml:"technology"`
	UID               string `yaml:"uid"`
	Namespace         string `yaml:"namespace"`
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
