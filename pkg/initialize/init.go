package initialize

import (
	"fmt"
	"log"
	"multims/pkg/auth"
	"multims/pkg/build"
	"multims/pkg/client"
	"multims/pkg/config"
	"multims/pkg/utils"
	"os"
	"path/filepath"
)

func RunInit() {
	fmt.Println(welcomeMessage)
	for {
		// Selección de kubeconfig y contexto
		useDefaultKubeConfig, kubeConfigPath := config.ChooseKubeConfig()
		ctx, err := config.ChooseContext(kubeConfigPath)
		if err != nil {
			log.Fatalf("Error choosing context: %v", err)
		}

		// Selección de namespace
		namespace, err := utils.SelectNamespace(kubeConfigPath, ctx)
		if err != nil {
			log.Fatalf("Error selecting namespace: %v", err)
		}
		fmt.Printf("Selected namespace: '%s'\n", namespace)

		var technology, registry string
		// Selección de tecnología y registro
		for {
			technology = SelectTechnology()
			if technology == "Cancel" {
				fmt.Println(operationCancelled)
				return
			}

			fmt.Printf("You have selected: %s\n", technology)
			registry = SelectRegistry()
			if registry == "Cancel" {
				fmt.Println(operationCancelled)
				return
			}

			if ConfirmSelection(technology, registry) {
				if registry == "DockerHub" {
					auth.HandleDockerLogin()
				} else if registry == "AWS ECR" {
					auth.HandleECRLogin()
				}
				break
			} else {
				fmt.Println("Revisiting the selection process.")
			}
		}

		// Entrada del usuario para comando y puerto
		command, port, err := HandleUserInput()
		if err != nil {
			fmt.Printf(errorReadingInput, err)
			continue // Volver a pedir entrada
		}

		// Obtener el nombre del directorio actual
		currentDir, err := os.Getwd()
		if err != nil {
			log.Fatalf(errorGettingDir, err)
		}
		dirName := filepath.Base(currentDir)
		fmt.Printf("Your app name: %s\n", dirName)

		// Crear el directorio de Multims
		build.CreateMultimsDirectory()

		// Obtener la configuración de AWS
		accountID, region, err := GetAWSConfig()
		if err != nil {
			log.Fatalf(errorAWSAccountInfo, err)
		}

		// Formatear y mostrar el puerto
		formattedPort := fmt.Sprintf("%08d", port)
		fmt.Println(formattedPort)

		// Guardar configuración en archivo
		build.SaveConfigToFile(technology, fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", accountID, region), ctx, namespace, useDefaultKubeConfig, kubeConfigPath, dirName, registry, command, port, utils.GenerateUUID())

		fmt.Println("Files generated")

		// Configurar la conexión a Kubernetes
		client.SetupKubernetesConnection(kubeConfigPath, ctx)

		break // Salir del bucle principal después de completar el proceso
	}
}
