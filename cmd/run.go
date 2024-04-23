package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"multims/pkg/client"
	"multims/pkg/config"
	"multims/pkg/container"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the multims environment",
	Long:  `Initialize the multims environment by setting up necessary configurations and directories.`,
	Run: func(cmd *cobra.Command, args []string) {
		baseDir, err := os.Getwd()

		configPath := filepath.Join(".", "multims.yml")
		conf, err := config.LoadConfigFromFile(configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}

		// Login to ECR
		loginCmdStr := fmt.Sprintf("aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin %s", conf.RegistryURL)
		loginCmd := exec.Command("bash", "-c", loginCmdStr)
		loginOutput, err := loginCmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Failed to login to Docker: %s, %v", string(loginOutput), err)
		}
		fmt.Println("Logged into Docker with ECR successfully.")

		// Asegurar que el repositorio exista
		repoName := fmt.Sprintf("%s", conf.AppName)

		exist := container.CheckRepository(repoName)

		fmt.Println("Logged into Docker with ECR successfully.", exist)

		if !exist {
			err := container.CreateRepository(repoName)
			if err != nil {
				log.Fatalf("Failed to create repository: %v", err)
			}
			fmt.Println("Repository created successfully:", repoName)
		} else {
			fmt.Println("Repository already exists:", repoName)
		}

		// Construcción de la imagen Docker
		appImage := fmt.Sprintf("%s/%s:latest", conf.RegistryURL, conf.AppName)
		// dockerfilePath := filepath.Join(".", ".multims", "Dockerfile")
		dockerfilePath := filepath.Join(baseDir, ".multims", "Dockerfile")

		buildCmd := exec.Command("docker", "build", "--platform=linux/amd64", "-t", appImage, "-f", dockerfilePath, ".")
		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Failed to build Docker image: %s, %v", string(buildOutput), err)
		}
		fmt.Println("Docker image built successfully:", appImage)

		// Etiquetado de la imagen Docker
		taggedImage := fmt.Sprintf("%s/%s:%s", conf.RegistryURL, conf.AppName, conf.UID)
		tagCmd := exec.Command("docker", "tag", appImage, taggedImage)
		tagOutput, err := tagCmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Failed to tag Docker image: %s, %v", string(tagOutput), err)
		}
		fmt.Println("Docker image tagged successfully:", taggedImage)

		// Empuje de la imagen Docker
		pushCmd := exec.Command("docker", "push", taggedImage)
		pushOutput, err := pushCmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Failed to push Docker image: %s, %v", string(pushOutput), err)
		}
		fmt.Println("Docker image pushed successfully to ECR:", taggedImage)
		// Configuración de Kubernetes

		kubeConfigPath := conf.KubeConfigPath
		contextName := conf.KubernetesContext
		namespace := conf.Namespace
		input := conf.Application.StartRun
		directory := conf.AppName

		// Ejemplo de nombre de contexto

		// Construir la configuración de clientecmd usando el contexto específico
		configLoadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeConfigPath}
		configOverrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(configLoadingRules, configOverrides)

		// Obtener el *rest.Config para usar con la API de Kubernetes
		config, err := kubeConfig.ClientConfig()
		if err != nil {
			log.Fatalf("Failed to load Kubernetes client configuration: %v", err)
		}

		// Crear el cliente de Kubernetes
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Fatalf("Failed to create Kubernetes client: %v", err)
		}

		fmt.Println("Deploying pod with volume...:", baseDir)
		if err := client.DeployPod(clientset, "ssh-pod", namespace, taggedImage); err != nil {
			log.Fatalf("Failed to deploy pod: %v", err)
		}

		// Esperar que el pod esté listo
		client.WaitForPod(clientset, "ssh-pod", namespace)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel() // Ensure context is canceled when main returns or upon cancellation signal

		// Tarea 1: Port-forwarding en una goroutine

		go client.EnsurePortForwarding(ctx, namespace, "ssh-pod", 3000, 3000)
		// Tarea 2: Ejecutar el script refreshv2 en una goroutine
		go func() {

			refreshCmdStr := fmt.Sprintf("/Volumes/DataJack/Jack/multims/refreshv2 %s", baseDir)
			fmt.Println("Executing refreshv2 script at:", baseDir)
			if output, err := exec.Command("bash", "-c", refreshCmdStr).CombinedOutput(); err != nil {
				log.Printf("Failed to execute refreshv2 script: %s\nError: %v", string(output), err)
			} else {
				log.Printf("Successfully executed refreshv2 script. Output:\n%s", string(output))
			}
		}()

		// Ejecutar el comando principal para interactuar con el pod
		if err := client.ExecIntoPod(clientset, config, "ssh-pod", namespace, input, directory); err != nil {
			log.Fatalf("Error executing into pod: %v", err)
		}

		// Cancelar el contexto para terminar todas las goroutines al salir de ExecIntoPod
		cancel()

		// Esperar una señal para terminar la ejecución completamente
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c // Bloquear hasta que se reciba una señal
		fmt.Println("Shutting down...")
	},
}
