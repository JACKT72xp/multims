package operations

import (
	"context"
	"fmt"
	"log"
	kong "multims/pkg/build"
	"multims/pkg/client"
	"multims/pkg/config"
	"multims/pkg/container"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func MultiServiceHandler() {
	// Configuración del cliente de Kubernetes
	configPath := filepath.Join(".", "multims.yml")
	conf, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		log.Fatalf("Failed to load config from file: %v", err)
	}
	kubeConfigPath := conf.KubeConfigPath
	contextName := conf.KubernetesContext
	namespace := conf.Namespace
	multiservices := conf.MultiServices
	// Crear un nuevo servicio
	newService := config.ServiceConfig{Name: "service-" + conf.UID, Image: "withoutimage", Port: int(conf.Application.Port)}
	// Declarar multiservices2 y asignar el resultado de append
	multiservices2 := append(multiservices, newService)

	configLoadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeConfigPath}
	configOverrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(configLoadingRules, configOverrides)

	config, err := kubeConfig.ClientConfig()
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes clientset: %v", err)
	}

	// // Limpieza de recursos al inicio
	// if err := cleanupResources(clientset, namespace, multiservices); err != nil {
	// 	log.Fatalf("Failed to clean up resources: %v", err)
	// }

	// Desplegar Kong y servicios externos

	fmt.Print("Deploying MultiServices...")

	if err := kong.DeployExternalServices(clientset, namespace, multiservices); err != nil {
		log.Fatalf("Failed to deploy MultiServices: %v", err)
	}

	if err := kong.DeployKong(clientset, namespace, multiservices2); err != nil {
		log.Fatalf("Failed to deploy Kong: %v", err)
	}
	fmt.Println("Kong deployed successfully in multi-service mode.")
	fmt.Println("Running...")

	OnlyOneService(multiservices2, namespace, conf.UID)

	// Verificar el estado de los pods en un bucle infinito
	// for {
	// 	watcher, err := clientset.CoreV1().Pods(namespace).Watch(context.Background(), metav1.ListOptions{})
	// 	if err != nil {
	// 		log.Printf("Error watching pods: %v", err)
	// 		time.Sleep(30 * time.Second) // Esperar antes de volver a intentar
	// 		continue
	// 	}
	// 	defer watcher.Stop()

	// 	// Manejar los eventos de los pods
	// 	for event := range watcher.ResultChan() {
	// 		pod, ok := event.Object.(*corev1.Pod)
	// 		if !ok {
	// 			log.Printf("Unexpected object type: %v", event.Object)
	// 			continue
	// 		}

	// 		switch event.Type {
	// 		case watch.Added:
	// 			// Pod agregado
	// 			fmt.Printf("Pod added: %v\n", pod.ObjectMeta.Name)
	// 		case watch.Modified:
	// 			// Pod modificado
	// 			fmt.Printf("Pod modified: %v\n", pod.ObjectMeta.Name)
	// 		case watch.Deleted:
	// 			// Pod eliminado
	// 			fmt.Printf("Pod deleted: %v\n", pod.ObjectMeta.Name)
	// 		case watch.Error:
	// 			// Error en el watch
	// 			fmt.Printf("Error watching pods: %v\n", event.Object)
	// 		}
	// 	}

	// 	time.Sleep(30 * time.Second) // Esperar antes de volver a verificar
	// 	// Limpieza de recursos al finalizar
	// }

}

func cleanupResources(clientset *kubernetes.Clientset, namespace string, multiservices []config.ServiceConfig) error {
	// Implementar lógica para eliminar recursos
	// En este caso, eliminar los pods creados anteriormente
	for _, service := range multiservices {
		podName := service.Name

		// Eliminar el pod del namespace
		err := clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("failed to delete pod %s: %v", podName, err)
		}
		fmt.Printf("Pod %s deleted successfully\n", podName)
	}

	return nil
}
func OnlyOneServiceHandler() {
	// Mueve el código de "onlyoneservice" aquí para reutilización y claridad
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
	uid := conf.UID
	exist := container.CheckRepository(repoName)
	languaje := conf.Technology

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
	port := conf.Application.Port

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
	image := ""
	switch languaje {
	case "Node":
		image = "node:lts-alpine3.19"
	case "Node-Typescript":
		image = "node:lts-alpine3.19"
	case "Python":
		image = "python:alpine3.19"
	}

	if err := client.DeployPod(clientset, uid, namespace, image, uid, port); err != nil { // client.DeployPod(clientset, uid, namespace, image, uid); err != nil {
		log.Fatalf("Failed to deploy pod: %v", err)
	}

	// Esperar que el pod esté listo
	client.WaitForPod(clientset, uid, namespace)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure context is canceled when main returns or upon cancellation signal

	// Tarea 1: Port-forwarding en una goroutine
	serviceName := fmt.Sprintf("service-%s", uid) // Por ejemplo, ajusta según cómo nombras tus servicios.

	go client.EnsurePortForwarding(clientset, ctx, namespace, serviceName, int(port), int(port))
	// Tarea 2: Ejecutar el script refreshv2 en una goroutine
	go func() {
		execPath, err := os.Executable()
		if err != nil {
			fmt.Println("Error al obtener el path del ejecutable:", err)
			return
		}
		execDir := filepath.Dir(execPath)
		scriptsPath := filepath.Join(execDir, "/opt/homebrew/etc/multims/scripts/refreshv2")
		refreshCmdStr := fmt.Sprintf("%s \"%s\" \"%s\" \"%s\"", scriptsPath, baseDir, uid, namespace)

		//refreshCmdStr := fmt.Sprintf("%s/../scripts/refreshv2 \"%s\" \"%s\" \"%s\"", execDir, baseDir, uid, namespace)
		//refreshCmdStr := fmt.Sprintf("%s/refreshv2 \"%s\" \"%s\" \"%s\"", execDir, baseDir, uid, namespace)
		//refreshCmdStr := fmt.Sprintf("/Volumes/DataJack/Jack/multims/refreshv2 \"%s\" \"%s\" \"%s\"", baseDir, uid, namespace)
		fmt.Println("Executing refreshv2 script at:", baseDir)
		fmt.Println("Executing refreshv2 script at:", uid)
		fmt.Println("Executing refreshv2 script at:", namespace)
		if output, err := exec.Command("bash", "-c", refreshCmdStr).CombinedOutput(); err != nil {
			log.Printf("Failed to execute refreshv2 script: %s\nError: %v", string(output), err)
		} else {
			log.Printf("Successfully executed refreshv2 script. Output:\n%s", string(output))
		}
	}()

	// Ejecutar el comando principal para interactuar con el pod
	if err := client.ExecIntoPod(clientset, config, uid, namespace, input, directory, languaje, nil); err != nil {
		log.Fatalf("Error executing into pod: %v", err)
	}

	// Cancelar el contexto para terminar todas las goroutines al salir de ExecIntoPod
	cancel()

	// Esperar una señal para terminar la ejecución completamente
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c // Bloquear hasta que se reciba una señal
	fmt.Println("Shutting down...")
}

func OnlyOneService(multiservices []config.ServiceConfig, namespace string, uid string) {
	// Mueve el código de "onlyoneservice" aquí para reutilización y claridad
	baseDir, err := os.Getwd()

	configPath := filepath.Join(".", "multims.yml")
	conf, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Login to ECR
	languaje := conf.Technology
	kubeConfigPath := conf.KubeConfigPath
	contextName := conf.KubernetesContext
	input := conf.Application.StartRun
	directory := conf.AppName
	port := conf.Application.Port

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
	image := ""
	switch languaje {
	case "Node":
		image = "node:lts-alpine3.19"
	case "Node-Typescript":
		image = "node:lts-alpine3.19"
	case "Python":
		image = "python:alpine3.19"
	}

	if err := client.DeployPod(clientset, uid, namespace, image, uid, port); err != nil { // client.DeployPod(clientset, uid, namespace, image, uid); err != nil {
		log.Fatalf("Failed to deploy pod: %v", err)
	}

	// Esperar que el pod esté listo
	client.WaitForPod(clientset, uid, namespace)

	go func() {
		execPath, err := os.Executable()
		if err != nil {
			fmt.Println("Error al obtener el path del ejecutable:", err)
			return
		}
		execDir := filepath.Dir(execPath)
		//refreshCmdStr := fmt.Sprintf("%s/../scripts/refreshv2 \"%s\" \"%s\" \"%s\"", execDir, baseDir, uid, namespace)
		//execDir := filepath.Dir(execPath)
		scriptsPath := filepath.Join(execDir, "../multims/scripts/refreshv2")
		refreshCmdStr := fmt.Sprintf("%s \"%s\" \"%s\" \"%s\"", scriptsPath, baseDir, uid, namespace)

		//		refreshCmdStr := fmt.Sprintf("%s/refreshv2 \"%s\" \"%s\" \"%s\"", execDir, baseDir, uid, namespace)
		//refreshCmdStr := fmt.Sprintf("/Volumes/DataJack/Jack/multims/refreshv2 \"%s\" \"%s\" \"%s\"", baseDir, uid, namespace)
		fmt.Println("Executing refreshv2 script at:", baseDir)
		fmt.Println("Executing refreshv2 script at:", uid)
		fmt.Println("Executing refreshv2 script at:", namespace)
		if output, err := exec.Command("bash", "-c", refreshCmdStr).CombinedOutput(); err != nil {
			log.Printf("Failed to execute refreshv2 script: %s\nError: %v", string(output), err)
		} else {
			log.Printf("Successfully executed refreshv2 script. Output:\n%s", string(output))
		}
	}()

	// Ejecutar el comando principal para interactuar con el pod
	if err := client.ExecIntoPod(clientset, config, uid, namespace, input, directory, languaje, multiservices); err != nil {
		log.Fatalf("Error executing into pod: %v", err)
	}

	// Esperar una señal para terminar la ejecución completamente
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c // Bloquear hasta que se reciba una señal
	fmt.Println("Shutting down...")
}
