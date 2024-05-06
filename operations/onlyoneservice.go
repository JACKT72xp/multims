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
	"strings"
	"syscall"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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

// Autentica con el registro Docker usando AWS ECR.
func executeLoginCommand(conf *config.Config) {
	loginCmdStr := fmt.Sprintf("aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin %s", conf.RegistryURL)
	loginCmd := exec.Command("bash", "-c", loginCmdStr)
	loginOutput, err := loginCmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to login to Docker: %s, %v", string(loginOutput), err)
	}
	fmt.Println("Logged into Docker with ECR successfully.")
}

// Asegura que el repositorio Docker exista en AWS ECR.
func ensureRepository(conf *config.Config) {
	repoName := fmt.Sprintf("%s", conf.AppName)
	exist := container.CheckRepository(repoName) // Asume una función que verifica la existencia del repositorio
	if !exist {
		err := container.CreateRepository(repoName) // Asume una función que crea el repositorio
		if err != nil {
			log.Fatalf("Failed to create repository: %v", err)
		}
		fmt.Println("Repository created successfully:", repoName)
	} else {
		fmt.Println("Repository already exists:", repoName)
	}
}

// Construye la imagen Docker basada en la configuración y el directorio base.
func buildDockerImage(conf *config.Config, baseDir string) {
	appImage := fmt.Sprintf("%s/%s:latest", conf.RegistryURL, conf.AppName)
	dockerfilePath := filepath.Join(baseDir, ".multims", "Dockerfile")

	buildCmd := exec.Command("docker", "build", "--platform=linux/amd64", "-t", appImage, "-f", dockerfilePath, ".")
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to build Docker image: %s, %v", string(buildOutput), err)
	}
	fmt.Println("Docker image built successfully:", appImage)
}

func manageDockerImage(conf *config.Config, baseDir string) {
	appName := strings.TrimPrefix(conf.AppName, "/")

	if conf.RegistryURL == "" {
		fmt.Println("RegistryURL is empty, skipping Docker image operations.")
		return // Salir de la función si no hay URL del registro
	}

	registryURL := strings.TrimPrefix(conf.RegistryURL, "/")
	appImage := fmt.Sprintf("%s/%s:latest", registryURL, appName)

	// Comando para construir la imagen Docker
	dockerfilePath := filepath.Join(baseDir, ".multims", "Dockerfile")
	buildCmd := exec.Command("docker", "build", "--platform=linux/amd64", "-t", appImage, "-f", dockerfilePath, ".")
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to build Docker image: %s, %v", string(buildOutput), err)
	}
	fmt.Println("Docker image built successfully:", appImage)

	// Continúa con el etiquetado y empuje de la imagen
	tagAndPushDockerImage(conf, appName) // Ajustada para pasar appName limpio
}

func buildImage(appImage, baseDir string) {
	dockerfilePath := filepath.Join(baseDir, ".multims", "Dockerfile")
	buildCmd := exec.Command("docker", "build", "--platform=linux/amd64", "-t", appImage, "-f", dockerfilePath, ".")
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to build Docker image: %s, %v", string(buildOutput), err)
	}
	fmt.Println("Docker image built successfully:", appImage)
}

func tagAndPushDockerImage(conf *config.Config, appName string) {
	if conf.RegistryURL == "" {
		fmt.Println("RegistryURL is empty, skipping tagging and pushing Docker image.")
		return // Salir si no hay URL de registro
	}

	registryURL := strings.TrimPrefix(conf.RegistryURL, "/")
	appImage := fmt.Sprintf("%s/%s:latest", registryURL, appName)
	taggedImage := fmt.Sprintf("%s/%s:%s", registryURL, appName, conf.UID)

	// Etiquetar la imagen Docker
	tagCmd := exec.Command("docker", "tag", appImage, taggedImage)
	tagOutput, err := tagCmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to tag Docker image: %s, %v", string(tagOutput), err)
	}
	fmt.Println("Docker image tagged successfully:", taggedImage)

	// Empujar la imagen Docker al registro
	pushCmd := exec.Command("docker", "push", taggedImage)
	pushOutput, err := pushCmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to push Docker image: %s, %v", string(pushOutput), err)
	}
	fmt.Println("Docker image pushed successfully:", taggedImage)
}

// Inicia sesión en el registro de Docker basado en la configuración.
func loginToRegistry(conf *config.Config) {
	if conf.RegistryOrDocker == "AWS ECR" {
		executeLoginCommand(conf)
		ensureRepository(conf)
	} else {
		fmt.Println("Use Dockerhub Local.")
	}
}

// Determina el puerto adecuado basado en el tipo de base de datos.
func determineDatabasePort(dbType string) int {
	switch dbType {
	case "postgres":
		return 5432
	case "mysql":
		return 3306
	default:
		return 0 // Retorna 0 si no se reconoce el tipo de base de datos
	}
}

// PortForward establece un reenvío de puerto para un servicio en Kubernetes.
func PortForward(clientset *kubernetes.Clientset, ctx context.Context, namespace, serviceName string, localPort, remotePort int) error {
	if clientset == nil {
		return fmt.Errorf("clientset is nil, cannot perform port-forwarding")
	}

	cmdStr := fmt.Sprintf("kubectl port-forward service/%s %d:%d -n %s", serviceName, localPort, remotePort, namespace)
	fmt.Println("Executing command: ", cmdStr)

	cmd := exec.Command("bash", "-c", cmdStr)
	if err := cmd.Start(); err != nil {
		log.Printf("Failed to start port-forwarding: %v", err)
		return err
	}
	// Añade el manejo adecuado aquí para cuando cmd termina o el contexto es cancelado
	return nil
}

// Configura el port forwarding para un servicio específico.
func ensurePortForwarding(clientset *kubernetes.Clientset, ctx context.Context, namespace, serviceName string, targetPort, localPort int) {
	if clientset == nil {
		log.Fatal("Kubernetes clientset is not initialized")
		return
	}
	// Luego sigue con el port-forwarding
	PortForward(clientset, ctx, namespace, serviceName, targetPort, localPort)
}

// Despliega un pod de aplicación en Kubernetes.
func deployApplicationPod(clientset *kubernetes.Clientset, conf *config.Config, baseDir string) {
	image := selectImageBasedOnLanguage(conf.Technology)
	if err := client.DeployPod(clientset, conf.UID, conf.Namespace, image, conf.UID, conf.Application.Port, conf.InstallationCommands); err != nil {
		log.Fatalf("Failed to deploy application pod: %v", err)
	}
}

// Función auxiliar para seleccionar la imagen de Docker basada en el lenguaje de programación.
func selectImageBasedOnLanguage(language string) string {
	switch language {
	case "Node", "Node-Typescript":
		return "node:lts-alpine3.19"
	case "Python":
		return "python:alpine3.19"
	default:
		return "ubuntu:latest" // Retorna Ubuntu como imagen predeterminada
	}
}

// Gestiona el port-forwarding usando goroutines.
func managePortForwarding(clientset *kubernetes.Clientset, conf *config.Config) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serviceName := fmt.Sprintf("service-%s", conf.UID)

	go ensurePortForwarding(clientset, ctx, conf.Namespace, serviceName, int(conf.Application.Port), 80)
}

// Espera una señal de interrupción para terminar el programa.
func waitForExitSignal() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	fmt.Println("Shutting down...")
}

// Despliega un pod para la base de datos en Kubernetes.
// func deployDatabasePod(clientset *kubernetes.Clientset, conf *config.Config) {
// 	databaseConfig := conf.Database
// 	if err := client.DeployPodDatabase(clientset, conf.Namespace, conf.UID, databaseConfig); err != nil {
// 		log.Fatalf("Failed to deploy database pod: %v", err)
// 	}
// }

// Carga la configuración de Kubernetes desde un archivo.
func loadKubeConfig(conf *config.Config) clientcmd.ClientConfig {
	configLoadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: conf.KubeConfigPath}
	configOverrides := &clientcmd.ConfigOverrides{CurrentContext: conf.KubernetesContext}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(configLoadingRules, configOverrides)
}

// Implementa los servicios y bases de datos en Kubernetes.
func deployServices(clientset *kubernetes.Clientset, conf *config.Config, baseDir string) {
	// deployApplicationPod(clientset, conf, baseDir)
	// if conf.Database.Active {
	// 	deployDatabasePod(clientset, conf)
	// }

	deployApplicationFull(clientset, conf, baseDir)
}

func deployApplicationFull(clientset *kubernetes.Clientset, conf *config.Config, baseDir string) {
	image := selectImageBasedOnLanguage(conf.Technology)
	if err := client.DeployPodV2(clientset, conf, baseDir, image); err != nil {
		log.Fatalf("Failed to deploy application pod: %v", err)
	}
}

// Carga y valida la configuración inicial desde un archivo.
func loadConfiguration() (string, *config.Config) {
	baseDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get working directory: %v", err)
	}

	configPath := filepath.Join(".", "multims.yml")
	conf, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	return baseDir, conf
}

// Crea un cliente de Kubernetes basado en la configuración proporcionada y no retorna *rest.Config.
func createKubernetesClient(kubeConfig clientcmd.ClientConfig) (*kubernetes.Clientset, error) {
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

// Configura y devuelve el cliente de Kubernetes.
// Configura y devuelve el cliente de Kubernetes y el objeto config.
// Configura y devuelve el cliente de Kubernetes.
func configureKubernetesClient(conf *config.Config) (*kubernetes.Clientset, *rest.Config) {
	kubeConfig := loadKubeConfig(conf)
	clientset, err := createKubernetesClient(kubeConfig)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
		return nil, nil // Retorna nil para ambos en caso de error
	}

	// Necesitas obtener el rest.Config de otra forma o modificar createKubernetesClient para devolverlo.
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		log.Fatalf("Failed to obtain Kubernetes rest config: %v", err)
		return nil, nil
	}

	return clientset, config
}

// executeRefreshScript ejecuta el script refreshv2 en el entorno especificado
func executeRefreshScriptRefresh(baseDir, uid, namespace string) {
	scriptsPath := "/Volumes/DataJack/Jack/multims/scripts/refreshv3"
	refreshCmdStr := fmt.Sprintf("%s \"%s\" \"%s\" \"%s\"", scriptsPath, baseDir, uid, namespace)
	fmt.Printf("Executing refreshv3 script at: %s, %s, %s\n", baseDir, uid, namespace)

	if output, err := exec.Command("bash", "-c", refreshCmdStr).CombinedOutput(); err != nil {
		log.Printf("Failed to execute refreshv2 script: %s\nError: %v", string(output), err)
	} else {
		log.Printf("Successfully executed refreshv2 script. Output:\n%s", string(output))
	}
}

// executeRefreshScript ejecuta el script refreshv2 en el entorno especificado
func executeRefreshScript(baseDir, uid, namespace string) {
	scriptsPath := "/Volumes/DataJack/Jack/multims/scripts/refreshv3Only"
	refreshCmdStr := fmt.Sprintf("%s \"%s\" \"%s\" \"%s\"", scriptsPath, baseDir, uid, namespace)
	fmt.Printf("Executing refreshv3 script at: %s, %s, %s\n", baseDir, uid, namespace)

	if output, err := exec.Command("bash", "-c", refreshCmdStr).CombinedOutput(); err != nil {
		log.Printf("Failed to execute refreshv2 script: %s\nError: %v", string(output), err)
	} else {
		log.Printf("Successfully executed refreshv2 script. Output:\n%s", string(output))
	}
}

func OnlyOneServiceHandler() {

	baseDir, conf := loadConfiguration()
	loginToRegistry(conf)
	manageDockerImage(conf, baseDir)

	clientset, config := configureKubernetesClient(conf) // Ajusta para recibir ambos valores

	deployServices(clientset, conf, baseDir)
	// Canal para indicar cuando executeRefreshScript ha terminado
	refreshDone := make(chan struct{})

	// Ejecuta executeRefreshScript una vez
	go func() {
		executeRefreshScript(baseDir, conf.UID, conf.Namespace)
		close(refreshDone) // Indica que executeRefreshScript ha terminado
	}()
	// Ejecutar comando dentro del pod
	<-refreshDone

	// Ejecuta executeRefreshScriptRefresh de manera infinita
	go executeRefreshScriptRefresh(baseDir, conf.UID, conf.Namespace)

	// Ejecuta ExecIntoPod
	uid, namespace, input, directory, language := conf.UID, conf.Namespace, conf.Application.StartRun, conf.AppName, conf.Technology
	if err := client.ExecIntoPod(clientset, config, uid, namespace, input, directory, language, nil); err != nil {
		log.Fatalf("Error executing into pod: %v", err)
	}

	managePortForwarding(clientset, conf)
	waitForExitSignal()
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

	if err := client.DeployPod(clientset, uid, namespace, image, uid, port, conf.InstallationCommands); err != nil { // client.DeployPod(clientset, uid, namespace, image, uid); err != nil {
		log.Fatalf("Failed to deploy pod: %v", err)
	}

	// Esperar que el pod esté listo
	client.WaitForPod(clientset, uid, namespace)

	go func() {
		//refreshCmdStr := fmt.Sprintf("%s/../scripts/refreshv2 \"%s\" \"%s\" \"%s\"", execDir, baseDir, uid, namespace)
		//execDir := filepath.Dir(execPath)
		scriptsPath := "/opt/homebrew/etc/multims/scripts/refreshv2"
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
