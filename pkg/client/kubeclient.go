package client

import (
	"context"
	"fmt"
	"io"
	"log"
	"multims/pkg/config"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

type terminalSizeQueue struct {
	resizeEvents chan remotecommand.TerminalSize
}

// ANSIWriter es un io.Writer que filtra secuencias de escape ANSI antes de escribir a la salida.
type ANSIWriter struct {
	writer io.Writer
}

func (a *ANSIWriter) Write(p []byte) (int, error) {
	re := regexp.MustCompile(`\x1b\[\d+(;\d+)?[A-HJKSTfimnsu]`)
	cleaned := re.ReplaceAll(p, nil)
	_, err := a.writer.Write(cleaned) // Ignora el valor de bytes escritos
	return len(p), err                // Devuelve la longitud original de p y cualquier error
}

func SetupKubernetesConnection(kubeconfigPath, contextName, namespace string) {
	// Cargar el archivo kubeconfig y seleccionar un contexto específico
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{CurrentContext: contextName},
	)

	config, err := loader.ClientConfig()
	if err != nil {
		log.Fatalf("Error building kubeconfig: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating Kubernetes clientset: %v", err)
	}

	// Intentar listar los pods para verificar permisos
	pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), v1.ListOptions{})
	if err != nil {
		if errors.IsForbidden(err) {
			log.Fatalf("No tienes permisos completos en el contexto '%s'.", contextName)
		} else {
			log.Fatalf("Error listing pods: %v", err)
		}
	}

	// Informar el número de pods en el namespace o en todos los namespaces si no se especifica
	if namespace == "" {
		fmt.Printf("Connected to context '%s', total pods found: %d\n", contextName, len(pods.Items))
	} else {
		fmt.Printf("Connected to context '%s' in namespace '%s', total pods found: %d\n", contextName, namespace, len(pods.Items))
	}
}

// ListNamespaces lista los namespaces disponibles en el cluster
func ListNamespaces(kubeconfig string) ([]string, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("Error building kubeconfig: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("Error creating Kubernetes clientset: %v", err)
	}

	namespaces, err := clientset.CoreV1().Namespaces().List(context.TODO(), v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("Error listing namespaces: %v", err)
	}

	var nsList []string
	for _, ns := range namespaces.Items {
		nsList = append(nsList, ns.Name)
	}
	return nsList, nil
}

func WaitForPodReady(clientset *kubernetes.Clientset, podName, namespace string) error {
	for {
		pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, v1.GetOptions{})
		if err != nil {
			return err
		}
		if pod.Status.Phase == "Running" {
			for _, cond := range pod.Status.Conditions {
				if cond.Type == "Ready" && cond.Status == "True" {
					fmt.Println("Pod is now ready")
					return nil
				}
			}
		}
		time.Sleep(5 * time.Second)
		fmt.Println("Waiting for pod to be ready...")
	}
}

// NewTerminalSizeQueue creates a queue to handle terminal resize events.
func NewTerminalSizeQueue() remotecommand.TerminalSizeQueue {
	resizeEvents := make(chan remotecommand.TerminalSize)
	go func() {
		// In a real implementation, you'd hook this up to listen for terminal resize events.
		// For now, let's simulate a resize event:
		resizeEvents <- remotecommand.TerminalSize{Width: 80, Height: 40}
		close(resizeEvents)
	}()
	return &terminalSizeQueue{resizeEvents: resizeEvents}
}

func (t *terminalSizeQueue) Next() *remotecommand.TerminalSize {
	event, ok := <-t.resizeEvents
	if !ok {
		return nil // Channel was closed
	}
	return &event
}

// func ExecIntoPod(clientset *kubernetes.Clientset, config *rest.Config, podName, namespace string) error {
// 	// Setup cancellation context and signal handling
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	sigs := make(chan os.Signal, 1)
// 	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
// 	go func() {
// 		<-sigs
// 		fmt.Println("Received an interrupt, deleting pod...")
// 		cancel() // Signal the context to cancel
// 	}()

// 	cmd := []string{"/bin/sh"}
// 	req := clientset.CoreV1().RESTClient().
// 		Post().
// 		Resource("pods").
// 		Name(podName).
// 		Namespace(namespace).
// 		SubResource("exec").
// 		VersionedParams(&corev1.PodExecOptions{
// 			Command: cmd,
// 			Stdin:   true,
// 			Stdout:  true,
// 			Stderr:  true,
// 			TTY:     true,
// 		}, scheme.ParameterCodec)

// 	executor, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
// 	if err != nil {
// 		return fmt.Errorf("error creating SPDY executor: %v", err)
// 	}

// 	streamErr := executor.StreamWithContext(ctx, remotecommand.StreamOptions{
// 		Stdin:  os.Stdin,
// 		Stdout: os.Stdout,
// 		Stderr: os.Stderr,
// 		Tty:    true,
// 	})

// 	fmt.Println("Session completed. Deleting the pod...")
// 	deletePolicy := v1.DeletePropagationForeground
// 	deleteOptions := v1.DeleteOptions{
// 		PropagationPolicy: &deletePolicy,
// 	}
// 	if deleteErr := clientset.CoreV1().Pods(namespace).Delete(context.TODO(), podName, deleteOptions); deleteErr != nil {
// 		fmt.Printf("Failed to delete pod: %v\n", deleteErr)
// 		return deleteErr
// 	}

//		fmt.Println("Pod deleted successfully.")
//		return streamErr
//	}
func filterANSISequences(data []byte) []byte {
	// Regex para identificar secuencias de escape ANSI
	re := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	return re.ReplaceAll(data, nil)
}

// func EnsurePortForwarding(ctx context.Context, namespace, podName string, localPort, remotePort int) {
// 	cmdStr := fmt.Sprintf("kubectl port-forward pod/%s %d:%d -n %s", podName, localPort, remotePort, namespace)

//		for {
//			select {
//			case <-ctx.Done():
//				log.Println("Port-forwarding canceled.")
//				return
//			default:
//				if podReady(namespace, podName) {
//					cmd := exec.Command("bash", "-c", cmdStr)
//					if err := cmd.Start(); err != nil {
//						log.Printf("Failed to start port-forwarding: %v", err)
//					} else {
//						log.Println("Port-forwarding established successfully.")
//						// Espera a que el comando termine o sea cancelado
//						done := make(chan error, 1)
//						go func() { done <- cmd.Wait() }()
//						select {
//						case <-ctx.Done():
//							if err := cmd.Process.Kill(); err != nil {
//								log.Printf("Failed to kill port-forward process: %v", err)
//							}
//							return
//						case err := <-done:
//							if err != nil {
//								log.Printf("Port-forwarding stopped unexpectedly: %v", err)
//								log.Println("Retrying in 10 seconds...")
//								time.Sleep(5 * time.Second)
//								continue
//							}
//						}
//					}
//				} else {
//					log.Println("Pod is not ready for port-forwarding. Retrying in 10 seconds...")
//					time.Sleep(5 * time.Second)
//				}
//			}
//		}
//	}

func serviceReady(clientset *kubernetes.Clientset, namespace, serviceName string) bool {
	// Verificar la existencia del servicio (no necesitamos usar la variable 'service' directamente)
	if _, err := clientset.CoreV1().Services(namespace).Get(context.TODO(), serviceName, v1.GetOptions{}); err != nil {
		log.Printf("Error retrieving service: %v", err)
		return false
	}

	// Verificar la presencia de endpoints asociados al servicio
	endpoints, err := clientset.CoreV1().Endpoints(namespace).Get(context.TODO(), serviceName, v1.GetOptions{})
	if err != nil {
		log.Printf("Error retrieving endpoints for service: %v", err)
		return false
	}

	if len(endpoints.Subsets) > 0 {
		for _, subset := range endpoints.Subsets {
			if len(subset.Addresses) > 0 {
				return true // Hay al menos una dirección IP asociada al endpoint
			}
		}
	}

	log.Println("Service has no active endpoints.")
	return false
}

func EnsurePortForwarding(clientset *kubernetes.Clientset, ctx context.Context, namespace, serviceName string, localPort, remotePort int) {
	cmdStr := fmt.Sprintf("kubectl port-forward service/%s %d:%d -n %s", serviceName, localPort, remotePort, namespace)
	fmt.Print(cmdStr)
	for {
		select {
		case <-ctx.Done():
			log.Println("Port-forwarding canceled.")
			return
		default:
			if serviceReady(clientset, namespace, serviceName) {
				cmd := exec.Command("bash", "-c", cmdStr)
				if err := cmd.Start(); err != nil {
					log.Printf("Failed to start port-forwarding: %v", err)
				} else {
					log.Println("Port-forwarding established successfully.")
					// Espera a que el comando termine o sea cancelado
					done := make(chan error, 1)
					go func() { done <- cmd.Wait() }()
					select {
					case <-ctx.Done():
						if err := cmd.Process.Kill(); err != nil {
							log.Printf("Failed to kill port-forward process: %v", err)
						}
						return
					case err := <-done:
						if err != nil {
							log.Printf("Port-forwarding stopped unexpectedly: %v", err)
							log.Println("Retrying in 10 seconds...")
							time.Sleep(10 * time.Second)
							continue
						}
					}
				}
			} else {
				log.Println("Service is not ready for port-forwarding. Retrying in 10 seconds...")
				time.Sleep(10 * time.Second)
			}
		}
	}
}

// func EnsurePortForwarding(namespace, podName string, localPort, remotePort int) {
// 	cmdStr := fmt.Sprintf("kubectl port-forward pod/%s %d:%d -n %s", podName, localPort, remotePort, namespace)

// 	for {
// 		if podReady(namespace, podName) {
// 			if output, err := exec.Command("bash", "-c", cmdStr).CombinedOutput(); err != nil {
// 				log.Printf("Failed to start port-forwarding: %s, %v", string(output), err)
// 			} else {
// 				log.Println("Port-forwarding established successfully.")
// 				return // Exit the function if port-forwarding is established successfully
// 			}
// 		}
// 		log.Println("Pod is not ready for port-forwarding. Retrying in 10 seconds...")
// 		time.Sleep(10 * time.Second) // Wait before retrying
// 	}
// }

func podReady(namespace, podName string) bool {
	cmdStr := fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.status.phase}'", podName, namespace)
	output, err := exec.Command("bash", "-c", cmdStr).Output()
	if err != nil {
		log.Printf("Error checking pod status: %v", err)
		return false
	}
	return strings.TrimSpace(string(output)) == "Running"
}

// buildCommand constructs the command string based on language and other parameters.
// buildCommand constructs the command string based on language and other parameters.
// buildCommand constructs the command string based on language and other parameters.
func buildCommand(language, directory, input string) string {
	bashSetup := `echo "PS1='\[\033[35m\]\u@\h \[\033[33m\]\w\[\033[0m\] \$ '" >> ~/.bashrc && echo "alias ll='ls -lha --color=auto'" >> ~/.bashrc && source ~/.bashrc`

	switch language {
	case "Node", "Node-Typescript":
		return fmt.Sprintf("%s && sleep 10 && npm i nodemon -g && exec /bin/bash", bashSetup)
	case "Python":
		return fmt.Sprintf("%s && sleep 10 && cd /home/%s && pip install -r requirements.txt && echo 'Ready to run your Python application. Type: python main.py' && exec /bin/bash", bashSetup, directory)
	default:
		return bashSetup
	}
}

// Function to execute a command in a pod with interactive terminal
func ExecIntoPodV2(clientset *kubernetes.Clientset, config *rest.Config, podName, namespace string) error {
	cmd := []string{"/bin/sh"} // Use /bin/bash if bash is available in the container

	req := clientset.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command:   cmd,
			Container: podName,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("failed to create executor: %v", executor)
	}

	// Create a pty
	ptmx, err := pty.Start(exec.Command("kubectl", "attach", "-it", podName, "-n", namespace, "--container", podName))
	if err != nil {
		return err
	}
	defer ptmx.Close()

	// Handle pty size.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			if err := pty.InheritSize(os.Stdin, ptmx); err != nil {
				fmt.Fprintf(os.Stderr, "error resizing pty: %s", err)
			}
		}
	}()
	ch <- syscall.SIGWINCH // Initial resize.

	// Redirect input and output
	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()
	_, err = io.Copy(os.Stdout, ptmx)

	return err
}

func ExecIntoPod(clientset *kubernetes.Clientset, config *rest.Config, podName, namespace string, input string, directory string, language string, servicesKong []config.ServiceConfig) error {
	// Contexto principal que no se cancela automáticamente
	ctx := context.Background()

	// Canal para manejar la señal de interrupción
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	// Goroutine para manejar la interrupción y limpieza
	go func() {
		<-sigs
		fmt.Println("\033[31mCTRL+C received, cleaning up...\033[0m")

		// Contexto específico para la limpieza para asegurar que se complete
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelCleanup()

		cleanup(clientset, podName, namespace, servicesKong, cleanupCtx) // Modificado para pasar contexto de limpieza

		os.Exit(0) // Salir del programa después de la limpieza
	}()

	lastCommand := buildCommand(language, directory, input)
	fmt.Printf("\033[34mCommands to apply: \033[1;34m%s\033[0m\n", lastCommand)

	command := []string{"/bin/sh", "-c", lastCommand}
	req := clientset.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command:   command,
			Container: podName,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		fmt.Printf("\033[31mFailed to create executor: %v\033[0m\n", err)
		return err
	}

	streamOptions := remotecommand.StreamOptions{
		Stdin:  os.Stdin,
		Stdout: &ANSIWriter{writer: os.Stdout},
		Stderr: &ANSIWriter{writer: os.Stderr},
		Tty:    true,
	}

	if err := executor.StreamWithContext(ctx, streamOptions); err != nil {
		fmt.Printf("\033[31mError in streaming: %v\033[0m\n", err)
		return err
	}

	fmt.Fprint(os.Stdout, "\033[2J\033[H") // Limpia la pantalla
	return nil
}

// cleanup maneja la eliminación del pod y cualquier otro recurso
func cleanup(clientset *kubernetes.Clientset, podName, namespace string, services []config.ServiceConfig, ctx context.Context) {
	fmt.Println("Cleaning up resources...", services)
	if err := deleteResources(clientset, podName, namespace, services, ctx); err != nil {
		fmt.Printf("Failed to clean up resources: %v\n", err)
	}
	// Aquí puedes agregar más llamadas para limpiar otros recursos si es necesario
}
func deleteResources(clientset *kubernetes.Clientset, podName, namespace string, services []config.ServiceConfig, ctx context.Context) error {
	fmt.Printf("Deleting pod %s in namespace %s...\n", podName, namespace)

	// Opciones de eliminación para los recursos
	deletePolicy := v1.DeletePropagationForeground
	deleteOptions := &v1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	}

	// Elimina el pod utilizando el contexto para permitir cancelación y timeout
	if err := clientset.CoreV1().Pods(namespace).Delete(ctx, podName, *deleteOptions); err != nil {
		fmt.Printf("Failed to delete pod: %v\n", err)
		return err
	} else {
		fmt.Println("Pod deletion initiated successfully.")
	}

	// Eliminar todos los servicios asociados listados en services
	for _, service := range services {
		serviceName := service.Name
		fmt.Printf("Deleting service %s in namespace %s...\n", serviceName, namespace)
		if err := clientset.CoreV1().Services(namespace).Delete(ctx, serviceName, *deleteOptions); err != nil {
			fmt.Printf("Failed to delete service: %v\n", err)
			return err
		} else {
			fmt.Printf("Service deletion initiated successfully: %s\n", serviceName)
		}
	}

	return nil
}

func deletePod(clientset *kubernetes.Clientset, podName, namespace string, services []config.ServiceConfig) {
	fmt.Printf("Deleting pod %s in namespace %s...\n", podName, namespace)
	deletePolicy := v1.DeletePropagationForeground
	deleteOptions := &v1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	}
	if err := clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, *deleteOptions); err != nil {
		fmt.Printf("Failed to delete pod: %v\n", err)
	} else {
		fmt.Println("Pod deletion initiated successfully.")
		// Optionally, you can add a wait mechanism to ensure the pod is deleted before continuing.
		waitForPodDeletion(clientset, podName, namespace)
	}
}
func waitForPodDeletion(clientset *kubernetes.Clientset, podName, namespace string) {
	for {
		_, err := clientset.CoreV1().Pods(namespace).Get(context.Background(), podName, v1.GetOptions{})
		if err != nil {
			fmt.Println("Pod has been deleted successfully.")
			break
		}
		fmt.Println("Waiting for pod to be deleted...")
		time.Sleep(2 * time.Second)
	}
}

// func DeployPodWithVolume(clientset *kubernetes.Clientset, podName string, namespace string, imagePath string, localPath string) error {
// 	// Deploy el pod
// 	if err := deployPodWithVolume(clientset, podName, namespace, imagePath, localPath); err != nil {
// 		return err
// 	}

//		return nil
//	}
func ensureNginxConfigMap(clientset *kubernetes.Clientset, namespace, name, nginxConfig string) error {
	configMap, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, v1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			// Create a new ConfigMap if not exists
			configMap = &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Data: map[string]string{"nginx.conf": nginxConfig},
			}
			_, err = clientset.CoreV1().ConfigMaps(namespace).Create(context.TODO(), configMap, v1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create configmap for nginx config: %v", err)
			}
			fmt.Println("ConfigMap created successfully")
		} else {
			return fmt.Errorf("failed to get configmap: %v", err)
		}
	} else {
		// Update existing ConfigMap
		configMap.Data["nginx.conf"] = nginxConfig
		_, err = clientset.CoreV1().ConfigMaps(namespace).Update(context.TODO(), configMap, v1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update configmap: %v", err)
		}
		fmt.Println("ConfigMap updated successfully")
	}
	return nil
}

// func DeployPod(clientset *kubernetes.Clientset, name string, namespace string, image string, uid string, port int32) error {

// 	// Load the nginx.conf template
// 	nginxConfFile, err := os.ReadFile("/opt/homebrew/etc/multims/templates/onservice/nginx.conf")
// 	if err != nil {
// 		return fmt.Errorf("failed to read nginx config file: %v", err)
// 	}
// 	nginxConfig := strings.Replace(string(nginxConfFile), "{app_port}", fmt.Sprintf("%d", port), -1)

// 	// Ensure the Nginx ConfigMap is created or updated
// 	err = ensureNginxConfigMap(clientset, namespace, "nginx-config", nginxConfig)
// 	if err != nil {
// 		return err
// 	}

// 	podName := fmt.Sprintf("%s", name)
// 	serviceName := fmt.Sprintf("service-%s", name)

// 	// Verificar si el pod ya existe
// 	_, err2 := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, v1.GetOptions{})
// 	if err2 == nil {
// 		fmt.Println("Pod already exists:", podName)
// 	} else {
// 		// Si el pod no existe, crea uno nuevo
// 		pod := &corev1.Pod{
// 			ObjectMeta: v1.ObjectMeta{
// 				Name:      podName,
// 				Namespace: namespace,
// 				Labels: map[string]string{
// 					"app": name, // Usando el nombre base como etiqueta para agrupación
// 				},
// 			},
// 			Spec: corev1.PodSpec{
// 				RestartPolicy: "Never",
// 				Containers: []corev1.Container{
// 					{
// 						Name:  name,
// 						Image: image,
// 						Command: []string{
// 							"/bin/sh",
// 							"-c",
// 							"apk update && apk add bash && apk add rsync && sleep infinity",
// 						},
// 						Ports: []corev1.ContainerPort{
// 							{
// 								ContainerPort: port,
// 								Protocol:      "TCP",
// 								HostPort:      port,
// 							},
// 						},
// 						VolumeMounts: []corev1.VolumeMount{
// 							{
// 								Name:      "code-volume",
// 								MountPath: "/opt/code",
// 							},
// 						},
// 					},
// 					{
// 						Name:         "nginx",
// 						Image:        "nginx:latest",
// 						Ports:        []corev1.ContainerPort{{ContainerPort: 80, Protocol: "TCP"}},
// 						VolumeMounts: []corev1.VolumeMount{{Name: "nginx-config", MountPath: "/etc/nginx/nginx.conf", SubPath: "nginx.conf"}},
// 					},
// 				},
// 				Volumes: []corev1.Volume{
// 					{Name: "code-volume", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
// 					{Name: "nginx-config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "nginx-config"}}}},
// 				},
// 			},
// 		}

// 		_, err = clientset.CoreV1().Pods(namespace).Create(context.TODO(), pod, v1.CreateOptions{})
// 		if err != nil {
// 			return fmt.Errorf("failed to create pod: %v", err)
// 		}
// 		fmt.Println("Pod created successfully:", podName)
// 	}

// 	// Verificar si el servicio ya existe
// 	_, err = clientset.CoreV1().Services(namespace).Get(context.TODO(), serviceName, v1.GetOptions{})
// 	if err == nil {
// 		fmt.Println("Service already exists:", serviceName)
// 		return nil
// 	}

// 	// Si el servicio no existe, crea uno nuevo
// 	service := &corev1.Service{
// 		ObjectMeta: v1.ObjectMeta{
// 			Name:      serviceName,
// 			Namespace: namespace,
// 		},
// 		Spec: corev1.ServiceSpec{
// 			Selector: map[string]string{
// 				"app": name, // Selector basado en la etiqueta del pod
// 			},
// 			Ports: []corev1.ServicePort{
// 				{
// 					Port:       80,
// 					TargetPort: intstr.FromInt(80),
// 					Protocol:   "TCP",
// 				},
// 			},
// 			Type: corev1.ServiceTypeClusterIP, // Ajusta según necesidad
// 		},
// 	}

// 	_, err = clientset.CoreV1().Services(namespace).Create(context.TODO(), service, v1.CreateOptions{})
// 	if err != nil {
// 		return fmt.Errorf("failed to create service: %v", err)
// 	}
// 	fmt.Println("Service created successfully:", serviceName)

// 	return nil
// }

func DeployPod(clientset *kubernetes.Clientset, name string, namespace string, image string, uid string, port int32, installationCommands []string) error {
	// Verificar si el pod ya existe
	_, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), name, v1.GetOptions{})
	if err == nil {
		// Si el pod existe, borrarlo
		if err := clientset.CoreV1().Pods(namespace).Delete(context.TODO(), name, v1.DeleteOptions{}); err != nil {
			return fmt.Errorf("failed to delete existing pod: %v", err)
		}
		fmt.Println("Pod deleted:", name)
	} else if !k8serrors.IsNotFound(err) {
		// Si ocurre un error diferente a "not found", retornar el error
		return fmt.Errorf("failed to get pod: %v", err)
	}

	// Verificar si el servicio ya existe
	serviceName := fmt.Sprintf("service-%s", name)
	_, err = clientset.CoreV1().Services(namespace).Get(context.TODO(), serviceName, v1.GetOptions{})
	if err == nil {
		// Si el servicio existe, borrarlo
		if err := clientset.CoreV1().Services(namespace).Delete(context.TODO(), serviceName, v1.DeleteOptions{}); err != nil {
			return fmt.Errorf("failed to delete existing service: %v", err)
		}
		fmt.Println("Service deleted:", serviceName)
	} else if !k8serrors.IsNotFound(err) {
		// Si ocurre un error diferente a "not found", retornar el error
		return fmt.Errorf("failed to get service: %v", err)
	}

	// Cargar el archivo de configuración de nginx
	nginxConfFile, err := os.ReadFile("/opt/homebrew/etc/multims/templates/onservice/nginx.conf")
	if err != nil {
		return fmt.Errorf("failed to read nginx config file: %v", err)
	}
	nginxConfig := strings.Replace(string(nginxConfFile), "{app_port}", fmt.Sprintf("%d", port), -1)

	// Asegurar que el ConfigMap de Nginx se cree o actualice
	err = ensureNginxConfigMap(clientset, namespace, "nginx-config", nginxConfig)
	if err != nil {
		return err
	}

	// Crear el pod
	pod := &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app": name, // Usando el nombre base como etiqueta para agrupación
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: "Never",
			Containers: []corev1.Container{
				{
					Name:  name,
					Image: image,
					Command: []string{
						"/bin/sh",
						"-c",
						"apk update && apk add rsync && apk add --no-cache bash && sleep infinity",
					},
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: port,
							Protocol:      "TCP",
							HostPort:      port,
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "code-volume",
							MountPath: "/opt/code",
						},
					},
				},
				{
					Name:         "nginx",
					Image:        "nginx:latest",
					Ports:        []corev1.ContainerPort{{ContainerPort: 80, Protocol: "TCP"}},
					VolumeMounts: []corev1.VolumeMount{{Name: "nginx-config", MountPath: "/etc/nginx/nginx.conf", SubPath: "nginx.conf"}},
				},
			},
			Volumes: []corev1.Volume{
				{Name: "code-volume", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "nginx-config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "nginx-config"}}}},
			},
		},
	}

	_, err = clientset.CoreV1().Pods(namespace).Create(context.TODO(), pod, v1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create pod: %v", err)
	}
	fmt.Println("Pod created successfully:", name)

	// Crear el servicio
	service := &corev1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name:      serviceName,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": name}, // Selector basado en la etiqueta del pod
			Ports: []corev1.ServicePort{
				{
					Port:       80,
					TargetPort: intstr.FromInt(80),
					Protocol:   "TCP",
				},
			},
			Type: corev1.ServiceTypeClusterIP, // Ajusta según necesidad
		},
	}

	_, err = clientset.CoreV1().Services(namespace).Create(context.TODO(), service, v1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create service: %v", err)
	}
	fmt.Println("Service created successfully:", serviceName)

	return nil
}

func DeployPodV2(clientset *kubernetes.Clientset, conf *config.Config, baseDir string, image string) error {

	namespace := conf.Namespace
	name := conf.UID
	port := conf.Application.Port

	// Verificar si el pod ya existe
	_, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), name, v1.GetOptions{})
	if err == nil {
		// Si el pod existe, borrarlo
		if err := clientset.CoreV1().Pods(namespace).Delete(context.TODO(), name, v1.DeleteOptions{}); err != nil {
			return fmt.Errorf("failed to delete existing pod: %v", err)
		}
		fmt.Println("Pod deleted:", name)
	} else if !k8serrors.IsNotFound(err) {
		// Si ocurre un error diferente a "not found", retornar el error
		return fmt.Errorf("failed to get pod: %v", err)
	}
	// Verificar si el servicio ya existe
	serviceName := fmt.Sprintf("service-%s", name)
	_, err = clientset.CoreV1().Services(namespace).Get(context.TODO(), serviceName, v1.GetOptions{})
	if err == nil {
		// Si el servicio existe, borrarlo
		if err := clientset.CoreV1().Services(namespace).Delete(context.TODO(), serviceName, v1.DeleteOptions{}); err != nil {
			return fmt.Errorf("failed to delete existing service: %v", err)
		}
		fmt.Println("Service deleted:", serviceName)
	} else if !k8serrors.IsNotFound(err) {
		// Si ocurre un error diferente a "not found", retornar el error
		return fmt.Errorf("failed to get service: %v", err)
	}
	// Cargar el archivo de configuración de nginx
	nginxConfFile, err := os.ReadFile("/opt/homebrew/etc/multims/templates/onservice/nginx.conf")
	if err != nil {
		return fmt.Errorf("failed to read nginx config file: %v", err)
	}
	nginxConfig := strings.Replace(string(nginxConfFile), "{app_port}", fmt.Sprintf("%d", port), -1)

	// Asegurar que el ConfigMap de Nginx se cree o actualice
	err = ensureNginxConfigMap(clientset, namespace, "nginx-config", nginxConfig)
	if err != nil {
		return err
	}

	dbConfig := conf.Database

	db_image := ""
	configMapName := ""
	db_port := 5432

	if conf.Database.Active {
		configMapName = "postgres-config"
		if dbConfig.Type == "mysql" {
			db_image = "mysql:latest"
			configMapName = "mysql-config"
		} else if dbConfig.Type == "postgres" {
			db_port = 5432
			db_image = "postgres:latest"
		} else {
			return fmt.Errorf("unsupported database type: %s", dbConfig.Type)
		}

		// ConfigMap para las configuraciones de PostgreSQL
		configMapData := map[string]string{
			"POSTGRES_DB":       dbConfig.Name,
			"POSTGRES_USER":     dbConfig.User,
			"POSTGRES_PASSWORD": dbConfig.Password,
		}
		configMap := &corev1.ConfigMap{
			ObjectMeta: v1.ObjectMeta{
				Name:      configMapName,
				Namespace: namespace,
			},
			Data: configMapData,
		}

		// Actualiza o crea el ConfigMap
		if err := ensureConfigMap(clientset, namespace, configMap, configMapName); err != nil {
			return err
		}
	}
	fmt.Print("=====================================")
	fmt.Println("Pod created successfully:", configMapName)
	// Crear el pod
	pod := &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app": name, // Usando el nombre base como etiqueta para agrupación
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: "Never",
			Containers: []corev1.Container{
				{
					Name:  name,
					Image: image,
					Command: []string{
						"/bin/sh",
						"-c",
						"apk update && apk add rsync && apk add --no-cache bash && sleep infinity",
					},
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: port,
							Protocol:      "TCP",
							HostPort:      port,
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "code-volume",
							MountPath: "/opt/code",
						},
					},
				},
				// Contenedor de base de datos, agregado si conf.Database.Active es verdadero
				func() corev1.Container {
					if conf.Database.Active {
						return corev1.Container{
							Name:  "database",
							Image: db_image,
							EnvFrom: []corev1.EnvFromSource{
								{
									ConfigMapRef: &corev1.ConfigMapEnvSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: configMapName,
										},
									},
								},
							},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: int32(db_port),
									Protocol:      corev1.ProtocolTCP,
								},
							},
						}
					}
					return corev1.Container{} // Si conf.Database.Active es falso, no se agrega ningún contenedor de base de datos.
				}(),
				{
					Name:         "nginx",
					Image:        "nginx:latest",
					Ports:        []corev1.ContainerPort{{ContainerPort: 80, Protocol: "TCP"}},
					VolumeMounts: []corev1.VolumeMount{{Name: "nginx-config", MountPath: "/etc/nginx/nginx.conf", SubPath: "nginx.conf"}},
				},
			},
			Volumes: []corev1.Volume{
				{Name: "code-volume", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "nginx-config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "nginx-config"}}}},
			},
		},
	}

	_, err = clientset.CoreV1().Pods(namespace).Create(context.TODO(), pod, v1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create pod: %v", err)
	}
	fmt.Print("=====================================")
	fmt.Println("Pod created successfully:", name)

	// Crear el servicio
	service := &corev1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name:      serviceName,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": name}, // Selector basado en la etiqueta del pod
			Ports: []corev1.ServicePort{
				{
					Port:       80,
					TargetPort: intstr.FromInt(80),
					Protocol:   "TCP",
				},
			},
			Type: corev1.ServiceTypeClusterIP, // Ajusta según necesidad
		},
	}

	_, err = clientset.CoreV1().Services(namespace).Create(context.TODO(), service, v1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create service: %v", err)
	}
	fmt.Println("Service created successfully:", serviceName)

	return nil
}

func ensureConfigMap(clientset *kubernetes.Clientset, namespace string, configMap *corev1.ConfigMap, name string) error {
	existingConfigMap, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMap.Name, v1.GetOptions{})
	if err == nil {
		configMap.ResourceVersion = existingConfigMap.ResourceVersion
		_, err = clientset.CoreV1().ConfigMaps(namespace).Update(context.TODO(), configMap, v1.UpdateOptions{})
		return err
	} else if errors.IsNotFound(err) {
		_, err = clientset.CoreV1().ConfigMaps(namespace).Create(context.TODO(), configMap, v1.CreateOptions{})
		return err
	}
	return err
}

func deleteResourceIfExists(clientset *kubernetes.Clientset, resourceName string, namespace string) error {
	_, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), resourceName, v1.GetOptions{})
	if err == nil {
		return clientset.CoreV1().Pods(namespace).Delete(context.TODO(), resourceName, v1.DeleteOptions{})
	} else if errors.IsNotFound(err) {
		return nil
	}
	return err
}

// func DeployPodDatabase(clientset *kubernetes.Clientset, namespace, name string, dbConfig config.DatabaseConfig) error {
// 	podName := dbConfig.Name + "-pod"         // Nombre del pod
// 	serviceName := dbConfig.Name + "-service" // Nombre del servicio
// 	configMapName := "postgres-config"

// 	// ConfigMap para las configuraciones de PostgreSQL
// 	configMapData := map[string]string{
// 		"POSTGRES_DB":       dbConfig.Name,
// 		"POSTGRES_USER":     dbConfig.User,
// 		"POSTGRES_PASSWORD": dbConfig.Password,
// 	}
// 	configMap := &corev1.ConfigMap{
// 		ObjectMeta: v1.ObjectMeta{
// 			Name:      configMapName,
// 			Namespace: namespace,
// 		},
// 		Data: configMapData,
// 	}

// 	// Actualiza o crea el ConfigMap
// 	if err := ensureConfigMap(clientset, namespace, configMap); err != nil {
// 		return err
// 	}

// 	// Verificar si el pod ya existe
// 	_, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, v1.GetOptions{})
// 	if err == nil {
// 		// El pod ya existe, no es necesario crear uno nuevo
// 		log.Printf("El pod '%s' ya existe. No se creará un nuevo pod.\n", podName)
// 	} else if errors.IsNotFound(err) {
// 		// El pod no existe, crear uno nuevo
// 		if err := createPostgresPod(clientset, namespace, podName, configMapName); err != nil {
// 			return err
// 		}
// 	} else {
// 		// Se produjo un error al intentar obtener el pod existente
// 		return fmt.Errorf("error al verificar si el pod '%s' ya existe: %v", podName, err)
// 	}

// 	// Verificar si el servicio ya existe
// 	_, err = clientset.CoreV1().Services(namespace).Get(context.TODO(), serviceName, v1.GetOptions{})
// 	if err == nil {
// 		// El servicio ya existe, no es necesario crear uno nuevo
// 		log.Printf("El servicio '%s' ya existe. No se creará un nuevo servicio.\n", serviceName)
// 	} else if errors.IsNotFound(err) {
// 		// El servicio no existe, crear uno nuevo
// 		if err := createPostgresService(clientset, namespace, serviceName); err != nil {
// 			return err
// 		}
// 	} else {
// 		// Se produjo un error al intentar obtener el servicio existente
// 		return fmt.Errorf("error al verificar si el servicio '%s' ya existe: %v", serviceName, err)
// 	}

// 	return nil
// }

func createPostgresService(clientset *kubernetes.Clientset, namespace, serviceName string) error {
	service := &corev1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name:      serviceName,
			Namespace: namespace,
			Labels: map[string]string{
				"app": serviceName,
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": serviceName,
			},
			Ports: []corev1.ServicePort{
				{
					Port:       5432,
					TargetPort: intstr.FromInt(5432),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}

	_, err := clientset.CoreV1().Services(namespace).Create(context.TODO(), service, v1.CreateOptions{})
	return err
}

func createPostgresPod(clientset *kubernetes.Clientset, namespace, podName, configMapName string) error {
	pod := &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			Labels: map[string]string{
				"app": podName,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "postgres",
					Image: "postgres:latest",
					EnvFrom: []corev1.EnvFromSource{
						{
							ConfigMapRef: &corev1.ConfigMapEnvSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: configMapName,
								},
							},
						},
					},
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 5432,
							Protocol:      corev1.ProtocolTCP,
						},
					},
				},
			},
		},
	}

	_, err := clientset.CoreV1().Pods(namespace).Create(context.TODO(), pod, v1.CreateOptions{})
	return err
}

// func DeployPodDatabase(clientset *kubernetes.Clientset, namespace, name string, dbConfig config.DatabaseConfig) error {
// 	podName := dbConfig.Name
// 	serviceName := dbConfig.Name
// 	configMapName := "postgres-config"

// 	// ConfigMap para las configuraciones de PostgreSQL
// 	configMapData := map[string]string{
// 		"POSTGRES_DB":       dbConfig.Name,
// 		"POSTGRES_USER":     dbConfig.User,
// 		"POSTGRES_PASSWORD": dbConfig.Password,
// 	}
// 	configMap := &corev1.ConfigMap{
// 		ObjectMeta: v1.ObjectMeta{
// 			Name:      configMapName,
// 			Namespace: namespace,
// 		},
// 		Data: configMapData,
// 	}

// 	// Verificar y actualizar/crear ConfigMap
// 	existingConfigMap, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, v1.GetOptions{})
// 	if err == nil {
// 		configMap.ResourceVersion = existingConfigMap.ResourceVersion // Importante para actualizar
// 		if _, err := clientset.CoreV1().ConfigMaps(namespace).Update(context.TODO(), configMap, v1.UpdateOptions{}); err != nil {
// 			return fmt.Errorf("failed to update configmap: %v", err)
// 		}
// 	} else if errors.IsNotFound(err) {
// 		if _, err := clientset.CoreV1().ConfigMaps(namespace).Create(context.TODO(), configMap, v1.CreateOptions{}); err != nil {
// 			return fmt.Errorf("failed to create configmap: %v", err)
// 		}
// 	}

// 	// Definición del pod de PostgreSQL
// 	pod := &corev1.Pod{
// 		ObjectMeta: v1.ObjectMeta{
// 			Name:      podName,
// 			Namespace: namespace,
// 			Labels: map[string]string{
// 				"app":  name,
// 				"role": "database",
// 			},
// 		},
// 		Spec: corev1.PodSpec{
// 			Containers: []corev1.Container{
// 				{
// 					Name:  "postgres",
// 					Image: "postgres:latest",
// 					EnvFrom: []corev1.EnvFromSource{
// 						{
// 							ConfigMapRef: &corev1.ConfigMapEnvSource{
// 								LocalObjectReference: corev1.LocalObjectReference{
// 									Name: configMapName,
// 								},
// 							},
// 						},
// 					},
// 					Ports: []corev1.ContainerPort{
// 						{
// 							ContainerPort: 5432,
// 							Protocol:      "TCP",
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}

// 	// Manejo del pod existente
// 	if _, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, v1.GetOptions{}); err == nil {
// 		if err := clientset.CoreV1().Pods(namespace).Delete(context.TODO(), podName, v1.DeleteOptions{}); err != nil {
// 			return fmt.Errorf("failed to delete existing PostgreSQL pod: %v", err)
// 		}
// 	}
// 	if _, err := clientset.CoreV1().Pods(namespace).Create(context.TODO(), pod, v1.CreateOptions{}); err != nil {
// 		return fmt.Errorf("failed to create PostgreSQL pod: %v", err)
// 	}

// 	// Definición y manejo del servicio
// 	service := &corev1.Service{
// 		ObjectMeta: v1.ObjectMeta{
// 			Name:      serviceName,
// 			Namespace: namespace,
// 		},
// 		Spec: corev1.ServiceSpec{
// 			Selector: map[string]string{
// 				"app":  name,
// 				"role": "database",
// 			},
// 			Ports: []corev1.ServicePort{
// 				{
// 					Port:       5432,
// 					TargetPort: intstr.FromInt(5432),
// 					Protocol:   "TCP",
// 				},
// 			},
// 			Type: corev1.ServiceTypeClusterIP,
// 		},
// 	}

// 	// Manejo del servicio existente
// 	if _, err := clientset.CoreV1().Services(namespace).Get(context.TODO(), serviceName, v1.GetOptions{}); err == nil {
// 		if err := clientset.CoreV1().Services(namespace).Delete(context.TODO(), serviceName, v1.DeleteOptions{}); err != nil {
// 			return fmt.Errorf("failed to delete existing service for PostgreSQL: %v", err)
// 		}
// 	}
// 	if _, err := clientset.CoreV1().Services(namespace).Create(context.TODO(), service, v1.CreateOptions{}); err != nil {
// 		return fmt.Errorf("failed to create service for PostgreSQL: %v", err)
// 	}

// 	return nil
// }

func continuousSync(localPath string, remotePath string) {
	for {
		// Ejecutar rsync para sincronizar los archivos
		err := syncLocalToRemote(localPath, remotePath)
		if err != nil {
			log.Printf("Failed to sync: %v", err)
		}
		time.Sleep(1 * time.Minute) // Sincronizar cada minuto o el intervalo adecuado
	}
}

func syncLocalToRemote(localDir string, remoteDir string) error {
	// Ejecutar rsync como un proceso separado en segundo plano
	cmd := exec.Command("/usr/bin/rsync", "-avz", "--delete", localDir, remoteDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// func DeployPodWithVolume(clientset *kubernetes.Clientset, podName string, namespace string, imagePath string, localPath string) error {
// 	pod := &corev1.Pod{
// 		ObjectMeta: v1.ObjectMeta{
// 			Name: podName,
// 		},
// 		Spec: corev1.PodSpec{
// 			Containers: []corev1.Container{
// 				{
// 					Name:  "my-container",
// 					Image: imagePath,
// 					VolumeMounts: []corev1.VolumeMount{
// 						{
// 							Name:      "code-volume",
// 							MountPath: "/opt/code",
// 						},
// 					},
// 				},
// 			},
// 			Volumes: []corev1.Volume{
// 				{
// 					Name: "code-volume",
// 					VolumeSource: corev1.VolumeSource{
// 						HostPath: &corev1.HostPathVolumeSource{
// 							Path: localPath,
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}

// 	_, err := clientset.CoreV1().Pods(namespace).Create(context.TODO(), pod, v1.CreateOptions{})
// 	if err != nil {
// 		return fmt.Errorf("failed to deploy pod with volume: %v", err)
// 	}
// 	fmt.Println("Pod deployed successfully with volume.")
// 	return nil
// }

func checkPodReady(clientset *kubernetes.Clientset, podName, namespace string) bool {
	pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, v1.GetOptions{})
	if err != nil {
		log.Println("Error getting pod:", err)
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// This function will wait until the pod is ready
func WaitForPod(clientset *kubernetes.Clientset, podName, namespace string) {
	for !checkPodReady(clientset, podName, namespace) {
		fmt.Println("Waiting for pod to become ready...")
		time.Sleep(5 * time.Second)
	}
}

func StartPortForwarding(podName, namespace string, localPort, podPort int) error {
	cmd := exec.Command("kubectl", "port-forward", podName, fmt.Sprintf("%d:%d", localPort, podPort), "-n", namespace)
	return cmd.Start() // Use Start to run it in the background
}
