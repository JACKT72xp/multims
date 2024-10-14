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

// func SetupKubernetesConnection(kubeconfigPath, contextName string) {
// 	// Cargando el archivo kubeconfig y seleccionando un contexto específico
// 	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
// 		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
// 		&clientcmd.ConfigOverrides{CurrentContext: contextName},
// 	)

// 	config, err := loader.ClientConfig()
// 	if err != nil {
// 		log.Fatalf("Error building kubeconfig: %v", err)
// 	}

// 	clientset, err := kubernetes.NewForConfig(config)
// 	if err != nil {
// 		log.Fatalf("Error creating Kubernetes clientset: %v", err)
// 	}

// 	// Ejemplo de cómo listar los pods en el contexto seleccionado
// 	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), v1.ListOptions{})
// 	if err != nil {
// 		log.Fatalf("Error listing pods: %v", err)
// 	}

// 	fmt.Printf("Connected to context %s, %d pods found\n", contextName, len(pods.Items))
// }

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

// ExecIntoPod ejecuta un comando en un pod y maneja la salida.
func ExecIntoPod(clientset *kubernetes.Clientset, config *rest.Config, podName, namespace string, input string, directory string, languaje string, servicesKong []config.ServiceConfig) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigs // Espera a recibir una señal.
		fmt.Println("Signal received:", sig)
		fmt.Println("Termination or interrupt signal received, cleaning up...")
		cancel()                                      // Cancela el contexto completo
		deletePod(clientset, podName, namespace, nil) // Eliminar el pod
		os.Exit(0)                                    // Salir del programa completamente
	}()
	//lastCommand := "sleep 30 && tail -f /dev/null"

	lastCommand := ""

	switch languaje {
	case "Node":
		lastCommand = fmt.Sprintf("sleep 10 && cd /home/%s && rm -rf package-lock.json && rm -rf node_modules/ && npm i nodemon -g && npm install --save && %s ", directory, input)

	case "Node-Typescript":
		lastCommand = fmt.Sprintf("sleep 10 && cd /home/%s && rm -rf package-lock.json && rm -rf node_modules/ && npm i nodemon -g && npm install --save && %s ", directory, input)

	case "Python":
		lastCommand = fmt.Sprintf("sleep 10 && cd /home/%s && pip install -r requirements.txt && %s ", directory, input)
	}
	// lastCommand := fmt.Sprintf("sleep 60 && cd /home/%s && rm -rf package-lock.json && rm -rf node_modules/ && npm i nodemon -g && npm install --save && %s ", directory, input)
	fmt.Println("Commands to apply", lastCommand)
	//command := []string{"/bin/sh", "-c", "sleep 30 && cd /home/cmi-ms-users-sims-01 && rm -rf package-lock.json && rm -rf node_modules/ && npm install --save && npm run start:dev"}
	command := []string{
		"/bin/sh", "-c",
		lastCommand,
	}
	req := clientset.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command: command,
			Stdin:   true,
			Stdout:  true,
			Stderr:  true,
			TTY:     true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		deletePod(clientset, podName, namespace, nil) // Eliminar el pod
		return fmt.Errorf("error creating SPDY executor: %v", err)
	}

	streamOptions := remotecommand.StreamOptions{
		Stdin:  os.Stdin,
		Stdout: &ANSIWriter{writer: os.Stdout},
		Stderr: &ANSIWriter{writer: os.Stderr},
		Tty:    true,
	}

	if err := executor.StreamWithContext(ctx, streamOptions); err != nil {
		deleteResources(clientset, podName, namespace, servicesKong) // Eliminar el pod

		fmt.Printf("Error in streaming: %v\n", err)
		return err
	}

	fmt.Fprint(os.Stdout, "\033c") // Restablecer el estado del TTY
	return nil
}

func deleteResources(clientset *kubernetes.Clientset, podName, namespace string, services []config.ServiceConfig) {
	fmt.Printf("Deleting pod %s in namespace %s...\n", podName, namespace)

	// Opciones de eliminación para los recursos
	deletePolicy := v1.DeletePropagationForeground
	deleteOptions := &v1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	}

	// Elimina el pod
	if err := clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, *deleteOptions); err != nil {
		fmt.Printf("Failed to delete pod: %v\n", err)
	} else {
		fmt.Println("Pod deletion initiated successfully.")
		// Implementar waitForPodDeletion si es necesario
	}
	for _, pod := range services {
		// Ajustar el nombre del servicio si es necesario
		podName := pod.Name + "-pod"
		fmt.Printf("Deleting pods %s in namespace %s...\n", podName, namespace)
		if err := clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, *deleteOptions); err != nil {
			fmt.Printf("Failed to delete pod: %v\n", err)
		} else {
			fmt.Printf("Pod deletion initiated successfully: %s\n", podName)
		}
	}

	// Eliminar todos los servicios asociados listados en services
	for _, service := range services {
		// Ajustar el nombre del servicio si es necesario
		serviceName := service.Name
		fmt.Printf("Deleting service %s in namespace %s...\n", serviceName, namespace)
		if err := clientset.CoreV1().Services(namespace).Delete(context.Background(), serviceName, *deleteOptions); err != nil {
			fmt.Printf("Failed to delete service: %v\n", err)
		} else {
			fmt.Printf("Service deletion initiated successfully: %s\n", serviceName)
		}
	}

	// Eliminar específicamente kong-admin y kong-proxy
	specialServices := []string{"kong-admin", "kong-proxy"}
	for _, s := range specialServices {
		fmt.Printf("Deleting service %s in namespace %s...\n", s, namespace)
		if err := clientset.CoreV1().Services(namespace).Delete(context.Background(), s, *deleteOptions); err != nil {
			fmt.Printf("Failed to delete special service %s: %v\n", s, err)
		} else {
			fmt.Printf("Special service deletion initiated successfully: %s\n", s)
		}
	}
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

// 	return nil
// }

func DeployPod(clientset *kubernetes.Clientset, name string, namespace string, image string, uid string, port int32) error {
	podName := fmt.Sprintf("%s", name)
	serviceName := fmt.Sprintf("service-%s", name)

	// Verificar si el pod ya existe
	_, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, v1.GetOptions{})
	if err == nil {
		fmt.Println("Pod already exists:", podName)
	} else {
		// Si el pod no existe, crea uno nuevo
		pod := &corev1.Pod{
			ObjectMeta: v1.ObjectMeta{
				Name:      podName,
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
				},
				Volumes: []corev1.Volume{
					{
						Name: "code-volume",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
				},
			},
		}

		_, err = clientset.CoreV1().Pods(namespace).Create(context.TODO(), pod, v1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create pod: %v", err)
		}
		fmt.Println("Pod created successfully:", podName)
	}

	// Verificar si el servicio ya existe
	_, err = clientset.CoreV1().Services(namespace).Get(context.TODO(), serviceName, v1.GetOptions{})
	if err == nil {
		fmt.Println("Service already exists:", serviceName)
		return nil
	}

	// Si el servicio no existe, crea uno nuevo
	service := &corev1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name:      serviceName,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": name, // Selector basado en la etiqueta del pod
			},
			Ports: []corev1.ServicePort{
				{
					Port:       port,
					TargetPort: intstr.FromInt32(port),
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
	cmd := exec.Command("rsync", "-avz", "--delete", localDir, remoteDir)
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
