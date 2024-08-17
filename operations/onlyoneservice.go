package operations

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	kong "multims/pkg/build"
	"multims/pkg/client"
	"multims/pkg/config"
	"multims/pkg/container"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// Función para generar el YAML del PVC
// func generatePVCYAML(namespace, uid string) string {
// 	return fmt.Sprintf(`
// apiVersion: v1
// kind: PersistentVolumeClaim
// metadata:
//   name: pvc-%s
//   namespace: %s
// spec:
//   accessModes:
//     - ReadWriteOnce
//   resources:
//     requests:
//       storage: 2Gi
//   storageClassName: openebs-standard
// `, uid, namespace)
// }

// func generatePodYAMLWithInteractiveCommand(conf *config.Config) string {
// 	image := conf.Registry.Image
// 	uid := conf.UID

// 	podYAML := fmt.Sprintf(`
// apiVersion: v1
// kind: Pod
// metadata:
//   name: pod-%s
//   namespace: %s
//   labels:
//     app: pod-%s
// spec:
//   restartPolicy: Never
//   terminationGracePeriodSeconds: 30
//   containers:
//   - name: %s
//     image: %s
//     ports:
//     - containerPort: %d
//     - containerPort: 6060 # Exponer puerto para msync
//     stdin: true
//     tty: true
//     volumeMounts:
//     - mountPath: /mnt/data
//       name: data-storage
//   volumes:
//   - name: data-storage
//     persistentVolumeClaim:
//       claimName: pvc-%s
// `, uid, conf.Namespace, uid, conf.AppName, image, conf.Application.Port, uid)

// 	return podYAML
// }

// // Función para crear un recurso en Kubernetes
// func createResource(resourceYAML string) error {
// 	// Utilizar la API de Kubernetes para aplicar el YAML
// 	cmd := exec.Command("kubectl", "apply", "-f", "-")
// 	cmd.Stdin = strings.NewReader(resourceYAML)
// 	output, err := cmd.CombinedOutput()
// 	if err != nil {
// 		log.Printf("Failed to apply resource: %s\nError: %v", string(output), err)
// 		return err
// 	}
// 	log.Printf("Successfully applied resource: %s\nOutput: %s", resourceYAML, string(output))
// 	return nil
// }

// prepareKubernetesClient configura el cliente de Kubernetes usando el contexto especificado
func prepareKubernetesClient(kubeConfigPath, contextName string) (*kubernetes.Clientset, error) {
	// Cargar la configuración del kubeconfig
	config, err := clientcmd.LoadFromFile(kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	// Configurar el contexto correcto
	config.CurrentContext = contextName
	clientConfig := clientcmd.NewDefaultClientConfig(*config, &clientcmd.ConfigOverrides{
		Context: clientcmdapi.Context{
			Namespace: config.Contexts[contextName].Namespace,
		},
	})
	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create client config: %w", err)
	}

	// Crear el cliente de Kubernetes
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	return clientset, nil
}

func WaitForPod(clientset *kubernetes.Clientset, podName, namespace string) error {
	for {
		pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if pod.Status.Phase == "Running" {
			fmt.Println("Pod is running")
			return nil
		}
		time.Sleep(2 * time.Second)
	}
}

// Función para verificar si un recurso existe
// Función para verificar si un recurso existe
// func resourceExists(clientset *kubernetes.Clientset, resourceType, resourceName, namespace string) bool {
// 	switch resourceType {
// 	case "pvc":
// 		_, err := clientset.CoreV1().PersistentVolumeClaims(namespace).Get(context.TODO(), resourceName, metav1.GetOptions{})
// 		return err == nil
// 	case "pod":
// 		_, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), resourceName, metav1.GetOptions{})
// 		return err == nil
// 	case "svc":
// 		_, err := clientset.CoreV1().Services(namespace).Get(context.TODO(), resourceName, metav1.GetOptions{})
// 		return err == nil
// 	default:
// 		return false
// 	}
// }

// Función para generar el YAML del servicio con dos puertos
func generateServiceYAML(namespace, uid string, appPort, msyncPort int) string {
	return fmt.Sprintf(`
apiVersion: v1
kind: Service
metadata:
  name: svc-%s
  namespace: %s
spec:
  selector:
    app: pod-%s  # Este selector debe coincidir con la etiqueta en el Pod YAML
  ports:
  - name: app-port
    protocol: TCP
    port: %d
    targetPort: %d
  - name: msync-port
    protocol: TCP
    port: 6060
    targetPort: 6060
`, uid, namespace, uid, appPort, appPort)
}

// func deleteResource(clientset *kubernetes.Clientset, resourceType, resourceName, namespace string) error {
// 	var err error
// 	switch resourceType {
// 	case "pvc":
// 		err = clientset.CoreV1().PersistentVolumeClaims(namespace).Delete(context.Background(), resourceName, metav1.DeleteOptions{})
// 	case "pod":
// 		err = clientset.CoreV1().Pods(namespace).Delete(context.Background(), resourceName, metav1.DeleteOptions{})
// 	}
// 	return err
// }

// func ensurePortForwarding(ctx context.Context, namespace, svcName string, appPort, msyncPort int) {
// 	// Configuración del port-forward para el puerto de la aplicación
// 	appCmd := exec.CommandContext(ctx, "kubectl", "port-forward", fmt.Sprintf("svc/%s", svcName), fmt.Sprintf("%d:%d", appPort, appPort), "-n", namespace)
// 	appCmd.Stdout = os.Stdout
// 	appCmd.Stderr = os.Stderr

// 	if err := appCmd.Start(); err != nil {
// 		log.Fatalf("Failed to start port-forwarding for app: %v", err)
// 	}

// 	// Configuración del port-forward para el puerto de msync
// 	msyncCmd := exec.CommandContext(ctx, "kubectl", "port-forward", fmt.Sprintf("svc/%s", svcName), fmt.Sprintf("%d:%d", msyncPort, msyncPort), "-n", namespace)
// 	msyncCmd.Stdout = os.Stdout
// 	msyncCmd.Stderr = os.Stderr

// 	if err := msyncCmd.Start(); err != nil {
// 		log.Fatalf("Failed to start port-forwarding for msync: %v", err)
// 	}

// 	go func() {
// 		<-ctx.Done()
// 		if err := appCmd.Process.Kill(); err != nil {
// 			log.Fatalf("Failed to kill app port-forwarding process: %v", err)
// 		}
// 		if err := msyncCmd.Process.Kill(); err != nil {
// 			log.Fatalf("Failed to kill msync port-forwarding process: %v", err)
// 		}
// 	}()
// }

func waitForPodReady(clientset *kubernetes.Clientset, podName, namespace string, timeoutSeconds int) error {
	watch, err := clientset.CoreV1().Pods(namespace).Watch(context.TODO(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("metadata.name=%s", podName),
	})
	if err != nil {
		return err
	}
	defer watch.Stop()

	timer := time.NewTimer(time.Duration(timeoutSeconds) * time.Second)
	defer timer.Stop()

	for {
		select {
		case event := <-watch.ResultChan():
			pod, ok := event.Object.(*corev1.Pod)
			if !ok {
				continue
			}
			if pod.Status.Phase == corev1.PodRunning {
				for _, condition := range pod.Status.Conditions {
					if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
						return nil
					}
				}
			}
		case <-timer.C:
			return fmt.Errorf("timed out waiting for pod to be ready")
		}
	}
}

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
	multiservices := conf.Multiservices

	fmt.Println("KubeConfig Path:", kubeConfigPath)
	fmt.Println("Context Name:", contextName)
	fmt.Println("Namespace:", namespace)
	fmt.Println("Multiservices:", multiservices)

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
}

// switchKubeContext cambia el contexto de Kubernetes
func switchKubeContext(kubeConfigPath, contextName string) error {
	cmd := exec.Command("kubectl", "config", "use-context", contextName, "--kubeconfig", kubeConfigPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func isPortListening(namespace, podName string, port int) bool {
	cmd := exec.Command("kubectl", "exec", podName, "-n", namespace, "--", "netstat", "-tuln")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to execute command to check port listening: %v", err)
		return false
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, fmt.Sprintf(":%d", port)) {
			return true
		}
	}
	return false
}

func createPersistentVolumeClaim(clientset *kubernetes.Clientset, namespace, pvcName string) error {
	storageClassName := "openebs-standard"

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pvcName,
			Namespace: namespace,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("5Gi"),
				},
			},
			StorageClassName: &storageClassName,
		},
	}

	_, err := clientset.CoreV1().PersistentVolumeClaims(namespace).Create(context.TODO(), pvc, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create PersistentVolumeClaim: %w", err)
	}
	return nil
}

func createConfigMap(clientset *kubernetes.Clientset, namespace string, name string) error {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string]string{
			"nginx.conf": `
events { }

http {
    server {
        listen 3000;

        location / {
            proxy_pass http://127.0.0.1:3001;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }

    server {
        listen 6065;

        location / {
            proxy_pass http://127.0.0.1:6067;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}

stream {
    server {
        listen 6060;

        proxy_pass 127.0.0.1:6062;
    }
}`,
		},
	}

	_, err := clientset.CoreV1().ConfigMaps(namespace).Create(context.TODO(), configMap, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ConfigMap: %w", err)
	}
	return nil
}

func createPod(clientset *kubernetes.Clientset, namespace, podName, pvcName, image, configmap string) error {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			Labels: map[string]string{
				"app": podName,
			},
		},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "data-storage",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: pvcName,
						},
					},
				},
				{
					Name: "nginx-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: configmap,
							},
						},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:  "nginx-proxy",
					Image: "nginx:alpine",
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 3000,
						},
						{
							ContainerPort: 6060,
						},
						{
							ContainerPort: 6065, // Adding HTTP port to the proxy
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "nginx-config",
							MountPath: "/etc/nginx/nginx.conf",
							SubPath:   "nginx.conf",
						},
						{
							Name:      "data-storage",
							MountPath: "/mnt/data",
						},
					},
					Command: []string{"nginx", "-g", "daemon off;"},
				},
				{
					Name:  "application-container",
					Image: image,
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 3001,
						},
						{
							ContainerPort: 6067, // Adding port for the application container
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "data-storage",
							MountPath: "/mnt/data",
						},
					},
					Stdin:   true,
					TTY:     true,
					Command: []string{"/bin/bash"},
					Args:    []string{"-c", "tail -f /dev/null"},
				},
				{
					Name:  "msync-container",
					Image: "jackt72xp/multims:initv22",
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 6062, // TCP for msync
						},
						{
							ContainerPort: 6065, // HTTP for msync
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "data-storage",
							MountPath: "/mnt/data",
						},
					},
					Command: []string{"/usr/local/bin/msync"},
					Args:    []string{"-mode=serverHttp", "-port=6067", "-directory=/mnt/data"},
				},
			},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}

	_, err := clientset.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Pod: %w", err)
	}
	return nil
}

func portForwardPod(clientset *kubernetes.Clientset, namespace, podName string, localPort, remotePort int, stopCh chan struct{}) error {
	kubeconfigPath := filepath.Join(homedir.HomeDir(), ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return fmt.Errorf("failed to build kubeconfig: %w", err)
	}

	transport, upgrader, err := spdy.RoundTripperFor(config)
	if err != nil {
		return fmt.Errorf("failed to create roundTripper: %w", err)
	}

	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(namespace).
		Name(podName).
		SubResource("portforward")

	portForwarder, err := portforward.New(
		spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", req.URL()),
		[]string{fmt.Sprintf("%d:%d", localPort, remotePort)},
		stopCh,
		make(chan struct{}), // readyCh is not used to avoid unnecessary checks
		os.Stdout,
		os.Stderr,
	)
	if err != nil {
		return fmt.Errorf("failed to create port forwarder: %w", err)
	}

	// Iniciar el port forwarding en una goroutine separada
	go func() {
		log.Printf("Starting port forwarding on %d:%d...\n", localPort, remotePort)
		if err := portForwarder.ForwardPorts(); err != nil {
			log.Printf("Port forwarding error on %d:%d: %v", localPort, remotePort, err)
		}
	}()

	return nil
}

// func portForwardPod(clientset *kubernetes.Clientset, namespace, podName string, localPort, remotePort int, stopCh chan struct{}) error {
// 	kubeconfigPath := filepath.Join(homedir.HomeDir(), ".kube", "config")
// 	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to build kubeconfig: %w", err)
// 	}

// 	transport, upgrader, err := spdy.RoundTripperFor(config)
// 	if err != nil {
// 		return fmt.Errorf("failed to create roundTripper: %w", err)
// 	}

// 	req := clientset.CoreV1().RESTClient().Post().
// 		Resource("pods").
// 		Namespace(namespace).
// 		Name(podName).
// 		SubResource("portforward")

// 	for {
// 		newStopCh := make(chan struct{})
// 		readyCh := make(chan struct{})
// 		out := new(bytes.Buffer)
// 		errOut := new(bytes.Buffer)

// 		portForwarder, err := portforward.New(
// 			spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", req.URL()),
// 			[]string{fmt.Sprintf("%d:%d", localPort, remotePort)},
// 			newStopCh,
// 			readyCh,
// 			out,
// 			errOut,
// 		)
// 		if err != nil {
// 			return fmt.Errorf("failed to create port forwarder: %w", err)
// 		}

// 		// Iniciar el port forwarding en una goroutine separada
// 		go func() {
// 			log.Printf("Starting port forwarding on %d:%d...\n", localPort, remotePort)
// 			if err := portForwarder.ForwardPorts(); err != nil {
// 				log.Printf("Error in port forwarding on %d:%d: %v", localPort, remotePort, err)
// 			}

// 			log.Printf("Port forwarding on %d:%d lost connection. Retrying in 5 seconds...\n", localPort, remotePort)
// 			close(newStopCh) // Asegurar que el canal stopCh se cierre al finalizar la goroutine
// 			time.Sleep(5 * time.Second)
// 		}()

// 		select {
// 		case <-readyCh:
// 			log.Printf("Port forwarding is ready for pod %s on %d:%d\n", podName, localPort, remotePort)
// 			<-newStopCh // Esperar hasta que se cierre el canal stopCh en caso de error o reconexión
// 		case <-time.After(10 * time.Second):
// 			log.Printf("Port forwarding to pod %s on %d:%d timed out\n", podName, localPort, remotePort)
// 			close(newStopCh)
// 			return fmt.Errorf("port forwarding to pod %s on %d:%d timed out", podName, localPort, remotePort)
// 		}
// 	}
// }

// Función para cerrar un canal de manera segura
// func closeChannel(ch chan struct{}) {
// 	select {
// 	case <-ch:
// 		// El canal ya está cerrado, no hacer nada
// 	default:
// 		close(ch)
// 	}
// }

func waitForPVCDeletion(clientset *kubernetes.Clientset, namespace, pvcName string) error {
	for {
		_, err := clientset.CoreV1().PersistentVolumeClaims(namespace).Get(context.TODO(), pvcName, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			// PVC no existe, podemos proceder
			return nil
		} else if err != nil {
			// Otro error inesperado
			return fmt.Errorf("error checking PVC existence: %w", err)
		}
		// Si el PVC aún existe, esperar y volver a intentar
		time.Sleep(2 * time.Second)
	}
}

func createService(clientset *kubernetes.Clientset, namespace, svcName string, appPort, msyncPort int) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": svcName,
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "app-port",
					Protocol:   corev1.ProtocolTCP,
					Port:       int32(appPort),
					TargetPort: intstr.FromInt(3001),
				},
				{
					Name:       "msync-port",
					Protocol:   corev1.ProtocolTCP,
					Port:       int32(msyncPort),
					TargetPort: intstr.FromInt(6062),
				},
			},
		},
	}

	_, err := clientset.CoreV1().Services(namespace).Create(context.TODO(), svc, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Service: %w", err)
	}
	return nil
}

func resourceExists(err error) bool {
	return !errors.IsNotFound(err) && err == nil
}

func askForRecreate(resourceType, resourceName string) bool {
	var input string
	fmt.Printf("%s %s already exists. Do you want to recreate it? [y/N]: ", resourceType, resourceName)
	fmt.Scanln(&input)
	return input == "y" || input == "Y"
}

func execIntoPod(namespace, podName, containerName string) error {
	// Construir el comando kubectl exec
	cmd := exec.Command("kubectl", "exec", "-n", namespace, "-it", podName, "-c", containerName, "--", "/bin/bash")

	// Redirigir la entrada, salida y errores del proceso al de la terminal actual
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Ejecutar el comando
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to exec into pod: %w", err)
	}

	return nil
}

func retryPortForward(clientset *kubernetes.Clientset, namespace, podName string, localPort, remotePort int, maxRetries int, stopCh chan struct{}) {
	for retries := 0; retries < maxRetries; retries++ {
		stopCh := make(chan struct{}) // Crear un nuevo canal para cada intento
		readyCh := make(chan struct{})

		go func() {
			if err := portForwardPod(clientset, namespace, podName, localPort, remotePort, stopCh); err != nil {
				log.Printf("Error in port forwarding on %d:%d: %v", localPort, remotePort, err)
			}
		}()

		select {
		case <-readyCh:
			log.Printf("Port forwarding on %d:%d started successfully.", localPort, remotePort)
			return
		case <-time.After(5 * time.Second):
			log.Printf("Port forwarding on %d:%d timed out, retrying...", localPort, remotePort)
			close(stopCh) // Cerrar el canal para detener el port forwarding fallido
		}
	}

	log.Fatalf("Failed to start port forwarding on %d:%d after %d retries.", localPort, remotePort, maxRetries)
}

// Evitar que la goroutine interfiera con la ejecución principal de la CLI
// func startPortForwarding(clientset *kubernetes.Clientset, namespace, podName string, localPort, remotePort int, stopCh chan struct{}) {
// 	go func() {
// 		if err := portForwardPod(clientset, namespace, podName, localPort, remotePort, stopCh); err != nil {
// 			log.Printf("Error in port forwarding: %v", err)
// 		}
// 	}()
// }

// func OnlyOneServiceHandlerV2() {
// 	// Obtener la configuración y preparar el entorno
// 	baseDir, err := os.Getwd()
// 	if err != nil {
// 		log.Fatalf("Failed to get working directory: %v", err)
// 	}

// 	configPath := filepath.Join(baseDir, "multims.yml")
// 	conf, err := config.LoadConfigFromFile(configPath)
// 	if err != nil {
// 		log.Fatalf("Failed to load config: %v", err)
// 	}

// 	kubeConfigPath := conf.KubeConfigPath
// 	if conf.UseDefaultKubeConfig {
// 		kubeConfigPath = filepath.Join(homedir.HomeDir(), ".kube", "config")
// 	}
// 	contextName := conf.KubernetesContext
// 	namespace := conf.Namespace
// 	uid := conf.UID
// 	appPort := conf.Application.Port
// 	msyncPort := 6060
// 	image := conf.Registry.Image

// 	clientset, err := prepareKubernetesClient(kubeConfigPath, contextName)
// 	if err != nil {
// 		log.Fatalf("Failed to prepare Kubernetes client: %v", err)
// 	}

// 	log.Printf("Using context: %s", contextName)
// 	log.Printf("Namespace: %s", namespace)
// 	log.Printf("KubeConfigPath: %s", kubeConfigPath)

// 	// Cambiar el contexto explícitamente
// 	err = switchKubeContext(kubeConfigPath, contextName)
// 	if err != nil {
// 		log.Fatalf("Failed to switch context: %v", err)
// 	}

// 	podName := fmt.Sprintf("pod-%s", uid)
// 	pvcName := fmt.Sprintf("pvc-%s", uid)
// 	svcName := fmt.Sprintf("svc-%s", uid)
// 	cfmName := fmt.Sprintf("svc-%s", uid)

// 	// Verificar y crear PVC
// 	_, err = clientset.CoreV1().PersistentVolumeClaims(namespace).Get(context.TODO(), pvcName, metav1.GetOptions{})
// 	if resourceExists(err) {
// 		if askForRecreate("PersistentVolumeClaim", pvcName) {
// 			clientset.CoreV1().PersistentVolumeClaims(namespace).Delete(context.TODO(), pvcName, metav1.DeleteOptions{})
// 			if err := waitForPVCDeletion(clientset, namespace, pvcName); err != nil {
// 				log.Fatalf("Error waiting for PVC deletion: %v", err)
// 			}
// 			if err := createPersistentVolumeClaim(clientset, namespace, pvcName); err != nil {
// 				log.Fatalf("Failed to create PVC: %v", err)
// 			}
// 		}
// 	} else if errors.IsNotFound(err) {
// 		if err := createPersistentVolumeClaim(clientset, namespace, pvcName); err != nil {
// 			log.Fatalf("Failed to create PVC: %v", err)
// 		}
// 	} else {
// 		log.Fatalf("Error checking PVC existence: %v", err)
// 	}

// 	// Verificar y crear ConfigMap
// 	_, err = clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), cfmName, metav1.GetOptions{})
// 	if resourceExists(err) {
// 		if askForRecreate("ConfigMap", cfmName) {
// 			clientset.CoreV1().ConfigMaps(namespace).Delete(context.TODO(), cfmName, metav1.DeleteOptions{})
// 			if err := createConfigMap(clientset, namespace, cfmName); err != nil {
// 				log.Fatalf("Failed to create ConfigMap: %v", err)
// 			}
// 		}
// 	} else if errors.IsNotFound(err) {
// 		if err := createConfigMap(clientset, namespace, cfmName); err != nil {
// 			log.Fatalf("Failed to create ConfigMap: %v", err)
// 		}
// 	} else {
// 		log.Fatalf("Error checking ConfigMap existence: %v", err)
// 	}

// 	// Verificar y crear Pod
// 	_, err = clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
// 	if resourceExists(err) {
// 		if askForRecreate("Pod", podName) {
// 			clientset.CoreV1().Pods(namespace).Delete(context.TODO(), podName, metav1.DeleteOptions{})
// 			if err := createPod(clientset, namespace, podName, pvcName, image, cfmName); err != nil {
// 				log.Fatalf("Failed to create Pod: %v", err)
// 			}
// 		}
// 	} else if errors.IsNotFound(err) {
// 		if err := createPod(clientset, namespace, podName, pvcName, image, cfmName); err != nil {
// 			log.Fatalf("Failed to create Pod: %v", err)
// 		}
// 	} else {
// 		log.Fatalf("Error checking Pod existence: %v", err)
// 	}

// 	// Verificar y crear Service
// 	_, err = clientset.CoreV1().Services(namespace).Get(context.TODO(), svcName, metav1.GetOptions{})
// 	if resourceExists(err) {
// 		if askForRecreate("Service", svcName) {
// 			clientset.CoreV1().Services(namespace).Delete(context.TODO(), svcName, metav1.DeleteOptions{})
// 			if err := createService(clientset, namespace, svcName, appPort, msyncPort); err != nil {
// 				log.Fatalf("Failed to create Service: %v", err)
// 			}
// 		}
// 	} else if errors.IsNotFound(err) {
// 		if err := createService(clientset, namespace, svcName, appPort, msyncPort); err != nil {
// 			log.Fatalf("Failed to create Service: %v", err)
// 		}
// 	} else {
// 		log.Fatalf("Error checking Service existence: %v", err)
// 	}
// 	// Esperar a que el pod esté listo
// 	fmt.Printf("Waiting for Pod %s to be ready...\n", podName)
// 	if err := waitForPodReady(clientset, podName, namespace, 120); err != nil {
// 		log.Fatalf("Error waiting for Pod to be ready: %v", err)
// 	}
// 	fmt.Println("Pod is ready.")

// 	stopCh1 := make(chan struct{})
// 	stopCh2 := make(chan struct{})
// 	portForwardReadyCh := make(chan bool, 2)

// 	// Iniciar el port forwarding para el appPort
// 	go func() {
// 		log.Println("Starting port forwarding for appPort...")
// 		if err := portForwardPod(clientset, namespace, podName, appPort, appPort, stopCh1); err != nil {
// 			log.Fatalf("Failed to start port forwarding for app port: %v", err)
// 		}
// 		log.Println("Port forwarding for appPort is ready.")
// 		portForwardReadyCh <- true
// 	}()

// 	// Iniciar el port forwarding para el msyncPort
// 	go func() {
// 		log.Println("Starting port forwarding for msyncPort...")
// 		if err := portForwardPod(clientset, namespace, podName, msyncPort, msyncPort, stopCh2); err != nil {
// 			log.Fatalf("Failed to start port forwarding for msync port: %v", err)
// 		}
// 		log.Println("Port forwarding for msyncPort is ready.")
// 		portForwardReadyCh <- true
// 	}()

// 	// Esperar a que ambos port forwards estén listos antes de continuar
// 	log.Println("Waiting for both port forwards to be ready...")

// 	// Timeout en caso de que los port forwards no estén listos en 30 segundos
// 	timeout := time.After(30 * time.Second)

// 	// Esperar a que los dos port forwards estén listos
// 	for i := 0; i < 2; i++ {
// 		select {
// 		case <-portForwardReadyCh:
// 			// Uno de los port forwards está listo
// 		case <-timeout:
// 			log.Fatal("Timeout waiting for port forwards to be ready")
// 		}
// 	}

// 	log.Println("Both port forwards are ready.")

// 	// Sincronización inicial
// 	log.Println("Iniciando sincronización inicial con reintentos...")
// 	// Aquí ejecutarías la función de sincronización
// 	// Por ejemplo: syncWithRetries(...)
// 	log.Println("Sincronización inicial completa.")

// 	// Ejecutar kubectl exec para entrar en el contenedor del pod
// 	containerName := "application-container"
// 	if err := execIntoPod(namespace, podName, containerName); err != nil {
// 		log.Fatalf("Failed to exec into pod: %v", err)
// 	}

// 	// Mantener el programa en ejecución para que la sincronización siga activa
// 	select {}
// }

// func OnlyOneServiceHandlerV2() {
// 	baseDir, err := os.Getwd()
// 	if err != nil {
// 		log.Fatalf("Failed to get working directory: %v", err)
// 	}

// 	configPath := filepath.Join(baseDir, "multims.yml")
// 	conf, err := config.LoadConfigFromFile(configPath)
// 	if err != nil {
// 		log.Fatalf("Failed to load config: %v", err)
// 	}

// 	kubeConfigPath := conf.KubeConfigPath
// 	if conf.UseDefaultKubeConfig {
// 		kubeConfigPath = filepath.Join(homedir.HomeDir(), ".kube", "config")
// 	}
// 	contextName := conf.KubernetesContext
// 	namespace := conf.Namespace
// 	uid := conf.UID
// 	appPort := conf.Application.Port
// 	msyncPort := 6060
// 	image := conf.Registry.Image

// 	clientset, err := prepareKubernetesClient(kubeConfigPath, contextName)
// 	if err != nil {
// 		log.Fatalf("Failed to prepare Kubernetes client: %v", err)
// 	}

// 	log.Printf("Using context: %s", contextName)
// 	log.Printf("Namespace: %s", namespace)
// 	log.Printf("KubeConfigPath: %s", kubeConfigPath)

// 	// Cambiar el contexto explícitamente
// 	err = switchKubeContext(kubeConfigPath, contextName)
// 	if err != nil {
// 		log.Fatalf("Failed to switch context: %v", err)
// 	}

// 	podName := fmt.Sprintf("pod-%s", uid)
// 	pvcName := fmt.Sprintf("pvc-%s", uid)
// 	svcName := fmt.Sprintf("svc-%s", uid)
// 	cfmName := fmt.Sprintf("svc-%s", uid)

// 	// Verificar y crear PVC (entrada de usuario antes de iniciar goroutines)
// 	_, err = clientset.CoreV1().PersistentVolumeClaims(namespace).Get(context.TODO(), pvcName, metav1.GetOptions{})
// 	if resourceExists(err) {
// 		if askForRecreate("PersistentVolumeClaim", pvcName) {
// 			clientset.CoreV1().PersistentVolumeClaims(namespace).Delete(context.TODO(), pvcName, metav1.DeleteOptions{})
// 			if err := waitForPVCDeletion(clientset, namespace, pvcName); err != nil {
// 				log.Fatalf("Error waiting for PVC deletion: %v", err)
// 			}
// 			if err := createPersistentVolumeClaim(clientset, namespace, pvcName); err != nil {
// 				log.Fatalf("Failed to create PVC: %v", err)
// 			}
// 		}
// 	} else if errors.IsNotFound(err) {
// 		if err := createPersistentVolumeClaim(clientset, namespace, pvcName); err != nil {
// 			log.Fatalf("Failed to create PVC: %v", err)
// 		}
// 	} else {
// 		log.Fatalf("Error checking PVC existence: %v", err)
// 	}

// 	// Verificar y crear ConfigMap
// 	_, err = clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), cfmName, metav1.GetOptions{})
// 	if resourceExists(err) {
// 		if askForRecreate("ConfigMap", cfmName) {
// 			clientset.CoreV1().ConfigMaps(namespace).Delete(context.TODO(), cfmName, metav1.DeleteOptions{})
// 			if err := createConfigMap(clientset, namespace, cfmName); err != nil {
// 				log.Fatalf("Failed to create ConfigMap: %v", err)
// 			}
// 		}
// 	} else if errors.IsNotFound(err) {
// 		if err := createConfigMap(clientset, namespace, cfmName); err != nil {
// 			log.Fatalf("Failed to create ConfigMap: %v", err)
// 		}
// 	} else {
// 		log.Fatalf("Error checking ConfigMap existence: %v", err)
// 	}

// 	// Verificar y crear Pod
// 	_, err = clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
// 	if resourceExists(err) {
// 		if askForRecreate("Pod", podName) {
// 			clientset.CoreV1().Pods(namespace).Delete(context.TODO(), podName, metav1.DeleteOptions{})
// 			if err := createPod(clientset, namespace, podName, pvcName, image, cfmName); err != nil {
// 				log.Fatalf("Failed to create Pod: %v", err)
// 			}
// 		}
// 	} else if errors.IsNotFound(err) {
// 		if err := createPod(clientset, namespace, podName, pvcName, image, cfmName); err != nil {
// 			log.Fatalf("Failed to create Pod: %v", err)
// 		}
// 	} else {
// 		log.Fatalf("Error checking Pod existence: %v", err)
// 	}

// 	// Verificar y crear Service
// 	_, err = clientset.CoreV1().Services(namespace).Get(context.TODO(), svcName, metav1.GetOptions{})
// 	if resourceExists(err) {
// 		if askForRecreate("Service", svcName) {
// 			clientset.CoreV1().Services(namespace).Delete(context.TODO(), svcName, metav1.DeleteOptions{})
// 			if err := createService(clientset, namespace, svcName, appPort, msyncPort); err != nil {
// 				log.Fatalf("Failed to create Service: %v", err)
// 			}
// 		}
// 	} else if errors.IsNotFound(err) {
// 		if err := createService(clientset, namespace, svcName, appPort, msyncPort); err != nil {
// 			log.Fatalf("Failed to create Service: %v", err)
// 		}
// 	} else {
// 		log.Fatalf("Error checking Service existence: %v", err)
// 	}

// 	// Esperar a que el pod esté listo
// 	fmt.Printf("Waiting for Pod %s to be ready...\n", podName)
// 	if err := waitForPodReady(clientset, podName, namespace, 120); err != nil {
// 		log.Fatalf("Error waiting for Pod to be ready: %v", err)
// 	}
// 	fmt.Println("Pod is ready.")

// 	// Ahora que la entrada del usuario se ha manejado, puedes iniciar las goroutines
// 	wg := sync.WaitGroup{}
// 	wg.Add(2)

// 	portForwardReadyCh := make(chan bool, 2)
// 	stopCh1 := make(chan struct{})
// 	stopCh2 := make(chan struct{})

// 	go func() {
// 		defer wg.Done()
// 		if err := portForwardPod(clientset, namespace, podName, appPort, appPort, stopCh1); err != nil {
// 			log.Fatalf("Failed to start port forwarding for app port: %v", err)
// 		}
// 	}()

// 	go func() {
// 		defer wg.Done()
// 		if err := portForwardPod(clientset, namespace, podName, msyncPort, msyncPort, stopCh2); err != nil {
// 			log.Fatalf("Failed to start port forwarding for msync port: %v", err)
// 		}
// 		portForwardReadyCh <- true
// 	}()

// 	wg.Wait() // Esperar a que las goroutines terminen

// 	// directory := baseDir
// 	// address := "localhost"
// 	// excludes := ".git/,node_modules/"
// 	// // Sincronización inicial
// 	// maxRetries := 3
// 	// log.Println("Iniciando sincronización inicial con reintentos...")
// 	// if err := syncWithRetries(directory, address, msyncPort, excludes, maxRetries); err != nil {
// 	// 	log.Fatalf("Failed to run initial msync after retries: %v", err)
// 	// }
// 	// log.Println("Sincronización inicial completa.")

// 	// Ejecutar kubectl exec para entrar en el contenedor del pod
// 	containerName := "application-container"
// 	if err := execIntoPod(namespace, podName, containerName); err != nil {
// 		log.Fatalf("Failed to exec into pod: %v", err)
// 	}

// 	// Mantener el programa en ejecución para que la sincronización siga activa
// 	select {}
// }

// checkAndKillProcessUsingPort verifica si el puerto está en uso, y si es así, mata el proceso.
func checkAndKillProcessUsingPort(port int) error {
	cmd := exec.Command("lsof", "-t", fmt.Sprintf("-i:%d", port))
	output, err := cmd.Output()
	if err != nil && !strings.Contains(err.Error(), "exit status 1") {
		// Ignora "exit status 1", que significa que no hay procesos usando el puerto.
		return fmt.Errorf("failed to check port usage: %w", err)
	}

	if len(output) == 0 {
		return nil
	}

	pidStr := strings.TrimSpace(string(output))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("failed to parse process ID: %w", err)
	}

	log.Printf("Killing process %d using port %d", pid, port)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return fmt.Errorf("failed to kill process %d: %w", pid, err)
	}

	return nil
}

// portForwardPodDetached inicia un port-forward en segundo plano, capturando y descartando stdout y stderr.
func portForwardPodDetached(namespace, podName string, localPort, remotePort int) error {
	if err := checkAndKillProcessUsingPort(localPort); err != nil {
		return fmt.Errorf("failed to prepare port %d: %w", localPort, err)
	}

	cmd := exec.Command("kubectl", "port-forward", fmt.Sprintf("pod/%s", podName), fmt.Sprintf("%d:%d", localPort, remotePort), "-n", namespace)

	// Crear pipes para capturar la salida
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Iniciar el proceso
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start port-forward: %w", err)
	}

	// Goroutine para capturar y descartar stdout
	go func() {
		io.Copy(io.Discard, stdoutPipe)
	}()

	// Goroutine para capturar y descartar stderr
	go func() {
		io.Copy(io.Discard, stderrPipe)
	}()

	// Goroutine para esperar que el proceso termine
	go func() {
		cmd.Wait()
	}()

	return nil
}

func OnlyOneServiceHandlerV2() {
	log.SetOutput(ioutil.Discard)
	// logFile, err := os.OpenFile("msync.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	// if err != nil {
	// 	log.Fatalf("Failed to open log file: %v", err)
	// }
	// defer logFile.Close()

	// log.SetOutput(logFile)
	baseDir, err := os.Getwd()
	if err != nil {

		log.Fatalf("Failed to get working directory: %v", err)
	}

	configPath := filepath.Join(baseDir, "multims.yml")
	conf, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	kubeConfigPath := conf.KubeConfigPath
	if conf.UseDefaultKubeConfig {
		kubeConfigPath = filepath.Join(homedir.HomeDir(), ".kube", "config")
	}
	contextName := conf.KubernetesContext
	namespace := conf.Namespace
	uid := conf.UID
	appPort := conf.Application.Port
	msyncPort := 6060
	msyncPortHttp := 6065
	image := conf.Registry.Image

	clientset, err := prepareKubernetesClient(kubeConfigPath, contextName)
	if err != nil {
		log.Fatalf("Failed to prepare Kubernetes client: %v", err)
	}

	log.Printf("Using context: %s", contextName)
	log.Printf("Namespace: %s", namespace)
	log.Printf("KubeConfigPath: %s", kubeConfigPath)

	// Cambiar el contexto explícitamente
	err = switchKubeContext(kubeConfigPath, contextName)
	if err != nil {
		log.Fatalf("Failed to switch context: %v", err)
	}

	podName := fmt.Sprintf("pod-%s", uid)
	pvcName := fmt.Sprintf("pvc-%s", uid)
	svcName := fmt.Sprintf("svc-%s", uid)
	cfmName := fmt.Sprintf("svc-%s", uid)

	// Verificar y crear PVC
	_, err = clientset.CoreV1().PersistentVolumeClaims(namespace).Get(context.TODO(), pvcName, metav1.GetOptions{})
	if resourceExists(err) {
		if askForRecreate("PersistentVolumeClaim", pvcName) {
			clientset.CoreV1().PersistentVolumeClaims(namespace).Delete(context.TODO(), pvcName, metav1.DeleteOptions{})
			if err := waitForPVCDeletion(clientset, namespace, pvcName); err != nil {
				log.Fatalf("Error waiting for PVC deletion: %v", err)
			}
			if err := createPersistentVolumeClaim(clientset, namespace, pvcName); err != nil {
				log.Fatalf("Failed to create PVC: %v", err)
			}
		}
	} else if errors.IsNotFound(err) {
		if err := createPersistentVolumeClaim(clientset, namespace, pvcName); err != nil {
			log.Fatalf("Failed to create PVC: %v", err)
		}
	} else {
		log.Fatalf("Error checking PVC existence: %v", err)
	}

	// Verificar y crear ConfigMap
	_, err = clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), cfmName, metav1.GetOptions{})
	if resourceExists(err) {
		if askForRecreate("ConfigMap", cfmName) {
			clientset.CoreV1().ConfigMaps(namespace).Delete(context.TODO(), cfmName, metav1.DeleteOptions{})
			if err := createConfigMap(clientset, namespace, cfmName); err != nil {
				log.Fatalf("Failed to create ConfigMap: %v", err)
			}
		}
	} else if errors.IsNotFound(err) {
		if err := createConfigMap(clientset, namespace, cfmName); err != nil {
			log.Fatalf("Failed to create ConfigMap: %v", err)
		}
	} else {
		log.Fatalf("Error checking ConfigMap existence: %v", err)
	}

	// Verificar y crear Pod
	_, err = clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if resourceExists(err) {
		if askForRecreate("Pod", podName) {
			clientset.CoreV1().Pods(namespace).Delete(context.TODO(), podName, metav1.DeleteOptions{})
			if err := createPod(clientset, namespace, podName, pvcName, image, cfmName); err != nil {
				log.Fatalf("Failed to create Pod: %v", err)
			}
		}
	} else if errors.IsNotFound(err) {
		if err := createPod(clientset, namespace, podName, pvcName, image, cfmName); err != nil {
			log.Fatalf("Failed to create Pod: %v", err)
		}
	} else {
		log.Fatalf("Error checking Pod existence: %v", err)
	}

	// Verificar y crear Service
	_, err = clientset.CoreV1().Services(namespace).Get(context.TODO(), svcName, metav1.GetOptions{})
	if resourceExists(err) {
		if askForRecreate("Service", svcName) {
			clientset.CoreV1().Services(namespace).Delete(context.TODO(), svcName, metav1.DeleteOptions{})
			if err := createService(clientset, namespace, svcName, appPort, msyncPort); err != nil {
				log.Fatalf("Failed to create Service: %v", err)
			}
		}
	} else if errors.IsNotFound(err) {
		if err := createService(clientset, namespace, svcName, appPort, msyncPort); err != nil {
			log.Fatalf("Failed to create Service: %v", err)
		}
	} else {
		log.Fatalf("Error checking Service existence: %v", err)
	}

	// Esperar a que el pod esté listo
	fmt.Printf("Waiting for Pod %s to be ready...\n", podName)
	if err := waitForPodReady(clientset, podName, namespace, 120); err != nil {
		log.Fatalf("Error waiting for Pod to be ready: %v", err)
	}
	fmt.Println("Pod is ready.")
	///////////// port-forward
	// Verificar que el puerto 6060 esté en escucha antes de proceder con el port-forward
	fmt.Printf("Checking if port %d is listening on pod %s...\n", msyncPort, podName)
	if !isPortListening(namespace, podName, msyncPort) {
		log.Fatalf("Port %d is not listening on Pod %s. Exiting.", msyncPort, podName)
	}
	fmt.Println("Port is listening. Proceeding with port forwarding.")
	//
	directory := baseDir
	fmt.Println("Directory: ", directory)
	// stopCh1 := make(chan struct{})
	// stopCh2 := make(chan struct{})
	// stopCh3 := make(chan struct{})
	containerName := "application-container"
	portForwardReadyCh := make(chan bool, 2)

	// Iniciar el port forwarding para el appPort
	// go func() {
	// 	log.Println("Starting port forwarding for appPort...")
	// 	if err := portForwardPod(clientset, namespace, podName, appPort, appPort, stopCh1); err != nil {
	// 		log.Fatalf("Failed to start port forwarding for app port: %v", err)
	// 	}
	// 	log.Println("Port forwarding for appPort is ready.")
	// 	portForwardReadyCh <- true
	// }()

	// // Iniciar el port forwarding para el msyncPort
	// go func() {
	// 	log.Println("Starting port forwarding for msyncPort...")
	// 	if err := portForwardPod(clientset, namespace, podName, msyncPort, msyncPort, stopCh2); err != nil {
	// 		log.Fatalf("Failed to start port forwarding for msync port: %v", err)
	// 	}
	// 	log.Println("Port forwarding for msyncPort is ready.")
	// 	portForwardReadyCh <- true
	// }()

	// // Iniciar el port forwarding para el msyncPortHttp
	// go func() {
	// 	log.Println("Starting port forwarding for msyncPort...")
	// 	if err := portForwardPod(clientset, namespace, podName, msyncPortHttp, msyncPortHttp, stopCh3); err != nil {
	// 		log.Fatalf("Failed to start port forwarding for msync port: %v", err)
	// 	}
	// 	log.Println("Port forwarding for msyncPort is ready.")
	// 	portForwardReadyCh <- true
	// }()

	// Iniciar el port forwarding para el appPort
	go func() {
		log.Println("Starting port forwarding for appPort...")
		if err := portForwardPodDetached(namespace, podName, appPort, appPort); err != nil {
			log.Fatalf("Failed to start port forwarding for app port: %v", err)
		}
		log.Println("Port forwarding for appPort is ready.")
		portForwardReadyCh <- true
	}()

	// Iniciar el port forwarding para el msyncPort
	go func() {
		log.Println("Starting port forwarding for msyncPort...")
		if err := portForwardPodDetached(namespace, podName, msyncPort, msyncPort); err != nil {
			log.Fatalf("Failed to start port forwarding for msync port: %v", err)
		}
		log.Println("Port forwarding for msyncPort is ready.")
		portForwardReadyCh <- true
	}()

	// Iniciar el port forwarding para el msyncPortHttp
	go func() {
		log.Println("Starting port forwarding for msyncPortHttp...")
		if err := portForwardPodDetached(namespace, podName, msyncPortHttp, msyncPortHttp); err != nil {
			log.Fatalf("Failed to start port forwarding for msync port: %v", err)
		}
		log.Println("Port forwarding for msyncPortHttp is ready.")
		portForwardReadyCh <- true
	}()
	log.Println("Waiting for both port forwards to be ready...")

	// Esperar a que ambos port forwards estén listos
	<-portForwardReadyCh
	<-portForwardReadyCh
	<-portForwardReadyCh

	log.Println("Both port forwards are ready or timed out. Proceeding with the synchronization...")
	log.Println("All port forwards are ready. Proceeding with the synchronization...")

	// Iniciar la sincronización HTTP en un goroutine para que se ejecute en segundo plano
	go func() {
		client.RunClientHTTP(directory, "localhost", fmt.Sprintf("%d", msyncPortHttp), "sync_state.json", []string{"*.log", ".git/", "node_modules/"})
	}()

	log.Println("Synchronization started. Proceeding to exec into pod...")

	log.Println("Executing into pod...")
	if err := execIntoPod(namespace, podName, containerName); err != nil {
		log.Fatalf("Failed to exec into pod: %v", err)
	}

	log.Println("Execution into pod completed successfully.")
	log.Println("Entering into select block to keep the program running.")

	// Mantener el programa en ejecución para que la sincronización siga activa
	select {}
}

// 		log.Fatalf("Error checking ConfigMap existence: %v", err)
// 	}

// 	// Verificar y crear Pod
// 	_, err = clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
// 	if resourceExists(err) {
// 		if askForRecreate("Pod", podName) {
// 			clientset.CoreV1().Pods(namespace).Delete(context.TODO(), podName, metav1.DeleteOptions{})
// 			if err := createPod(clientset, namespace, podName, pvcName, image, cfmName); err != nil {
// 				log.Fatalf("Failed to create Pod: %v", err)
// 			}
// 		}
// 	} else if errors.IsNotFound(err) {
// 		if err := createPod(clientset, namespace, podName, pvcName, image, cfmName); err != nil {
// 			log.Fatalf("Failed to create Pod: %v", err)
// 		}
// 	} else {
// 		log.Fatalf("Error checking Pod existence: %v", err)
// 	}

// 	// Verificar y crear Service
// 	_, err = clientset.CoreV1().Services(namespace).Get(context.TODO(), svcName, metav1.GetOptions{})
// 	if resourceExists(err) {
// 		if askForRecreate("Service", svcName) {
// 			clientset.CoreV1().Services(namespace).Delete(context.TODO(), svcName, metav1.DeleteOptions{})
// 			if err := createService(clientset, namespace, svcName, appPort, msyncPort); err != nil {
// 				log.Fatalf("Failed to create Service: %v", err)
// 			}
// 		}
// 	} else if errors.IsNotFound(err) {
// 		if err := createService(clientset, namespace, svcName, appPort, msyncPort); err != nil {
// 			log.Fatalf("Failed to create Service: %v", err)
// 		}
// 	} else {
// 		log.Fatalf("Error checking Service existence: %v", err)
// 	}

// 	// Esperar a que el pod esté listo
// 	fmt.Printf("Waiting for Pod %s to be ready...\n", podName)
// 	if err := waitForPodReady(clientset, podName, namespace, 120); err != nil {
// 		log.Fatalf("Error waiting for Pod to be ready: %v", err)
// 	}
// 	fmt.Println("Pod is ready.")

// 	// Verificar que el puerto 6060 esté en escucha antes de proceder con el port-forward
// 	if !isPortListening(namespace, podName, msyncPort) {
// 		log.Fatalf("Port %d is not listening on Pod %s. Exiting.", msyncPort, podName)
// 	}
// }

// func OnlyOneServiceHandlerV2() {
// 	baseDir, err := os.Getwd()
// 	if err != nil {
// 		log.Fatalf("Failed to get working directory: %v", err)
// 	}

// 	configPath := filepath.Join(baseDir, "multims.yml")
// 	conf, err := config.LoadConfigFromFile(configPath)
// 	if err != nil {
// 		log.Fatalf("Failed to load config: %v", err)
// 	}

// 	kubeConfigPath := conf.KubeConfigPath
// 	if conf.UseDefaultKubeConfig {
// 		kubeConfigPath = filepath.Join(homedir.HomeDir(), ".kube", "config")
// 	}
// 	contextName := conf.KubernetesContext
// 	namespace := conf.Namespace
// 	uid := conf.UID
// 	appPort := conf.Application.Port
// 	msyncPort := 6060 // Puerto para msync

// 	clientset, err := prepareKubernetesClient(kubeConfigPath, contextName)
// 	if err != nil {
// 		log.Fatalf("Failed to prepare Kubernetes client: %v", err)
// 	}

// 	log.Printf("Using context: %s", contextName)
// 	log.Printf("Namespace: %s", namespace)
// 	log.Printf("KubeConfigPath: %s", kubeConfigPath)

// 	// Cambiar el contexto explícitamente
// 	err = switchKubeContext(kubeConfigPath, contextName)
// 	if err != nil {
// 		log.Fatalf("Failed to switch context: %v", err)
// 	}

// 	podName := fmt.Sprintf("pod-%s", uid)
// 	pvcName := fmt.Sprintf("pvc-%s", uid)
// 	svcName := fmt.Sprintf("svc-%s", uid)

// 	pvcYAML := generatePVCYAML(namespace, uid)
// 	podYAML := generatePodYAMLWithInteractiveCommand(conf)
// 	serviceYAML := generateServiceYAML(namespace, uid, appPort, msyncPort)

// 	// Crear o recrear recursos en Kubernetes
// 	createOrUpdateResource(clientset, pvcName, namespace, pvcYAML, "pvc")
// 	createOrUpdateResource(clientset, podName, namespace, podYAML, "pod")
// 	createOrUpdateResource(clientset, svcName, namespace, serviceYAML, "svc")

// 	// Esperar a que el pod esté listo
// 	fmt.Printf("Waiting for Pod %s to be ready...\n", podName)
// 	if err := waitForPodReady(clientset, podName, namespace, 120); err != nil {
// 		log.Fatalf("Error waiting for Pod to be ready: %v", err)
// 	}
// 	fmt.Println("Pod is ready.")

// 	// Verificar que el puerto 6060 esté en escucha antes de proceder con el port-forward
// 	if !isPortListening(namespace, podName, msyncPort) {
// 		log.Fatalf("Port %d is not listening on Pod %s. Exiting.", msyncPort, podName)
// 	}

// 	// Ejecutar la sincronización inicial
// 	executeSyncScript(baseDir, podName, namespace)

// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	// Goroutine para port-forwarding del puerto 3000 del servicio
// 	go func() {
// 		if err := startPortForward(ctx, namespace, svcName, appPort, appPort); err != nil {
// 			log.Fatalf("Failed to start port-forwarding for service: %v", err)
// 		}
// 	}()

// 	// Goroutine para port-forwarding del puerto 6060 del pod
// 	go func() {
// 		if err := startPortForward(ctx, namespace, podName, msyncPort, msyncPort); err != nil {
// 			log.Fatalf("Failed to start port-forwarding for pod: %v", err)
// 		}
// 	}()

// 	// Ejecutar el comando principal para interactuar con el pod
// 	if err := execIntoPod(uid, namespace); err != nil {
// 		log.Fatalf("Error executing into pod: %v", err)
// 	}

// 	// Manejar señales para terminación limpia
// 	c := make(chan os.Signal, 1)
// 	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
// 	<-c
// 	fmt.Println("Shutting down...")
// }

func executeSyncScript(baseDir, podName, namespace string) {
	log.Printf("Starting initial synchronization with sync.sh script...")
	scriptPath := filepath.Join(baseDir, "sync.sh")
	log.Printf("Script path: %s", scriptPath)
	cmdStr := fmt.Sprintf("%s \"%s\" \"%s\" \"%s\"", scriptPath, baseDir, podName, namespace)
	log.Printf("Executing command: %s", cmdStr)

	cmd := exec.Command("bash", "-c", cmdStr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to execute sync.sh script: %v", err)
	} else {
		log.Println("Successfully executed sync.sh script.")
	}
}

// func ensurePodPortForwarding(ctx context.Context, namespace, podName string, port int) {
// 	cmd := exec.CommandContext(ctx, "kubectl", "port-forward", fmt.Sprintf("pod/%s", podName), fmt.Sprintf("%d:%d", port, port), "-n", namespace)
// 	cmd.Stdout = os.Stdout
// 	cmd.Stderr = os.Stderr

// 	if err := cmd.Start(); err != nil {
// 		log.Fatalf("Failed to start port-forwarding for pod: %v", err)
// 	}

// 	go func() {
// 		<-ctx.Done()
// 		if err := cmd.Process.Kill(); err != nil {
// 			log.Fatalf("Failed to kill port-forwarding process for pod: %v", err)
// 		}
// 	}()
// }

// func createOrUpdateResource(clientset *kubernetes.Clientset, name, namespace, yaml, resourceType string) {
// 	if resourceExists(clientset, name, namespace, resourceType) {
// 		fmt.Printf("%s %s already exists in namespace %s.\n", strings.Title(resourceType), name, namespace)
// 		var recreate bool
// 		prompt := &survey.Confirm{
// 			Message: fmt.Sprintf("%s already exists. Do you want to recreate it?", strings.Title(resourceType)),
// 		}
// 		survey.AskOne(prompt, &recreate)
// 		if recreate {
// 			fmt.Printf("Deleting %s %s in namespace %s...\n", resourceType, name, namespace)
// 			if err := deleteResource(clientset, name, namespace, resourceType); err != nil {
// 				log.Fatalf("Failed to delete %s: %v", resourceType, err)
// 			}
// 			if err := createResource(yaml); err != nil {
// 				log.Fatalf("Failed to create %s: %v", resourceType, err)
// 			}
// 			fmt.Printf("%s created successfully.\n", strings.Title(resourceType))
// 		}
// 	} else {
// 		if err := createResource(yaml); err != nil {
// 			log.Fatalf("Failed to create %s: %v", resourceType, err)
// 		}
// 		fmt.Printf("%s created successfully.\n", strings.Title(resourceType))
// 	}
// }

func startPortForward(ctx context.Context, namespace, resourceName string, localPort, remotePort int) error {
	cmd := exec.CommandContext(ctx, "kubectl", "port-forward", fmt.Sprintf("%s/%s", resourceName, namespace), fmt.Sprintf("%d:%d", localPort, remotePort))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start port-forward: %w", err)
	}

	go func() {
		<-ctx.Done()
		if err := cmd.Process.Kill(); err != nil {
			log.Printf("Failed to kill port-forwarding process: %v", err)
		}
	}()

	return cmd.Wait()
}

func OnlyOneServiceHandler() {
	// Mueve el código de "onlyoneservice" aquí para reutilización y claridad

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
	baseDir := "demo"
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

	if err := client.DeployPod(clientset, uid, namespace, image, uid, int32(port)); err != nil { // client.DeployPod(clientset, uid, namespace, image, uid); err != nil {
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
		scriptsPath := filepath.Join(execDir, "../multims/scripts/refreshv2")
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

	if err := client.DeployPod(clientset, uid, namespace, image, uid, int32(port)); err != nil { // client.DeployPod(clientset, uid, namespace, image, uid); err != nil {
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
