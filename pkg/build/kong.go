package build

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"multims/pkg/config"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// GenerateKongConfig genera el contenido del archivo kong.yml utilizando la lista de servicios desplegados.
// GenerateKongConfig genera el contenido del archivo kong.yml utilizando la lista de servicios desplegados.
// GenerateKongConfig genera el contenido del archivo kong.yml utilizando la lista de servicios desplegados.
// GenerateKongConfig genera el contenido del archivo kong.yml utilizando la lista de servicios desplegados.
// GenerateKongConfig genera el contenido del archivo kong.yml utilizando la lista de servicios desplegados.
func GenerateKongConfig(services []config.ServiceConfig, namespace string) (string, error) {
	const configTemplate = `apiVersion: v1
kind: ConfigMap
metadata:
  name: kong-config
data:
  kong.yml: |
    _format_version: "1.1"
    services:
  {{- range .Services }}
    - name: {{ .Name }}-service
      url: http://{{ .Name }}.{{ $.Namespace }}.svc.cluster.local:{{ .Port }}
      routes:
      - name: {{ .Name }}-route
        paths:
        - "/{{ .Name }}"
    {{- end }}
`

	tmpl, err := template.New("config").Parse(configTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse config template: %v", err)
	}

	var result string
	buffer := &bytes.Buffer{}

	err = tmpl.Execute(buffer, struct {
		Services  []config.ServiceConfig
		Namespace string
	}{Services: services, Namespace: namespace})

	if err != nil {
		return "", fmt.Errorf("failed to execute template: %v", err)
	}

	result = buffer.String()
	return result, nil
}

// WriteToFile escribe el contenido generado en un archivo especificado.
func WriteToFile(content, filePath string) error {
	// Crea el archivo
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	// Escribe el contenido en el archivo
	_, err = file.WriteString(content)
	if err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	return nil
}
func DeployKong(clientset *kubernetes.Clientset, namespace string, services []config.ServiceConfig) error {
	// Obtén la ruta absoluta del ejecutable actual
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get the executable path: %v", err)
	}
	dir := filepath.Dir(exePath)

	// Asume que los archivos YAML están en la misma ubicación que el ejecutable de tu CLI
	deployYAMLFile := filepath.Join(dir, "pkg/build/templates/kong/deploy.yaml")
	svcYAMLFile := filepath.Join(dir, "pkg/build/templates/kong/svc.yaml")

	configContent, err := GenerateKongConfig(services, namespace)
	// Define la ruta completa del archivo configdemo.yaml
	configFilePath := filepath.Join(dir, "pkg/build/templates/kong/config.yaml")

	// Escribe el contenido generado en el archivo configdemo.yaml
	if err := WriteToFile(configContent, configFilePath); err != nil {
		return fmt.Errorf("failed to write Kong config to file: %v", err)
	}

	if err != nil {
		return fmt.Errorf("failed to generate Kong config: %v", err)
	}

	// Verifica si los archivos existen
	if _, err := os.Stat(deployYAMLFile); os.IsNotExist(err) {
		return fmt.Errorf("deploy yaml file does not exist at %s", deployYAMLFile)
	}
	if _, err := os.Stat(svcYAMLFile); os.IsNotExist(err) {
		return fmt.Errorf("service yaml file does not exist at %s", svcYAMLFile)
	}
	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		return fmt.Errorf("configmap yaml file does not exist at %s", configFilePath)
	}

	// Aplicar el archivo deploy.yaml
	if err := applyKongTemplate(deployYAMLFile, namespace); err != nil {
		return err
	}

	// Aplicar el archivo svc.yaml
	if err := applyKongTemplate(svcYAMLFile, namespace); err != nil {
		return err
	}

	// Aplicar el archivo svc.yaml
	if err := applyKongTemplate(configFilePath, namespace); err != nil {
		return err
	}

	// Esperar a que Kong esté listo
	return waitForKongReady(clientset, namespace)
}

func applyKongTemplate(templateFile, namespace string) error {
	// Comando para aplicar el archivo de plantilla
	cmd := exec.Command("kubectl", "apply", "-f", templateFile, "-n", namespace)

	// Ejecutar el comando
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to apply %s: %s\n%s", templateFile, err, string(output))
		return err
	}

	// Éxito
	fmt.Printf("%s applied successfully\n", templateFile)
	return nil
}

func waitForKongReady(clientset *kubernetes.Clientset, namespace string) error {
	// Define lo que significa estar 'Ready' para Kong
	return wait.PollImmediate(time.Second*5, time.Minute*10, func() (bool, error) {
		// Verificar el estado de los pods de Kong
		pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), v1.ListOptions{
			LabelSelector: "app=kong", // Asumiendo que tus pods de Kong tienen esta etiqueta
		})
		if err != nil {
			return false, fmt.Errorf("error getting pods: %v", err)
		}

		if len(pods.Items) == 0 {
			return false, nil // Aún no hay pods, seguir esperando
		}

		for _, pod := range pods.Items {
			allReady := true
			for _, cond := range pod.Status.Conditions {
				if cond.Type == "Ready" && cond.Status != "True" {
					allReady = false
					break
				}
			}
			if !allReady {
				return false, nil // Al menos un pod no está listo
			}
		}

		// Verificar el estado del servicio de Kong
		_, err = clientset.CoreV1().Services(namespace).Get(context.TODO(), "kong-proxy", v1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("error getting Kong service: %v", err)
		}

		// TODO: Aquí podrías añadir más verificaciones según sea necesario

		return true, nil // Todo está listo
	})
}

func DeployExternalServices(clientset *kubernetes.Clientset, namespace string, multiservices []config.ServiceConfig) error {
	// Iterar sobre los servicios a desplegar
	for _, service := range multiservices {
		serviceName := service.Name
		servicePort := service.Port
		podName := serviceName + "-pod" // Asignar un nombre al pod basado en el nombre del servicio
		image := service.Image
		port := service.Port
		port32 := int32(port)
		fmt.Print("Deploying MultiServices...1")
		// Verificar si el servicio ya existe
		if _, err := clientset.CoreV1().Services(namespace).Get(context.Background(), serviceName, v1.GetOptions{}); err == nil {
			// Si el servicio ya existe, pasar al siguiente servicio
			log.Printf("Service %s already exists. Skipping...\n", serviceName)
			fmt.Print("Deploying MultiServices...1")

			continue
		} else if !errors.IsNotFound(err) {
			// Si hay un error diferente a "no encontrado", manejarlo
			fmt.Print("Deploying MultiServices...1")

			log.Fatalf("Failed to get service %s: %v\n", serviceName, err)
		}
		fmt.Print("Deploying MultiServices...1")

		// Crear la definición del servicio
		service := &corev1.Service{
			ObjectMeta: v1.ObjectMeta{
				Name:      serviceName,
				Namespace: namespace,
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{
					"app": podName, // Asociar el servicio al pod basado en el nombre del pod
				},
				Ports: []corev1.ServicePort{
					{
						Name:     serviceName + "-port",
						Protocol: corev1.ProtocolTCP,
						Port:     int32(servicePort),
						TargetPort: intstr.IntOrString{
							IntVal: int32(port),
						},
					},
				},
			},
		}

		// Crear el servicio en Kubernetes
		if _, err := clientset.CoreV1().Services(namespace).Create(context.Background(), service, v1.CreateOptions{}); err != nil {
			log.Fatalf("Failed to create service %s: %v", serviceName, err)
		}

		fmt.Printf("Service %s deployed successfully on port %d\n", serviceName, servicePort)

		// Verificar si el pod ya existe
		if _, err := clientset.CoreV1().Pods(namespace).Get(context.Background(), podName, v1.GetOptions{}); err == nil {
			// Si el pod ya existe, pasar al siguiente servicio
			log.Printf("Pod %s already exists. Skipping...\n", podName)
			continue
		} else if !errors.IsNotFound(err) {
			// Si hay un error diferente a "no encontrado", manejarlo
			log.Fatalf("Failed to get pod %s: %v\n", podName, err)
		}

		// Crear la definición del pod
		pod := &corev1.Pod{
			ObjectMeta: v1.ObjectMeta{
				Name:      podName,
				Namespace: namespace,
				Labels: map[string]string{
					"app": podName, // Asignar una etiqueta al pod para que el servicio lo seleccione
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  serviceName,
						Image: image,
						Ports: []corev1.ContainerPort{
							{
								ContainerPort: port32,
							},
						},
					},
				},
			},
		}

		// Crear el pod en Kubernetes
		if _, err := clientset.CoreV1().Pods(namespace).Create(context.Background(), pod, v1.CreateOptions{}); err != nil {
			log.Fatalf("Failed to create pod %s: %v", podName, err)
		}

		fmt.Printf("Pod %s deployed successfully with image %s and port %d\n", podName, image, port)
	}

	// Desplegar Kong

	fmt.Println("Kong deployed successfully in multi-service mode.")

	return nil
}
