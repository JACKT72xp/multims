package logging

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/spf13/viper"
)

func CheckForLoggingAgentsWithKubectl() []string {
	// Ejecutar kubectl para listar deployments con la etiqueta "app=logging-agent"
	cmd := exec.Command("kubectl", "get", "deployments", "--all-namespaces", "-l", "app=logging-agent", "-o", "jsonpath={.items[*].metadata.namespace}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error checking for logging agents: %v\n", err)
		return nil
	}

	namespaces := string(output)
	if namespaces == "" {
		return nil
	}

	// Dividir los nombres de los namespaces en un slice
	return strings.Split(namespaces, " ")
}

func InstallLoggingAgent(namespace string) {
	fmt.Printf("Installing logging agent in namespace: %s...\n", namespace)

	// Cargar variables de entorno desde multims.yml
	loadConfig()

	// Definir el manifiesto YAML del ServiceAccount, Role y RoleBinding
	permissionsManifest := fmt.Sprintf(`
apiVersion: v1
kind: ServiceAccount
metadata:
  name: logging-agent-sa
  namespace: %s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: %s
  name: logging-agent-role
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"] 
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: logging-agent-rolebinding
  namespace: %s
subjects:
- kind: ServiceAccount
  name: logging-agent-sa
  namespace: %s
roleRef:
  kind: Role
  name: logging-agent-role
  apiGroup: rbac.authorization.k8s.io
`, namespace, namespace, namespace, namespace)

	// Ejecutar kubectl apply con el manifiesto de permisos
	cmdPermissions := exec.Command("kubectl", "apply", "-f", "-")
	cmdPermissions.Stdin = strings.NewReader(permissionsManifest)
	outputPermissions, err := cmdPermissions.CombinedOutput()
	if err != nil {
		fmt.Printf("Error applying permissions: %v\nOutput: %s\n", err, string(outputPermissions))
		return
	}
	fmt.Println("Permissions applied successfully.")

	// Definir el manifiesto YAML del agente
	manifest := fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: logging-agent
  namespace: %s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: logging-agent
  template:
    metadata:
      labels:
        app: logging-agent
    spec:
      serviceAccountName: logging-agent-sa
      containers:
        - name: logging-agent
          image: jackt72xp/multims:monitoring_agentv4
          env:
            - name: AWS_ACCESS_KEY_ID
              value: "%s"
            - name: AWS_SECRET_ACCESS_KEY
              value: "%s"
            - name: AWS_REGION
              value: "%s"
            - name: S3_BUCKET
              value: "%s"
            - name: END_DATE
              value: "%s"
            - name: NAMESPACE
              value: "%s"
          resources:
            limits:
              memory: "256Mi"
              cpu: "100m"
            requests:
              memory: "128Mi"
              cpu: "50m"
`, namespace, viper.GetString("environments.AWS_ACCESS_KEY_ID"), viper.GetString("environments.AWS_SECRET_ACCESS_KEY"), viper.GetString("environments.AWS_REGION"), viper.GetString("environments.S3_BUCKET"), viper.GetString("environments.END_DATE"), namespace)

	// Ejecutar kubectl apply con el manifiesto del agente
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error installing logging agent: %v\nOutput: %s\n", err, string(output))
		return
	}
	fmt.Printf("Logging agent installed in namespace: %s\n", namespace)
}

// Cargar configuración desde multims.yml
func loadConfig() {
	viper.SetConfigName("multims")
	viper.SetConfigType("yml")
	viper.AddConfigPath(".") // Ruta actual

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}
}

func UninstallLoggingAgent(namespace string) {
	fmt.Printf("Uninstalling logging agent from namespace: %s...\n", namespace)

	// Ejecutar kubectl delete para eliminar el deployment del agente
	cmd := exec.Command("kubectl", "delete", "deployment", "logging-agent", "-n", namespace)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error uninstalling logging agent: %v\nOutput: %s\n", err, string(output))
		return
	}
	fmt.Println("Logging agent uninstalled.")
}

func ValidateAgentStatus(installedNamespaces []string) {
	for _, namespace := range installedNamespaces {
		fmt.Printf("\nValidating logging agent status in namespace: %s\n", namespace)

		// Ejecutar un comando para verificar el estado del deployment del agente de logging en el namespace
		cmd := exec.Command("kubectl", "get", "pods", "-n", namespace, "-l", "app=logging-agent", "--field-selector=status.phase=Running")
		output, err := cmd.CombinedOutput()

		if err != nil {
			fmt.Printf("Error validating agent status in namespace %s: %v\nOutput: %s\n", namespace, err, string(output))
		} else if len(output) == 0 {
			fmt.Printf("No running logging agent pods found in namespace: %s\n", namespace)
		} else {
			fmt.Printf("Logging agent is running in namespace: %s\nDetails:\n%s\n", namespace, string(output))
		}
	}
}

func CheckIfAgentInstalled() []string {
	// Ejecutar `kubectl` para listar los namespaces
	cmd := exec.Command("kubectl", "get", "namespaces", "-o", "custom-columns=:metadata.name")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Error listing namespaces: %v\nOutput: %s", err, string(output))
	}

	// Convertir la salida en una lista de namespaces
	namespaces := strings.Split(strings.TrimSpace(string(output)), "\n")

	var installedNamespaces []string
	for _, ns := range namespaces {
		// Ejecutar `kubectl` para verificar si el agente está instalado en cada namespace
		cmdCheck := exec.Command("kubectl", "get", "deployments", "-n", ns, "-o", "custom-columns=:metadata.name")
		outputCheck, err := cmdCheck.CombinedOutput()
		if err != nil {
			log.Printf("Error listing deployments in namespace %s: %v\nOutput: %s", ns, err, string(outputCheck))
			continue
		}

		// Verificar si el deployment "logging-agent" está presente
		deployments := strings.Split(strings.TrimSpace(string(outputCheck)), "\n")
		for _, deployment := range deployments {
			if deployment == "logging-agent" {
				installedNamespaces = append(installedNamespaces, ns)
				fmt.Printf("Logging agent is installed in namespace: %s\n", ns)
			}
		}
	}

	return installedNamespaces
}

func ListNamespaces() []string {
	cmd := exec.Command("kubectl", "get", "namespaces", "-o", "custom-columns=:metadata.name")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error fetching namespaces: %v\n", err)
		return nil
	}
	namespaces := strings.Split(strings.TrimSpace(string(output)), "\n")
	return namespaces
}

// Cargar variables de entorno desde multims.yml
// func loadConfig() {
// 	AWSAccessKeyID := viper.GetString("environments.AWS_ACCESS_KEY_ID")
// 	AWSSecretAccessKey := viper.GetString("environments.AWS_SECRET_ACCESS_KEY")
// 	AWSRegion := viper.GetString("environments.AWS_REGION")
// 	S3Bucket := viper.GetString("environments.S3_BUCKET")
// 	EndDate := viper.GetString("environments.END_DATE")

// 	fmt.Println("Loaded environment variables:")
// 	fmt.Printf("AWS_ACCESS_KEY_ID: %s\n", AWSAccessKeyID)
// 	fmt.Printf("AWS_SECRET_ACCESS_KEY: %s\n", AWSSecretAccessKey)
// 	fmt.Printf("AWS_REGION: %s\n", AWSRegion)
// 	fmt.Printf("S3_BUCKET: %s\n", S3Bucket)
// 	fmt.Printf("END_DATE: %s\n", EndDate)
// }
