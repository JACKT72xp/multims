package security

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// Estructuras
type PodStatus struct {
	// Define the fields of the PodStatus type here
}
type PodInfo struct {
	Metadata struct {
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
}
type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     PodSpec    `json:"spec"`
	Status   PodStatus  `json:"status"`
}

type ObjectMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type PodSpec struct {
	Containers []Container `json:"containers"`
}

type Container struct {
	Name            string               `json:"name"`
	SecurityContext *SecurityContext     `json:"securityContext"`
	Resources       ResourceRequirements `json:"resources"`
	Image           string               `json:"image"`
}

type ResourceRequirements struct {
	Limits   map[string]string `json:"limits"`
	Requests map[string]string `json:"requests"`
}

type SecurityContext struct {
	RunAsUser    *int64        `json:"runAsUser,omitempty"`
	Capabilities *Capabilities `json:"capabilities,omitempty"`
}

type Capabilities struct {
	Add  []string `json:"add,omitempty"`
	Drop []string `json:"drop,omitempty"`
}

func GetPodSecurityDetails(pod Pod) map[string]interface{} {
	details := make(map[string]interface{})

	// Obtener si está corriendo como root
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.RunAsUser != nil {
			if *container.SecurityContext.RunAsUser == int64(0) {
				details["RunningAsRoot"] = true
			} else {
				details["RunningAsRoot"] = false
			}
		} else {
			details["RunningAsRoot"] = "Unknown"
		}
	}

	// Verificar si tiene modo privilegiado (el campo puede no estar presente en algunas versiones)
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil {
			// Aquí verificamos si el campo `Privileged` existe en el SecurityContext
			if hasPrivileged := reflect.ValueOf(container.SecurityContext).Elem().FieldByName("Privileged"); hasPrivileged.IsValid() {
				if hasPrivileged.Elem().Bool() {
					details["PrivilegedMode"] = true
				} else {
					details["PrivilegedMode"] = false
				}
			} else {
				details["PrivilegedMode"] = "Unknown" // Campo no disponible
			}
		} else {
			details["PrivilegedMode"] = "Unknown"
		}
	}

	// Verificar el controlador del pod
	controllerOwner := GetPodController(pod.Metadata.Name, pod.Metadata.Namespace)
	if controllerOwner == "" {
		details["ControllerOwner"] = "Orphaned"
	} else {
		details["ControllerOwner"] = controllerOwner
	}

	// Verificar capacidades de red inseguras
	networkCapabilities, _ := HasPodNetworkCapabilities(pod.Metadata.Namespace, pod.Metadata.Name)
	details["InsecureNetworkCapabilities"] = !networkCapabilities

	// Verificar si tiene acceso a bash/sh
	for _, container := range pod.Spec.Containers {
		hasShell := CheckForShell(container.Image)
		details["HasShellAccess"] = hasShell
	}

	return details
}

func GetPodController(podName, namespace string) string {
	cmd := exec.Command("kubectl", "get", "pod", podName, "-n", namespace, "-o", "jsonpath={.metadata.ownerReferences[0].kind}")
	output, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(output)) == "" {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// Verificar si un contenedor tiene acceso a bash o sh
func CheckForShell(image string) bool {
	cmd := exec.Command("docker", "run", "--rm", image, "sh", "-c", "command -v bash || command -v sh")
	output, err := cmd.Output()
	return err == nil && len(output) > 0
}

// Función para obtener los detalles de seguridad y generar un reporte de seguridad avanzado
func AdvancedPodSecurityAnalysis(pod Pod) {
	details := GetPodSecurityDetails(pod)

	// Guardar los detalles de seguridad del pod en un archivo JSON
	filePath := fmt.Sprintf("security_details_%s_%s.json", pod.Metadata.Namespace, pod.Metadata.Name)
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Printf("Error saving security details: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(details)
	if err != nil {
		fmt.Printf("Error encoding security details: %v\n", err)
	}
}

// BasicAnalysisMenu permite al usuario seleccionar si el análisis será para un nodo, namespace o el clúster completo
// func AdvancedAnalysisMenu(returnToMenuFunc func()) {
// 	reader := bufio.NewReader(os.Stdin)
// 	fmt.Println("\nDo you want to analyze an entire cluster, a specific node, or a namespace for advanced?")
// 	fmt.Println("1. Entire cluster")
// 	fmt.Println("2. Specific node")
// 	fmt.Println("3. Specific namespace")

// 	fmt.Print("\nChoose an option: ")
// 	option, _ := reader.ReadString('\n')
// 	option = strings.TrimSpace(option)

// 	var target string
// 	var analysisType string

// 	switch option {
// 	case "1":
// 		target = "entire_cluster"
// 		analysisType = "entire_cluster"
// 	case "2":
// 		fmt.Print("\nEnter the node name: ")
// 		nodeName, _ := reader.ReadString('\n')
// 		target = strings.TrimSpace(nodeName)
// 		analysisType = "specific_node"
// 	case "3":
// 		namespace, err := GetNamespaceSelection() // Obtener la selección del namespace
// 		if err != nil {
// 			fmt.Println("Error selecting namespace:", err)
// 			returnToMenuFunc() // Volver al menú si hay un error
// 			return
// 		}
// 		target = namespace
// 		analysisType = "specific_namespace"
// 	default:
// 		fmt.Println("Invalid option. Returning to main menu.")
// 		returnToMenuFunc()
// 		return
// 	}

//		AdvancedAnalysis(target, analysisType)
//		returnToMenuFunc() // Volver al menú principal
//	}
func HasDroppedCapabilities(pod Pod) bool {
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
			// Verificamos si el contenedor ha eliminado capacidades (drop)
			if len(container.SecurityContext.Capabilities.Drop) > 0 {
				return true
			}
		}
	}
	return false
}

// Función para obtener los detalles de un pod
func GetPodDetails(namespace, podName string) (Pod, error) {
	cmd := exec.Command("kubectl", "get", "pod", podName, "-n", namespace, "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return Pod{}, err
	}

	var pod Pod
	err = json.Unmarshal(output, &pod)
	if err != nil {
		return Pod{}, err
	}

	return pod, nil
}

// Función para ejecutar Trivy en la imagen de un contenedor
func ScanContainerImageWithTrivy(image string) (string, error) {
	cmd := exec.Command("trivy", "image", "--format", "json", image)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error running trivy: %v", err)
	}
	return string(output), nil
}

// Función para obtener la lista de pods en un namespace
func GetPodsInNamespace(namespace string) ([]string, error) {
	cmd := exec.Command("kubectl", "get", "pods", "-n", namespace, "-o", "jsonpath={.items[*].metadata.name}")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	pods := strings.Fields(string(output))
	return pods, nil
}

func AdvancedAnalysis(target string, analysisType string) {
	fmt.Printf("Starting advanced security analysis for %s...\n", target)
	directoryName := fmt.Sprintf("Reports/advanced_analysis_%s_%s", target, analysisType)

	// Crear el directorio "Reports" y el subdirectorio para el análisis avanzado
	err := os.MkdirAll(directoryName, os.ModePerm)
	if err != nil {
		fmt.Printf("Error creating directory %s: %v\n", directoryName, err)
		return
	}

	// Obtener los namespaces según el análisis seleccionado
	var namespaces []string
	if analysisType == "entire_cluster" {
		namespaces, err = GetAllNamespaces()
		if err != nil {
			fmt.Println("Error fetching namespaces for entire cluster:", err)
			return
		}
	} else {
		namespaces = []string{target}
	}

	var podSecurityDetails []map[string]interface{} // Agregar detalles de seguridad

	// Recorremos los namespaces y sus pods
	for _, namespace := range namespaces {
		// Obtenemos todos los pods del namespace
		pods, err := GetPodsInNamespace(namespace)
		if err != nil {
			fmt.Printf("Error fetching pods for namespace %s: %v\n", namespace, err)
			continue
		}

		// Recorremos cada pod en el namespace
		for _, podName := range pods {
			pod, err := GetPodDetails(namespace, podName)
			if err != nil {
				fmt.Printf("Error getting pod details for pod %s in namespace %s: %v\n", podName, namespace, err)
				continue
			}

			// Obtener detalles de seguridad del pod por cada contenedor
			podDetails := make(map[string]interface{})
			podDetails["namespace"] = namespace
			podDetails["pod_name"] = podName
			podDetails["security_details"] = GetPodSecurityDetails(pod)
			podDetails["timestamp"] = time.Now()

			// Lista para almacenar las violaciones a nivel de pod
			var podViolations []string

			// Validaciones OWASP para seguridad en el pod
			for _, container := range pod.Spec.Containers {
				containerViolations := CheckContainerSecurityPractices(container, podName, namespace)
				podViolations = append(podViolations, containerViolations...)
			}

			// Agregar violaciones al resumen del pod
			podDetails["violations"] = podViolations

			// Guardar los reportes por pod en un archivo individual
			savePodReport(directoryName, namespace, podName, podDetails, podViolations)

			// Escaneo de imágenes de contenedores con Trivy
			for _, container := range pod.Spec.Containers {
				fmt.Printf("Scanning image %s from pod %s in namespace %s...\n", container.Image, podName, namespace)
				scanResult, err := ScanContainerImageWithTrivy(container.Image)
				if err != nil {
					fmt.Printf("Error scanning image %s: %v\n", container.Image, err)
				} else {
					imageScanFilePath := fmt.Sprintf("%s/%s_%s_image_scan.md", directoryName, namespace, podName)
					err := saveImageScanReport(imageScanFilePath, scanResult)
					if err != nil {
						fmt.Printf("Error saving image scan report for pod %s in namespace %s: %v\n", podName, namespace, err)
					}
				}
			}

			// Agregar los detalles de seguridad del pod a la lista general
			podSecurityDetails = append(podSecurityDetails, podDetails)
		}
	}

	// Guardar el reporte de análisis avanzado
	report := map[string]interface{}{
		"target":        target,
		"analysis_type": analysisType,
		"pod_security":  podSecurityDetails, // Agregar los detalles de seguridad de los pods
		"timestamp":     time.Now(),
	}

	err = SaveReport(fmt.Sprintf("%s/advanced_%s_%s.json", directoryName, target, analysisType), report)
	if err != nil {
		fmt.Println("Error saving report:", err)
	}

	fmt.Println("Advanced analysis completed.")
}

func CheckContainerSecurityPractices(container Container, podName, namespace string) []string {
	var violations []string
	// Verificar si está corriendo como root
	if container.SecurityContext != nil {
		if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == int64(0) {
			violations = append(violations, fmt.Sprintf("Container %s in pod %s (namespace: %s) is running as root", container.Name, podName, namespace))
		}
	}

	// Verificar si no tiene límites de recursos definidos
	if container.Resources.Limits == nil || container.Resources.Requests == nil {
		violations = append(violations, fmt.Sprintf("Container %s in pod %s (namespace: %s) does not have resource limits or requests set", container.Name, podName, namespace))
	}

	return violations
}

func savePodReport(directoryName, namespace, podName string, securityDetails map[string]interface{}, violations []string) {
	// Crear un reporte individual para el pod
	podReport := map[string]interface{}{
		"pod_name":         podName,
		"namespace":        namespace,
		"security_details": securityDetails,
		"timestamp":        time.Now(),
	}

	// Asegurarse de que el directorio existe
	podDirectory := filepath.Join(directoryName, namespace)
	err := os.MkdirAll(podDirectory, os.ModePerm)
	if err != nil {
		fmt.Printf("Error creating directory for pod reports: %v\n", err)
		return
	}

	// Generar el archivo JSON para el pod en su propio directorio
	podReportFileName := filepath.Join(podDirectory, fmt.Sprintf("%s_%s_security_report.json", namespace, podName))
	err = SaveReport(podReportFileName, podReport)
	if err != nil {
		fmt.Printf("Error saving report for pod %s in namespace %s: %v\n", podName, namespace, err)
		return
	}

	fmt.Printf("Security analysis for pod %s in namespace %s completed and saved to %s\n", podName, namespace, podReportFileName)
}

// Función para guardar el reporte de escaneo de una imagen en un archivo Markdown
func saveImageScanReport(filePath, scanResult string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(scanResult)
	return err
}

// Función para guardar un resumen del análisis en un archivo Markdown
func saveSummaryReport(filePath string, namespaces []string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	file.WriteString("# Summary of Advanced Security Analysis\n")
	file.WriteString(fmt.Sprintf("Date: %s\n\n", time.Now().Format(time.RFC1123)))
	file.WriteString("## Namespaces analyzed:\n")
	for _, ns := range namespaces {
		file.WriteString(fmt.Sprintf("- %s\n", ns))
	}

	return nil
}

func CheckOWASPSecurityPractices(pod Pod, namespace string) []string {
	violations := []string{}

	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil {
			if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == int64(0) {
				violations = append(violations, fmt.Sprintf("Pod %s in namespace %s is running as root", pod.Metadata.Name, pod.Metadata.Namespace))
			}
		}

		if container.Resources.Limits == nil || container.Resources.Requests == nil {
			violations = append(violations, fmt.Sprintf("Pod %s in namespace %s does not have resource limits or requests set", pod.Metadata.Name, pod.Metadata.Namespace))
		}

		if !HasDroppedCapabilities(pod) {
			violations = append(violations, fmt.Sprintf("Pod %s in namespace %s has not dropped unnecessary capabilities", pod.Metadata.Name, pod.Metadata.Namespace))
		}

		if hasCapabilities, _ := HasPodNetworkCapabilities(pod.Metadata.Namespace, pod.Metadata.Name); !hasCapabilities {
			violations = append(violations, fmt.Sprintf("Pod %s in namespace %s has insecure network capabilities", pod.Metadata.Name, pod.Metadata.Namespace))
		}
	}

	return violations
}

func GetNamespacesFromNode(nodeName string) ([]string, error) {
	cmd := exec.Command("kubectl", "get", "pods", "--all-namespaces", "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error executing kubectl command: %v", err)
	}

	var podList struct {
		Items []PodInfo `json:"items"`
	}

	err = json.Unmarshal(output, &podList)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling pod list: %v", err)
	}

	namespaceSet := make(map[string]struct{})

	// Filtrar los pods que están en el nodo especificado
	for _, pod := range podList.Items {
		if strings.TrimSpace(pod.Spec.NodeName) == nodeName {
			namespaceSet[pod.Metadata.Namespace] = struct{}{}
		}
	}

	// Convertir el conjunto de namespaces en una lista
	var namespaces []string
	for namespace := range namespaceSet {
		namespaces = append(namespaces, namespace)
	}

	if len(namespaces) == 0 {
		return nil, fmt.Errorf("no namespaces found for node %s", nodeName)
	}

	return namespaces, nil
}
