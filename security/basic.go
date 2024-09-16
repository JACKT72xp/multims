package security

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func getRBACRoles(namespaces []string) (map[string][]map[string]string, error) {
	rbacRoles := make(map[string][]map[string]string)

	for _, ns := range namespaces {
		// Obtener detalles de RBAC roles y ServiceAccounts en el namespace
		cmd := exec.Command("kubectl", "get", "roles,rolebindings,serviceaccounts", "-n", ns, "-o", "jsonpath={range .items[*]}{.kind}{','}{.metadata.name}{','}{.roleRef.name}{','}{.subjects[*].name}{'\\n'}{end}")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("error fetching RBAC details for namespace %s: %v", ns, err)
		}

		roleLines := strings.Split(string(output), "\n")
		for _, line := range roleLines {
			if line == "" {
				continue
			}
			parts := strings.Split(line, ",")
			if len(parts) < 4 {
				continue
			}

			kind := parts[0]
			name := parts[1]
			roleRef := parts[2]
			subject := parts[3]

			role := map[string]string{
				"kind":     kind,
				"name":     name,
				"role_ref": roleRef,
				"subject":  subject,
			}

			rbacRoles[ns] = append(rbacRoles[ns], role)
		}
	}

	return rbacRoles, nil
}

func getPodDetails(namespaces []string) (map[string][]map[string]interface{}, error) {
	podDetails := make(map[string][]map[string]interface{})

	for _, ns := range namespaces {
		// Obtener detalles de los pods en el namespace
		cmd := exec.Command("kubectl", "get", "pods", "-n", ns, "-o", "jsonpath={range .items[*]}{.metadata.name}{','}{.status.phase}{','}{.status.containerStatuses[*].restartCount}{','}{.spec.containers[*].resources.requests.cpu}{','}{.spec.containers[*].resources.requests.memory}{','}{.spec.containers[*].securityContext.runAsNonRoot}{','}{.status.conditions[?(@.type=='Ready')].status}{'\\n'}{end}")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("error fetching pod details for namespace %s: %v", ns, err)
		}

		podLines := strings.Split(string(output), "\n")
		for _, line := range podLines {
			if line == "" {
				continue
			}
			parts := strings.Split(line, ",")
			if len(parts) < 7 {
				continue
			}

			// Parsear los detalles
			podName := parts[0]
			phase := parts[1]
			restarts := parts[2]
			cpuRequest := parts[3]
			memRequest := parts[4]
			runAsNonRoot := parts[5] == "true"
			ready := parts[6] == "True"

			// Crear el objeto de pod
			pod := map[string]interface{}{
				"pod_name":       podName,
				"phase":          phase,
				"restarts":       restarts,
				"cpu_request":    cpuRequest,
				"memory_request": memRequest,
				"run_as_nonroot": runAsNonRoot,
				"ready":          ready,
			}

			podDetails[ns] = append(podDetails[ns], pod)
		}
	}

	return podDetails, nil
}

// BasicAnalysis realiza un análisis básico del clúster, nodo o namespace
func BasicAnalysis(target string, analysisType string) {
	fmt.Printf("Starting basic security analysis for %s (%s)...\n", target, analysisType)

	var namespaces []string
	var err error
	errorLog := []string{} // Registro de errores

	// Si el análisis es para el clúster completo, obtenemos todos los namespaces
	if analysisType == "entire_cluster" {
		namespaces, err = GetAllNamespaces()
		if err != nil {
			fmt.Println("Error fetching namespaces:", err)
			errorLog = append(errorLog, fmt.Sprintf("Error fetching namespaces: %v", err))
			// Continuar con el análisis incluso si hay error obteniendo namespaces
		}
	} else if analysisType == "namespace" {
		namespaces = []string{target}
	} else if analysisType == "node" {
		namespaces, err = getNamespacesFromNode(target)
		if err != nil {
			fmt.Println("Error fetching namespaces for node:", err)
			errorLog = append(errorLog, fmt.Sprintf("Error fetching namespaces for node %s: %v", target, err))
			// Continuar con el análisis incluso si hay error obteniendo namespaces de nodo
		}
	}

	// Obtener el estado de los pods en los namespaces seleccionados
	podStatus, err := GetPodStatus(namespaces)
	if err != nil {
		fmt.Println("Error getting pod status:", err)
		errorLog = append(errorLog, fmt.Sprintf("Error getting pod status: %v", err))
	}

	// Obtener los pods con más de 5 reinicios en los namespaces seleccionados
	highRestarts, err := GetHighRestarts(namespaces)
	if err != nil {
		fmt.Println("Error getting high restart pods:", err)
		errorLog = append(errorLog, fmt.Sprintf("Error getting high restart pods: %v", err))
	}

	// Obtener servicios expuestos en los namespaces seleccionados
	services, err := GetExposedServices(namespaces)
	if err != nil {
		fmt.Println("Error getting exposed services:", err)
		errorLog = append(errorLog, fmt.Sprintf("Error getting exposed services: %v", err))
	}

	// Obtener la configuración de Ingress
	ingressConfigs, err := GetIngressConfig(namespaces)
	if err != nil {
		fmt.Println("Error getting ingress configs:", err)
		errorLog = append(errorLog, fmt.Sprintf("Error getting ingress configs: %v", err))
	}

	// Obtener permisos utilizando `kubectl auth can-i` para detectar vulnerabilidades
	permissions, err := GetPodPermissions(namespaces)
	if err != nil {
		fmt.Println("Error getting pod permissions:", err)
		errorLog = append(errorLog, fmt.Sprintf("Error getting pod permissions: %v", err))
	}

	// Crear el reporte básico de seguridad
	report := map[string]interface{}{
		"pod_status":       podStatus,
		"high_restarts":    highRestarts,
		"exposed_services": services,
		"ingress_config":   ingressConfigs,
		"permissions":      permissions,
		"status":           "Basic analysis complete",
		"target":           target,
		"analysis_type":    analysisType,
		"errors":           errorLog, // Registrar los errores aquí
		"timestamp":        time.Now(),
	}

	// Guardar el reporte básico en JSON
	fileName := fmt.Sprintf("basic_%s_%s.json", target, analysisType)
	err = SaveReport(fileName, report)
	if err != nil {
		fmt.Println("Error saving report:", err)
	}

	fmt.Println("Basic analysis completed.")
}

// func GetPodsInNamespace(namespace string) ([]string, error) {
// 	// Ejecutamos un comando `kubectl` para obtener los nombres de todos los pods en el namespace
// 	cmd := exec.Command("kubectl", "get", "pods", "-n", namespace, "-o", "jsonpath={.items[*].metadata.name}")
// 	output, err := cmd.CombinedOutput()
// 	if err != nil {
// 		return nil, fmt.Errorf("error fetching pods in namespace %s: %v", namespace, err)
// 	}

// 	// Convertimos la salida a una lista de nombres de pods
// 	pods := strings.Split(string(output), " ")
// 	if len(pods) == 1 && pods[0] == "" {
// 		return []string{}, nil // No hay pods en el namespace
// 	}
// 	return pods, nil
// }

func GetPodResourceLimits(pod, namespace string) (limits struct {
	CPULimit    string
	MemoryLimit string
}) {
	// Aquí puedes ejecutar un comando `kubectl describe pod` y analizar los límites de recursos
	// Placeholder de ejemplo:
	limits.CPULimit = "500m"      // 500 millicores de CPU
	limits.MemoryLimit = "1024Mi" // 1024Mi de RAM
	return limits
}

func HasPodNetworkCapabilities(pod, namespace string) (bool, error) {
	// Ejecutar un comando para revisar las capacidades de red del pod
	// Utilizamos `kubectl describe pod` para obtener detalles de las capacidades de red

	cmd := exec.Command("kubectl", "describe", "pod", pod, "-n", namespace)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("error checking network capabilities for pod %s: %v", pod, err)
	}

	// Analizamos la salida de `kubectl describe pod` para encontrar detalles de la configuración de red
	// En este caso, buscamos si hay configuraciones de capacidades de red como NET_ADMIN o NET_RAW
	networkCapabilities := strings.Contains(string(output), "NET_ADMIN") || strings.Contains(string(output), "NET_RAW")

	if networkCapabilities {
		return true, nil // El pod tiene capacidades de red amplias
	}
	return false, nil // El pod está restringido a su namespace o nodo
}

// GetPodSidecarCount obtiene el número de sidecars o contenedores adicionales en el pod
func GetPodSidecarCount(pod, namespace string) int {
	// Utilizamos `kubectl get pod` para obtener detalles del pod y contar los contenedores
	cmd := exec.Command("kubectl", "get", "pod", pod, "-n", namespace, "-o", "jsonpath={.spec.containers[*].name}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error checking sidecars for pod %s: %v\n", pod, err)
		return 0
	}

	// La salida de `kubectl get pod` contiene una lista de los nombres de los contenedores
	containers := strings.Split(string(output), " ")

	// Restar 1 para obtener el número de sidecars (asumiendo que el primer contenedor es el principal)
	if len(containers) > 1 {
		return len(containers) - 1 // Número de sidecars (contendores adicionales)
	}
	return 0 // No hay sidecars
}

func GetPodStatus(namespaces []string) (map[string][]map[string]interface{}, error) {
	podStatus := make(map[string][]map[string]interface{})

	for _, ns := range namespaces {
		// Ejecuta kubectl para obtener los detalles de los pods en formato JSON
		cmd := exec.Command("kubectl", "get", "pods", "-n", ns, "-o", "json")
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("error fetching pod details: %v", err)
		}

		// Parsear la salida JSON de kubectl
		var podData struct {
			Items []struct {
				Metadata struct {
					Name              string `json:"name"`
					CreationTimestamp string `json:"creationTimestamp"`
				} `json:"metadata"`
				Spec struct {
					NodeName   string `json:"nodeName"`
					Containers []struct {
						Name      string `json:"name"`
						Resources struct {
							Limits   map[string]string `json:"limits"`
							Requests map[string]string `json:"requests"`
						} `json:"resources"`
					} `json:"containers"`
				} `json:"spec"`
				Status struct {
					Phase             string `json:"phase"`
					HostIP            string `json:"hostIP"`
					PodIP             string `json:"podIP"`
					StartTime         string `json:"startTime"`
					RestartCount      int    `json:"restartCount"`
					ContainerStatuses []struct {
						Name         string `json:"name"`
						Ready        bool   `json:"ready"`
						RestartCount int    `json:"restartCount"`
					} `json:"containerStatuses"`
				} `json:"status"`
			} `json:"items"`
		}

		if err := json.Unmarshal(output, &podData); err != nil {
			return nil, fmt.Errorf("error parsing pod details: %v", err)
		}

		// Procesamos cada pod dentro del namespace
		for _, pod := range podData.Items {
			podDetail := map[string]interface{}{
				"pod_name":         pod.Metadata.Name,
				"phase":            pod.Status.Phase,
				"node":             pod.Spec.NodeName,
				"start_time":       pod.Status.StartTime,
				"restart_count":    pod.Status.RestartCount,
				"host_ip":          pod.Status.HostIP,
				"pod_ip":           pod.Status.PodIP,
				"container_status": pod.Status.ContainerStatuses,
				"resources":        pod.Spec.Containers,
				"root_user":        IsPodRunningAsRoot(pod.Metadata.Name, ns),
			}

			// Añadimos el pod al listado del namespace correspondiente
			podStatus[ns] = append(podStatus[ns], podDetail)
		}
	}

	return podStatus, nil
}

// IsPodRunningAsRoot verifica si el pod está corriendo como root
func IsPodRunningAsRoot(podName, namespace string) bool {
	// Usar un comando kubectl para verificar si el pod está corriendo como root
	cmd := exec.Command("kubectl", "exec", podName, "-n", namespace, "--", "id", "-u")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Error checking root status for pod %s in namespace %s: %v\n", podName, namespace, err)
		return false
	}

	// Verificamos si el ID de usuario es 0 (root)
	return strings.TrimSpace(string(output)) == "0"
}

func GetPodPermissions(namespaces []string) (map[string][]string, error) {
	permissions := make(map[string][]string)

	for _, ns := range namespaces {
		// Verificar permisos de los pods en este namespace
		cmd := exec.Command("kubectl", "auth", "can-i", "--list", "-n", ns)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("error checking permissions for namespace %s: %v", ns, err)
		}

		permissions[ns] = strings.Split(string(output), "\n")
	}

	return permissions, nil
}

func GetIngressConfig(namespaces []string) (map[string][]string, error) {
	ingressConfig := make(map[string][]string)

	for _, ns := range namespaces {
		cmd := exec.Command("kubectl", "get", "ingress", "-n", ns, "-o", "jsonpath={.items[*].spec.tls}")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("error fetching ingress for namespace %s: %v", ns, err)
		}

		ingress := strings.Fields(string(output))
		if len(ingress) == 0 {
			ingressConfig[ns] = append(ingressConfig[ns], "No TLS configured")
		} else {
			ingressConfig[ns] = append(ingressConfig[ns], "TLS configured")
		}
	}

	return ingressConfig, nil
}

func GetExposedServices(namespaces []string) (map[string][]string, error) {
	exposedServices := make(map[string][]string)

	for _, ns := range namespaces {
		cmd := exec.Command("kubectl", "get", "svc", "-n", ns, "-o", "jsonpath={.items[*].spec.type}")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("error fetching services for namespace %s: %v", ns, err)
		}

		services := strings.Fields(string(output))
		for _, svc := range services {
			if svc == "LoadBalancer" || svc == "NodePort" {
				exposedServices[ns] = append(exposedServices[ns], svc)
			}
		}
	}

	return exposedServices, nil
}

// getHighRestarts obtiene los pods con más de 5 reinicios en los namespaces proporcionados
func GetHighRestarts(namespaces []string) ([]map[string]interface{}, error) {
	var highRestartPods []map[string]interface{}

	for _, namespace := range namespaces {
		cmd := exec.Command("kubectl", "get", "pods", "-n", namespace, "-o", "jsonpath={range .items[*]}{.metadata.name}{','}{.status.containerStatuses[*].restartCount}{'\\n'}{end}")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, err
		}

		pods := strings.Split(string(output), "\n")
		for _, pod := range pods {
			if pod == "" {
				continue
			}
			podDetails := strings.Split(pod, ",")
			if len(podDetails) < 2 {
				continue
			}

			podName := podDetails[0]
			restartCount := strings.TrimSpace(podDetails[1])
			if restarts, err := parseRestartCount(restartCount); err == nil && restarts > 5 {
				highRestartPods = append(highRestartPods, map[string]interface{}{
					"pod_name":  podName,
					"restarts":  restarts,
					"namespace": namespace,
				})
			}
		}
	}

	return highRestartPods, nil
}

// getNamespacesFromNode obtiene los namespaces que están asociados con un nodo específico
func getNamespacesFromNode(node string) ([]string, error) {
	// Ejecutar kubectl para obtener los pods en un nodo específico
	cmd := exec.Command("kubectl", "get", "pods", "--field-selector=spec.nodeName="+node, "-o", "jsonpath={range .items[*]}{.metadata.namespace}{'\\n'}{end}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	// Convertir la salida a un array de namespaces únicos
	namespaces := strings.Split(string(output), "\n")
	namespaceSet := make(map[string]bool)
	for _, ns := range namespaces {
		if ns != "" {
			namespaceSet[ns] = true
		}
	}

	// Extraer los namespaces únicos
	uniqueNamespaces := []string{}
	for ns := range namespaceSet {
		uniqueNamespaces = append(uniqueNamespaces, ns)
	}

	return uniqueNamespaces, nil
}

// parseRestartCount convierte la cadena de reinicios en un entero
func parseRestartCount(restartStr string) (int, error) {
	var restarts int
	_, err := fmt.Sscanf(restartStr, "%d", &restarts)
	return restarts, err
}

// saveReport guarda el reporte en un archivo JSON
func saveReport(filename string, data map[string]interface{}) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// BasicAnalysisMenu permite al usuario seleccionar si el análisis será para un nodo, namespace o el clúster completo
func BasicAnalysisMenu(returnToMenuFunc func()) {
	target := GetTarget("basic")
	BasicAnalysis(target, "entire_cluster")
	returnToMenuFunc() // Volver al menú principal
}
