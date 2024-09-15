package security

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// saveReport guarda un informe de análisis en formato JSON
func SaveReport(fileName string, report map[string]interface{}) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// saveThirdPartyReport guarda el informe de una herramienta de terceros
func SaveThirdPartyReport(filename string, tool string, output string) error {
	report := map[string]interface{}{
		"tool":   tool,
		"output": output,
		"status": "Third-party analysis complete",
	}

	return SaveReport(filename, report)
}

// GetAllNamespaces obtiene todos los namespaces del clúster
func GetAllNamespaces() ([]string, error) {
	// Ejecutar el comando kubectl para obtener los namespaces
	cmd := exec.Command("kubectl", "get", "ns", "-o", "jsonpath={.items[*].metadata.name}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error running kubectl command: %v", err)
	}

	// Convertir la salida en una lista de namespaces
	namespaces := strings.Fields(string(output))

	if len(namespaces) == 0 {
		return nil, fmt.Errorf("no namespaces found")
	}

	return namespaces, nil
}

func GetTarget(analysisType string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("\nDo you want to analyze an entire cluster, a specific node, or a namespace for %s?\n", analysisType)
	fmt.Println("1. Entire cluster")
	fmt.Println("2. Specific node")
	fmt.Println("3. Specific namespace")

	fmt.Print("\nChoose an option: ")
	option, _ := reader.ReadString('\n')
	option = strings.TrimSpace(option)

	var target string
	switch option {
	case "1":
		target = "entire_cluster"
	case "2":
		fmt.Print("\nEnter the node name: ")
		nodeName, _ := reader.ReadString('\n')
		target = "node_" + strings.TrimSpace(nodeName)
	case "3":
		fmt.Print("\nEnter the namespace name: ")
		namespace, _ := reader.ReadString('\n')
		target = "namespace_" + strings.TrimSpace(namespace)
	default:
		fmt.Println("Invalid option. Defaulting to entire cluster.")
		target = "entire_cluster"
	}

	return target
}

func GetNamespaceSelection() (string, error) {
	namespaces, err := GetAllNamespaces()
	if err != nil {
		return "", err
	}

	fmt.Println("Available namespaces:")
	for i, ns := range namespaces {
		fmt.Printf("%d. %s\n", i+1, ns)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Choose a namespace by number: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	selection, err := strconv.Atoi(input)
	if err != nil || selection < 1 || selection > len(namespaces) {
		return "", fmt.Errorf("invalid selection")
	}

	return namespaces[selection-1], nil
}
