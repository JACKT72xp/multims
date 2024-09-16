package security

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

type Config struct {
	KubernetesContext string `yaml:"kubernetesContext"`
}

// LoadConfig loads the multims.yml file and returns the Kubernetes context.
func LoadConfig() (Config, error) {
	var config Config
	file, err := os.Open("multims.yml")
	if err != nil {
		return config, fmt.Errorf("could not open multims.yml: %v", err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return config, fmt.Errorf("could not read multims.yml: %v", err)
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return config, fmt.Errorf("could not parse multims.yml: %v", err)
	}

	return config, nil
}

// GetContext returns the Kubernetes context from the configuration.
func GetContext() (string, error) {
	config, err := LoadConfig()
	if err != nil {
		return "", err
	}
	if config.KubernetesContext == "" {
		return "", fmt.Errorf("no kubernetesContext found in multims.yml")
	}
	return config.KubernetesContext, nil
}

func ThirdPartyTool(toolName, target, context, analysisType string) {
	fmt.Printf("Running %s analysis for %s (%s)...\n", toolName, target, analysisType)

	var cmd *exec.Cmd

	fmt.Println("Running third-party tool analysis...", context)

	// Definir los comandos según el análisis seleccionado
	if toolName == "trivy" {
		if analysisType == "entire_cluster" {
			// Comando para todo el clúster con el contexto desde multims.yml
			cmd = exec.Command("trivy", "k8s", context, "--report", "summary", "--timeout", "60m")
			fmt.Printf("Executing command: trivy k8s %s --report summary --timeout 60m\n", context)
		} else if analysisType == "namespace" {
			// Comando para un namespace específico usando --include-namespaces
			cmd = exec.Command("trivy", "k8s", context, "--report", "summary", "--include-namespaces", target, "--timeout", "60m")
			fmt.Printf("Executing command: trivy k8s %s --report summary --include-namespaces %s --timeout 60m\n", context, target)
		} else {
			fmt.Println("Invalid analysis type for trivy.")
			return
		}
	} else {
		// Para otras herramientas (kube-hunter, kube-bench), mantener la lógica básica
		cmd = exec.Command(toolName, "scan", target)
		fmt.Printf("Executing command: %s scan %s\n", toolName, target)
	}

	// Ejecutar el comando y capturar el resultado
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running %s: %v\nCommand Output: %s\n", toolName, err, string(output))
		return
	}

	// Crear el directorio adecuado para guardar los resultados
	reportDir := filepath.Join("Reports", "third_party", toolName, analysisType)
	err = os.MkdirAll(reportDir, os.ModePerm)
	if err != nil {
		fmt.Printf("Error creating report directory %s: %v\n", reportDir, err)
		return
	}

	// Guardar el reporte en formato Markdown o JSON
	reportFile := filepath.Join(reportDir, fmt.Sprintf("%s_%s_report.md", target, toolName))
	err = saveImageScanReport(reportFile, string(output))
	if err != nil {
		fmt.Printf("Error saving report for %s: %v\n", toolName, err)
	}

	fmt.Printf("%s analysis completed and saved to %s.\n", toolName, reportFile)
}

// ThirdPartyMenu permite seleccionar una herramienta de terceros para ejecutar
func ThirdPartyMenu(returnToMenuFunc func()) {
	// Cargar el contexto desde multims.yml
	context, err := GetContext()
	if err != nil {
		fmt.Printf("Error loading context from multims.yml: %v\n", err)
		returnToMenuFunc()
		return
	}

	// Obtener los namespaces del clúster
	namespaces, err := GetAllNamespaces()
	if err != nil {
		fmt.Printf("Error fetching namespaces: %v\n", err)
		returnToMenuFunc()
		return
	}

	// Listar los namespaces
	fmt.Println("\nAvailable namespaces:")
	for i, ns := range namespaces {
		fmt.Printf("%d. %s\n", i+1, ns)
	}

	// Preguntar al usuario que elija un namespace
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nChoose a namespace by number or type 'all' for entire cluster: ")
	nsOption, _ := reader.ReadString('\n')
	nsOption = strings.TrimSpace(nsOption)

	// Verificar si se eligió todo el clúster o un namespace específico
	analysisType := ""
	target := ""

	if nsOption == "all" {
		analysisType = "entire_cluster"
		target = context
	} else {
		nsIndex, err := strconv.Atoi(nsOption)
		if err != nil || nsIndex < 1 || nsIndex > len(namespaces) {
			fmt.Println("Invalid option. Returning to menu.")
			returnToMenuFunc()
			return
		}
		analysisType = "namespace"
		target = namespaces[nsIndex-1]
	}

	// Elegir la herramienta de terceros
	fmt.Println("\nSelect a third-party tool:")
	fmt.Println("1. Trivy")
	fmt.Println("2. Kube-Hunter")
	fmt.Println("3. Kube-Bench")

	fmt.Print("\nChoose an option: ")
	toolOption, _ := reader.ReadString('\n')
	toolOption = strings.TrimSpace(toolOption)

	// Ejecutar la herramienta seleccionada
	switch toolOption {
	case "1":
		ThirdPartyTool("trivy", target, context, analysisType)
	case "2":
		ThirdPartyTool("kube-hunter", target, context, analysisType)
	case "3":
		ThirdPartyTool("kube-bench", target, context, analysisType)
	default:
		fmt.Println("Invalid option. Returning to menu.")
	}

	fmt.Println("Third-party tool analysis completed.")
	returnToMenuFunc() // Volver al menú principal
}

type TrivyReport struct {
	Target          string `json:"Target"`
	Vulnerabilities []struct {
		VulnerabilityID  string `json:"VulnerabilityID"`
		PkgName          string `json:"PkgName"`
		InstalledVersion string `json:"InstalledVersion"`
		Severity         string `json:"Severity"`
		Description      string `json:"Description"`
	} `json:"Vulnerabilities"`
}

func ThirdPartyToolAnalysis(context string, scope string, isNamespaceScope bool, returnToMenu func()) {
	// Preguntar al usuario qué herramienta de terceros desea usar
	tool := chooseThirdPartyTool()

	// Dependiendo de la herramienta seleccionada, ejecutar el comando correspondiente
	switch tool {
	case "trivy":
		RunTrivy(context, scope, isNamespaceScope) // Llamada corregida con el argumento adicional
	case "kube-hunter":
		runKubeHunter(scope)
	case "kube-bench":
		runKubeBench(scope)
	default:
		fmt.Println("Invalid tool choice. Returning to main menu.")
		returnToMenu()
	}
}

// chooseThirdPartyTool permite al usuario seleccionar la herramienta de terceros que desea usar
func chooseThirdPartyTool() string {
	fmt.Println("Select a third-party tool:")
	fmt.Println("1. Trivy")
	fmt.Println("2. Kube-Hunter")
	fmt.Println("3. Kube-Bench")

	var option string
	fmt.Print("Choose an option: ")
	fmt.Scanln(&option)

	switch option {
	case "1":
		return "trivy"
	case "2":
		return "kube-hunter"
	case "3":
		return "kube-bench"
	default:
		return ""
	}
}

func generateMarkdownReport(report TrivyReport) []byte {
	mdContent := fmt.Sprintf("# Trivy Report for %s\n\n", report.Target)
	if len(report.Vulnerabilities) == 0 {
		mdContent += "## No vulnerabilities found.\n"
	} else {
		mdContent += "## Vulnerabilities found:\n"
		for _, vuln := range report.Vulnerabilities {
			mdContent += fmt.Sprintf("### Vulnerability ID: %s\n", vuln.VulnerabilityID)
			mdContent += fmt.Sprintf("- **Package**: %s\n", vuln.PkgName)
			mdContent += fmt.Sprintf("- **Installed Version**: %s\n", vuln.InstalledVersion)
			mdContent += fmt.Sprintf("- **Severity**: %s\n", vuln.Severity)
			mdContent += fmt.Sprintf("- **Description**: %s\n\n", vuln.Description)
		}
	}
	return []byte(mdContent)
}

// Ejecutar Trivy con el alcance especificado y guardar el resultado en un archivo Markdown
func RunTrivy(context string, scope string, isNamespaceScope bool) {
	fmt.Printf("Running Trivy analysis for %s...\n", scope)

	var cmd *exec.Cmd

	// Si es un análisis para el namespace, utilizar el comando adecuado.
	if isNamespaceScope {
		cmd = exec.Command("trivy", "k8s", context, "--include-namespaces", scope, "--format", "json", "--timeout", "60m")
	} else {
		cmd = exec.Command("trivy", "k8s", context, "--format", "json", "--timeout", "60m")
	}

	// Capturar salida combinada (stdout y stderr) para depuración
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running Trivy: %v\nOutput: %s\n", err, string(output))
		return
	}

	// Parsear la salida de JSON
	var report TrivyReport
	err = json.Unmarshal(output, &report)
	if err != nil {
		fmt.Printf("Error parsing Trivy JSON output: %v\n", err)
		return
	}

	// Crear el archivo de resumen Markdown
	currentTime := time.Now()
	fileName := fmt.Sprintf("trivy_report_%s_%02d%02d%02d.md", scope, currentTime.Hour(), currentTime.Minute(), currentTime.Second())

	// Guardar el archivo en formato Markdown
	err = ioutil.WriteFile(filepath.Join("reports", fileName), generateMarkdownReport(report), 0644)
	if err != nil {
		fmt.Printf("Error saving Trivy report to file: %v\n", err)
		return
	}

	fmt.Printf("Trivy analysis completed. Report saved as %s\n", fileName)
}

// Ejecutar Trivy con el alcance especificado
// Ejecutar Trivy con el alcance especificado y guardar el resultado en un archivo JSON

// func printTrivySummary(report TrivyReport) {
// 	fmt.Printf("Target: %s\n", report.Target)
// 	if len(report.Vulnerabilities) == 0 {
// 		fmt.Println("No vulnerabilities found.")
// 		return
// 	}

// 	fmt.Println("Vulnerabilities found:")
// 	for _, vuln := range report.Vulnerabilities {
// 		fmt.Printf("- ID: %s\n  Package: %s\n  Version: %s\n  Severity: %s\n  Description: %s\n\n",
// 			vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion, vuln.Severity, vuln.Description)
// 	}
// }

// Ejecutar Kube-Hunter con el alcance especificado
func runKubeHunter(scope string) {
	fmt.Printf("Running Kube-Hunter analysis for %s...\n", scope)
	cmd := exec.Command("kube-hunter", "--remote", scope)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running Kube-Hunter: %v\nOutput: %s\n", err, string(output))
		return
	}

	fmt.Printf("Kube-Hunter Output:\n%s\n", string(output))
}

// Ejecutar Kube-Bench con el alcance especificado
func runKubeBench(scope string) {
	fmt.Printf("Running Kube-Bench analysis for %s...\n", scope)
	cmd := exec.Command("kube-bench", "--kubeconfig", scope)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running Kube-Bench: %v\nOutput: %s\n", err, string(output))
		return
	}

	fmt.Printf("Kube-Bench Output:\n%s\n", string(output))
}
