package initialize

const (
	defaultCommand      = "node index.js"
	defaultCommandPort  = "3000"
	welcomeMessage      = "Welcome to MULTIMS by JT. Manage your Kubernetes clusters effectively."
	operationCancelled  = "Operation cancelled by the user."
	errorReadingInput   = "Error reading input: %v"
	errorConvertingPort = "Error converting port input: %v"
	errorGettingDir     = "Error getting current directory: %v"
	errorAWSAccountInfo = "Failed to retrieve AWS account info: %v"
)

// Opciones para la selección de tecnología y registro
var (
	TechnologyOptions = []string{"Node", "Node-Typescript", "Python", "Cancel"}
	RegistryOptions   = []string{"DockerHub", "AWS ECR", "Cancel"}
)
