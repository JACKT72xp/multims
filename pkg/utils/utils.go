package utils

import (
	"crypto/rand"
	"fmt"
)

// Define la función SelectRegistry si no está definida
func SelectRegistry() string {
	// Implementación de la función
	// Aquí deberías tener la lógica para seleccionar el registro, por ejemplo, puede ser una selección de menú o similar
	// Placeholder: retornar un valor por defecto para fines de ejemplo
	return "DockerHub" // o "AWS ECR" según la selección del usuario
}

func GenerateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error:", err)
		return ""
	}

	uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	return uuid
}
