package auth

import (
    "os/exec"
    "strings"
    "log"
)

// CheckDockerLogin verifica si el usuario está logueado en Docker Hub.
func CheckDockerLogin() bool {
    cmd := exec.Command("docker", "info")
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Println("Error executing docker info:", err)
        return false
    }

    // Verifica si el output contiene indicativos de estar logueado.
    return strings.Contains(string(output), "Username")
}

// HandleDockerLogin maneja la lógica para asegurarse de que el usuario está logueado en Docker Hub.
func HandleDockerLogin() {
    if !CheckDockerLogin() {
        log.Println("You need to log in to Docker Hub first.")
        return
    }
    log.Println("Logged into Docker Hub successfully.")
}
