package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// NativeMessage representa el mensaje recibido de la extensión de Chrome
type NativeMessage struct {
	Action string `json:"action"`
}

// sendResponse envía una respuesta JSON de vuelta a la extensión
func sendResponse(response map[string]string) {
	responseJSON, _ := json.Marshal(response)
	fmt.Printf("%s", responseJSON)
}

func StartNativeHost() {
	var msg NativeMessage
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&msg); err != nil {
		sendResponse(map[string]string{"status": "error", "message": "Failed to decode message"})
		return
	}

	switch msg.Action {
	case "run_multims_ui":
		cmd := exec.Command("multims", "ui")
		if err := cmd.Start(); err != nil {
			sendResponse(map[string]string{"status": "error", "message": err.Error()})
			return
		}
		sendResponse(map[string]string{"status": "success", "message": "multims ui started"})
	default:
		sendResponse(map[string]string{"status": "error", "message": "Unknown action"})
	}
}
