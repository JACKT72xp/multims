package operations

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

// CloudCredentials almacena las credenciales de acceso a la nube
type CloudCredentials struct {
	AccessKey string `json:"accesskey"`
	SecretKey string `json:"secretkey"`
}

// CreateApplication crea una nueva aplicación llamando al endpoint API
func CreateApplication(appName string) bool {
	configDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error finding home directory:", err)
		return false
	}
	configPath := filepath.Join(configDir, ".multims")

	// Leer y validar el contenido del archivo
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		fmt.Println("Error reading credentials file:", err)
		return false
	}

	var credentials CloudCredentials
	if err := json.Unmarshal(data, &credentials); err != nil || credentials.AccessKey == "" || credentials.SecretKey == "" {
		return false // Formato incorrecto o credenciales incompletas
	}
	// Concatenar las credenciales y codificar en Base64
	authString := fmt.Sprintf("%s;%s", credentials.AccessKey, credentials.SecretKey)
	authEncoded := base64.StdEncoding.EncodeToString([]byte(authString))

	data2 := map[string]interface{}{
		"name": appName,
	}
	jsonData, err := json.Marshal(data2)
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
		return false
	}

	// Enviar la solicitud POST a la API de creación de aplicaciones
	req, err := http.NewRequest("POST", "http://localhost:3000/api/v1/applications/create", bytes.NewBuffer(jsonData))
	req.Header.Set("AuthorizationCli", authEncoded)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func GetCloudCredentials() *CloudCredentials {
	credentials := &CloudCredentials{}

	// Solicitar accesskey y secretkey al usuario
	fmt.Print("Enter Access Key: ")
	fmt.Scanln(&credentials.AccessKey)
	fmt.Print("Enter Secret Key: ")
	fmt.Scanln(&credentials.SecretKey)

	// Concatenar las credenciales y codificar en Base64
	authString := fmt.Sprintf("%s;%s", credentials.AccessKey, credentials.SecretKey)
	authEncoded := base64.StdEncoding.EncodeToString([]byte(authString))

	// Crear la solicitud HTTP con el header AuthorizationCli
	req, err := http.NewRequest("POST", "http://localhost:3000/cli/v1/valid", nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil
	}
	req.Header.Set("AuthorizationCli", authEncoded)
	req.Header.Set("Content-Type", "application/json")

	// Realizar la solicitud HTTP
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		return nil
	}
	defer resp.Body.Close()

	// Verificar el estado de la respuesta
	if resp.StatusCode != http.StatusOK {
		fmt.Println("Authentication failed. Please check your access and secret keys.")
		return nil
	}

	// Guardar credenciales si la autenticación es exitosa
	saveCredentials(credentials)

	return credentials
}

// saveCredentials guarda las credenciales en el archivo ~/.multims
func saveCredentials(credentials *CloudCredentials) {
	configDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error finding home directory:", err)
		return
	}
	configPath := filepath.Join(configDir, ".multims")

	// Convertir las credenciales a JSON
	data, err := json.Marshal(credentials)
	if err != nil {
		fmt.Println("Error encoding credentials:", err)
		return
	}

	// Guardar el archivo
	if err := ioutil.WriteFile(configPath, data, 0600); err != nil {
		fmt.Println("Error writing credentials to file:", err)
		return
	}

	fmt.Println("✔ Credentials saved successfully.")
}

// LoadCredentials carga las credenciales desde el archivo ~/.multims
func LoadCredentials() (*CloudCredentials, error) {
	configDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("error finding home directory: %w", err)
	}
	configPath := filepath.Join(configDir, ".multims")

	// Leer el archivo
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("error reading credentials file: %w", err)
	}

	// Deserializar las credenciales
	var credentials CloudCredentials
	if err := json.Unmarshal(data, &credentials); err != nil {
		return nil, fmt.Errorf("error decoding credentials: %w", err)
	}

	return &credentials, nil
}
