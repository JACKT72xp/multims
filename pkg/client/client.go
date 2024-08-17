package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type SyncStateHttp struct {
	FileHashes map[string]string `json:"file_hashes"`
	mu         sync.Mutex        // Mutex para proteger el mapa
}

// sendFile se encarga de enviar un archivo específico al servidor
func sendFile(conn net.Conn, filePath string, rootDir string) error {
	relPath, err := filepath.Rel(rootDir, filePath)
	if err != nil {
		return err
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	fileNameBytes := []byte(relPath)
	fileNameLength := int64(len(fileNameBytes))

	// Enviar longitud y nombre del archivo
	if err := binary.Write(conn, binary.LittleEndian, fileNameLength); err != nil {
		return err
	}
	if _, err := conn.Write(fileNameBytes); err != nil {
		return err
	}

	// Enviar tamaño del archivo
	if err := binary.Write(conn, binary.LittleEndian, fileInfo.Size()); err != nil {
		return err
	}

	// Enviar contenido del archivo
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := io.Copy(conn, file); err != nil {
		return err
	}

	log.Printf("Archivo enviado: %s", relPath)
	return nil
}

// sendFileList envía la lista de archivos al servidor
func sendFileList(conn net.Conn, fileList []string) error {
	for _, file := range fileList {
		fileBytes := []byte(file)
		fileLength := int64(len(fileBytes))

		// Enviar longitud y nombre del archivo
		if err := binary.Write(conn, binary.LittleEndian, fileLength); err != nil {
			return err
		}
		if _, err := conn.Write(fileBytes); err != nil {
			return err
		}
	}

	// Enviar un marcador para indicar el final de la lista (un archivo de longitud 0)
	if err := binary.Write(conn, binary.LittleEndian, int64(0)); err != nil {
		return err
	}

	return nil
}

func shouldExclude(relPath string, excludePatterns []string) bool {
	if relPath == "sync_state.json" || relPath == "msync.log" || relPath == "portforward.log" {
		return true
	}
	log.Printf("Evaluating exclusion for: %s", relPath)

	// Split the excludePatterns string into individual patterns
	var patterns []string
	for _, pattern := range excludePatterns {
		patterns = append(patterns, strings.Split(pattern, ",")...)
	}

	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		log.Printf("Checking against pattern: %s", pattern)

		// Excluir si `relPath` comienza con el patrón (para directorios como ".git/" o "node_modules/")
		if strings.HasPrefix(relPath, pattern) {
			log.Printf("Excluding based on prefix pattern: %s", pattern)
			return true
		}

		// Excluir si `relPath` contiene el patrón en cualquier parte de la ruta (para directorios y subdirectorios)
		if strings.Contains(relPath, pattern) {
			log.Printf("Excluding based on contains pattern: %s", pattern)
			return true
		}

		// Excluir si `relPath` termina con el patrón (para archivos como "*.log")
		if strings.HasSuffix(relPath, strings.TrimPrefix(pattern, "*")) {
			log.Printf("Excluding based on suffix pattern: %s", pattern)
			return true
		}
	}

	log.Printf("Not excluded: %s", relPath)
	return false
}

// RunClient inicia el cliente de sincronización
// func RunClient(directory string, address string, port string, excludePatterns []string, useTLS bool, certFile string) {
// 	var conn net.Conn
// 	var err error

// 	if useTLS {
// 		// Manejo de la conexión TLS omitido por brevedad...
// 	} else {
// 		conn, err = net.Dial("tcp", net.JoinHostPort(address, port))
// 		if err != nil {
// 			log.Fatalf("Error connecting to server: %v", err)
// 		}
// 	}

// 	defer conn.Close()

// 	var fileList []string

// 	err = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
// 		if err != nil {
// 			return err
// 		}

// 		relPath, _ := filepath.Rel(directory, path)
// 		if info.IsDir() {
// 			relPath += "/"
// 		}

// 		if shouldExclude(relPath, excludePatterns) {
// 			return nil
// 		}

// 		if !info.IsDir() {
// 			fileList = append(fileList, relPath)
// 			if err := sendFile(conn, path, directory); err != nil {
// 				log.Printf("Error sending file %s: %v", path, err)
// 				return err
// 			}
// 		}
// 		return nil
// 	})

// 	if err != nil {
// 		log.Fatalf("Error walking the directory: %v", err)
// 	}

// 	// Enviar la lista de archivos al servidor
// 	log.Println("Sending file list to server:", fileList)
// 	if err := sendFileList(conn, fileList); err != nil {
// 		log.Fatalf("Error sending file list: %v", err)
// 	}

// 	log.Println("Synchronization complete.")
// }

func RunClient(directory, address, port string, excludePatterns []string, useTLS bool, certFile string, logFilePath string) {
	var conn net.Conn
	var err error

	if useTLS {
		// Manejo de la conexión TLS omitido por brevedad...
	} else {
		conn, err = net.Dial("tcp", net.JoinHostPort(address, port))
		if err != nil {
			log.Fatalf("Error connecting to server: %v", err)
		}
	}

	defer conn.Close()

	var fileList []string

	err = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(directory, path)
		if info.IsDir() {
			relPath += "/"
		}

		if shouldExclude(relPath, excludePatterns) {
			return nil
		}

		if !info.IsDir() {
			fileList = append(fileList, relPath)
			if err := sendFile(conn, path, directory); err != nil {
				log.Printf("Error sending file %s: %v", path, err)
				return err
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Error walking the directory: %v", err)
	}

	// Enviar la lista de archivos al servidor
	log.Println("Sending file list to server:", fileList)
	if err := sendFileList(conn, fileList); err != nil {
		log.Fatalf("Error sending file list: %v", err)
	}

	log.Println("Synchronization complete.")
}

// syncFileHTTP compares and syncs a file if it has changed
func syncFileHTTP(url, filePath string, state *SyncStateHttp, rootDir string) error {
	relPath, err := filepath.Rel(rootDir, filePath)
	if err != nil {
		return fmt.Errorf("failed to get relative path: %w", err)
	}

	localHash, err := calculateFileHash(filePath)
	if err != nil {
		return fmt.Errorf("failed to calculate local hash: %w", err)
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	if previousHash, exists := state.FileHashes[relPath]; exists && previousHash == localHash {
		log.Printf("File unchanged, skipping sync: %s", relPath)
		return nil
	}

	log.Printf("Syncing file: %s", filePath)
	if err := uploadFileHTTP(url, filePath, relPath); err != nil {
		return err
	}

	// Update the state with the new hash
	state.FileHashes[relPath] = localHash
	return nil
}

// calculateFileHash calculates the SHA-256 hash of a file
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// LoadStateHttp loads the previous sync state from a file
func LoadStateHttp(stateFile string) (*SyncStateHttp, error) {
	file, err := os.Open(stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &SyncStateHttp{FileHashes: make(map[string]string)}, nil
		}
		return nil, err
	}
	defer file.Close()

	var state SyncStateHttp
	if err := json.NewDecoder(file).Decode(&state); err != nil {
		return nil, err
	}

	return &state, nil
}

// SaveState saves the current sync state to a file
func SaveState(stateFile string, state *SyncStateHttp) error {
	state.mu.Lock()
	defer state.mu.Unlock()

	file, err := os.Create(stateFile)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(state)
}

// uploadFileHTTP uploads a file to the HTTP server
func uploadFileHTTP(url, filePath, relPath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var b bytes.Buffer
	writer := multipart.NewWriter(&b)

	part, err := writer.CreateFormFile("file", relPath) // Usa el path relativo
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return fmt.Errorf("failed to copy file content: %w", err)
	}

	writer.Close()

	req, err := http.NewRequest("POST", url, &b)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-File-Name", relPath) // Usa el path relativo

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-200 status: %s", resp.Status)
	}

	log.Printf("Successfully uploaded file: %s", filePath)
	return nil
}

// shouldExcludeHttp checks if a file should be excluded based on the exclusion patterns
func shouldExcludeHttp(relPath string, excludePatterns []string) bool {
	// Excluir sync_state.json explícitamente
	if relPath == "sync_state.json" {
		return true
	}
	log.Printf("Evaluating exclusion for: %s", relPath)

	var patterns []string
	for _, pattern := range excludePatterns {
		patterns = append(patterns, strings.Split(pattern, ",")...)
	}

	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		log.Printf("Checking against pattern: %s", pattern)

		if strings.HasPrefix(relPath, strings.TrimSuffix(pattern, "/")) {
			log.Printf("Excluding based on prefix pattern: %s", pattern)
			return true
		}

		if strings.Contains(relPath, strings.TrimPrefix(pattern, "*")) {
			log.Printf("Excluding based on contains pattern: %s", pattern)
			return true
		}

		if strings.HasSuffix(relPath, strings.TrimPrefix(pattern, "*")) {
			log.Printf("Excluding based on suffix pattern: %s", pattern)
			return true
		}
	}

	log.Printf("Not excluded: %s", relPath)
	return false
}

// WatchAndSyncHTTP monitors the directory for changes and syncs files as they change
func WatchAndSyncHTTP(directory, address, port, stateFile string, excludePatterns []string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Failed to create watcher: %v", err)
	}
	defer watcher.Close()

	state, err := LoadStateHttp(stateFile)
	if err != nil {
		log.Fatalf("Failed to load sync state: %v", err)
	}

	serverURL := fmt.Sprintf("http://%s:%s", address, port)

	err = watcher.Add(directory)
	if err != nil {
		log.Fatalf("Failed to watch directory: %v", err)
	}

	var mutex sync.Mutex
	done := make(chan bool)

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
					mutex.Lock()
					relPath, _ := filepath.Rel(directory, event.Name)
					if shouldExcludeHttp(relPath, excludePatterns) {
						mutex.Unlock()
						continue
					}
					log.Printf("Detected change: %s", event.Name)
					if err := syncFileHTTP(serverURL+"/upload", event.Name, state, directory); err != nil {
						log.Printf("Error syncing file %s: %v", event.Name, err)
					}
					SaveState(stateFile, state)
					mutex.Unlock()
				}
			case err := <-watcher.Errors:
				log.Printf("Watcher error: %v", err)
			}
		}
	}()

	<-done // Block indefinitely to keep the watcher running
}

// RunClientHTTP starts the HTTP client, loads sync state, and syncs files to the server
func RunClientHTTP(directory, address, port, stateFile string, excludePatterns []string) {
	state, err := LoadStateHttp(stateFile)
	if err != nil {
		log.Fatalf("Failed to load sync state: %v", err)
	}

	serverURL := fmt.Sprintf("http://%s:%s", address, port)

	var wg sync.WaitGroup
	err = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(directory, path)
		if info.IsDir() {
			return nil
		}

		if shouldExcludeHttp(relPath, excludePatterns) {
			return nil
		}

		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			if err := syncFileHTTP(serverURL+"/upload", path, state, directory); err != nil {
				log.Printf("Error syncing file %s: %v", path, err)
			}
		}(path)
		time.Sleep(50 * time.Millisecond)

		return nil
	})

	wg.Wait()
	if err != nil {
		log.Fatalf("Error walking the directory: %v", err)
	}

	if err := SaveState(stateFile, state); err != nil {
		log.Fatalf("Failed to save sync state: %v", err)
	}

	log.Println("HTTP Synchronization complete.")

	// Start watching the directory for changes
	WatchAndSyncHTTP(directory, address, port, stateFile, excludePatterns)
}
