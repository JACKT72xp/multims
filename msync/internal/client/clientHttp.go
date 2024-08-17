package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
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

// shouldExcludeHttp checks if a file should be excluded based on the exclusion patterns
func shouldExcludeHttp(relPath string, excludePatterns []string) bool {
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
