package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	chunkSize      = 8 * 1024 * 1024 // 1 MB chunks
	maxRetries     = 3
	retryDelay     = 5 * time.Second
	reconnectDelay = 10 * time.Second
)

type SyncState struct {
	FileHashes map[string]string `json:"file_hashes"`
}

// LoadState loads the previous sync state from a file
func LoadState(stateFile string) (*SyncState, error) {
	file, err := os.Open(stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &SyncState{FileHashes: make(map[string]string)}, nil
		}
		return nil, err
	}
	defer file.Close()

	var state SyncState
	if err := json.NewDecoder(file).Decode(&state); err != nil {
		return nil, err
	}

	return &state, nil
}

// SaveStateHttp saves the current sync state to a file
func SaveStateHttp(stateFile string, state *SyncState) error {
	file, err := os.Create(stateFile)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(state)
}

// getFileHash calculates and returns the SHA-256 hash of a file
func getFileHash(filePath string) (string, error) {
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

// sendFileWithRetry sends a file with retry logic and chunking
func sendFileWithRetry(conn net.Conn, filePath string, rootDir string, address, port string) error {
	var startOffset int64
	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := sendFileInChunks(conn, filePath, rootDir, startOffset)
		if err == nil {
			return nil
		}

		if strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection refused") {
			log.Printf("Error detected while sending file %s. Retrying attempt %d of %d after a delay...", filePath, attempt, maxRetries)

			// Reconnect and retry
			if err := reconnectAndRetry(filePath, rootDir, address, port, startOffset, attempt); err != nil {
				log.Printf("Failed to send file after reconnection: %v", err)
				continue
			}
		} else {
			log.Printf("Error during file transfer: %v", err)
			return err
		}
	}
	return fmt.Errorf("failed to send file %s after %d attempts", filePath, maxRetries)
}

// sendFileInChunks sends a file in chunks to allow for resumable transfers
func sendFileInChunks(conn net.Conn, filePath string, rootDir string, startOffset int64) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Seek to the start offset
	if _, err := file.Seek(startOffset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek file: %w", err)
	}

	relPath, err := filepath.Rel(rootDir, filePath)
	if err != nil {
		return fmt.Errorf("failed to get relative path: %w", err)
	}

	buffer := make([]byte, chunkSize)
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read file: %w", err)
		}
		if n == 0 {
			break
		}

		// Send the chunk
		log.Printf("Sending %d bytes of %s", n, relPath)
		if _, err := conn.Write(buffer[:n]); err != nil {
			return fmt.Errorf("failed to send file chunk: %w", err)
		}

		// Log progress
		log.Printf("Sent %d bytes of %s", n, relPath)
		startOffset += int64(n)

		// Introduce a small delay between chunks to help stabilize the connection
		time.Sleep(100 * time.Millisecond)
	}

	log.Printf("Finished sending file: %s", relPath)
	return nil
}

// syncFileIfChanged checks if the file has changed and syncs it if necessary
func syncFileIfChanged(conn net.Conn, filePath string, rootDir string, state *SyncState, address, port string) error {
	hash, err := getFileHash(filePath)
	if err != nil {
		return fmt.Errorf("failed to calculate file hash: %w", err)
	}

	relPath, err := filepath.Rel(rootDir, filePath)
	if err != nil {
		return fmt.Errorf("failed to get relative path: %w", err)
	}

	// Check if the file has changed since the last sync
	if previousHash, exists := state.FileHashes[relPath]; exists && previousHash == hash {
		log.Printf("File unchanged: %s", relPath)
		return nil // No need to sync
	}

	// Sync the file
	if err := sendFileWithRetry(conn, filePath, rootDir, address, port); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}

	// Update the state with the new file hash
	state.FileHashes[relPath] = hash
	return nil
}

// RunClient starts the synchronization client with more controlled processing
func RunClient(directory string, address string, port string, stateFile string, excludePatterns []string) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, port), 10*time.Second)
	if err != nil {
		log.Fatalf("Error connecting to server: %v", err)
	}
	defer conn.Close()

	state, err := LoadState(stateFile)
	if err != nil {
		log.Fatalf("Error loading sync state: %v", err)
	}

	var fileList []string
	err = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("failed to walk the directory: %w", err)
		}

		relPath, _ := filepath.Rel(directory, path)
		if shouldExclude(relPath, excludePatterns) {
			return nil
		}

		if !info.IsDir() {
			fileList = append(fileList, path)
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Error walking the directory: %v", err)
	}

	// Process the files one by one, or in small chunks
	if err := processFiles(conn, fileList, directory, state, address, port); err != nil {
		log.Fatalf("Error processing files: %v", err)
	}

	if err := SaveStateHttp(stateFile, state); err != nil {
		log.Fatalf("Error saving sync state: %v", err)
	}

	log.Println("Synchronization complete.")
}

// AutoClient monitors a directory for changes and automatically syncs files
func AutoClient(directory string, address string, port string, stateFile string, excludePatterns []string) {
	log.Println("Starting AutoClient...")

	// Perform the initial sync
	RunClient(directory, address, port, stateFile, excludePatterns)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Failed to create watcher: %v", err)
	}

	if err := watcher.Add(directory); err != nil {
		log.Fatalf("Failed to watch directory: %v", err)
	}

	var mutex sync.Mutex
	done := make(chan bool)

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				log.Printf("Detected change: %v", event)
				// Sync if a file is created, written, or removed
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Remove == fsnotify.Remove {
					mutex.Lock()
					go func() {
						RunClient(directory, address, port, stateFile, excludePatterns)
						mutex.Unlock()
					}()
				}
			case err := <-watcher.Errors:
				log.Printf("Watcher error: %v", err)
			}
		}
	}()

	<-done // Block indefinitely to keep the AutoClient running
}

// processFiles processes and sends files one by one
func processFiles(conn net.Conn, fileList []string, rootDir string, state *SyncState, address, port string) error {
	for _, file := range fileList {
		err := syncFileIfChanged(conn, file, rootDir, state, address, port)
		if err != nil {
			log.Printf("Error processing file %s: %v", file, err)
			continue // Skip to the next file
		}
		time.Sleep(100 * time.Millisecond) // Small delay between files to prevent overload
	}
	return nil
}

func shouldExclude(relPath string, excludePatterns []string) bool {
	log.Printf("Evaluating exclusion for: %s", relPath)

	// Split the excludePatterns string into individual patterns
	var patterns []string
	for _, pattern := range excludePatterns {
		patterns = append(patterns, strings.Split(pattern, ",")...)
	}

	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		log.Printf("Checking against pattern: %s", pattern)

		// Exclude if the relPath starts with the pattern (e.g., directories like ".git/")
		if strings.HasPrefix(relPath, strings.TrimSuffix(pattern, "/")) {
			log.Printf("Excluding based on prefix pattern: %s", pattern)
			return true
		}
		// Exclude if relPath contains the pattern (e.g., subdirectories)
		if strings.Contains(relPath, strings.TrimPrefix(pattern, "*")) {
			log.Printf("Excluding based on contains pattern: %s", pattern)
			return true
		}
		// Exclude if relPath ends with the pattern (e.g., files like "*.log")
		if strings.HasSuffix(relPath, strings.TrimPrefix(pattern, "*")) {
			log.Printf("Excluding based on suffix pattern: %s", pattern)
			return true
		}
	}

	log.Printf("Not excluded: %s", relPath)
	return false
}

// reconnectAndRetry retries a file transfer after reconnecting
func reconnectAndRetry(filePath, rootDir, address, port string, startOffset int64, attempt int) error {
	backoff := time.Duration(attempt) * reconnectDelay
	log.Printf("Reconnecting and retrying after %v...", backoff)
	time.Sleep(backoff) // Allow time for port forward to stabilize

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, port), 10*time.Second)
	if err != nil {
		log.Printf("Failed to reconnect: %v", err)
		return fmt.Errorf("failed to reconnect: %w", err)
	}
	defer conn.Close()

	log.Printf("Successfully reconnected. Resuming file transfer from offset %d", startOffset)

	return sendFileInChunks(conn, filePath, rootDir, startOffset)
}
