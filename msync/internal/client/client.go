package client

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
)

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
func RunClient(directory string, address string, port string, excludePatterns []string, useTLS bool, certFile string) {
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
