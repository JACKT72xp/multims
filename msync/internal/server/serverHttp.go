package server

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

// StartServerHTTP starts the HTTP server with a file upload and health check endpoint
func StartServerHTTP(port, directory string) {
	// File upload handler
	http.HandleFunc("/upload", uploadHandler(directory))

	// Health check handler
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})

	log.Printf("Starting HTTP server on port %s...", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func uploadHandler(directory string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		relPath := r.Header.Get("X-File-Name") // Recibe el path relativo desde el cliente

		// Obtén el path absoluto en el servidor donde se debe guardar el archivo
		destPath := filepath.Join(directory, relPath)

		// Crea el directorio necesario si no existe
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			http.Error(w, fmt.Sprintf("failed to create directory: %v", err), http.StatusInternalServerError)
			return
		}

		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to read file: %v", err), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		out, err := os.Create(destPath)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create file: %v", err), http.StatusInternalServerError)
			return
		}
		defer out.Close()

		if _, err := io.Copy(out, file); err != nil {
			http.Error(w, fmt.Sprintf("failed to write file: %v", err), http.StatusInternalServerError)
			return
		}

		log.Printf("File uploaded successfully: %s", destPath)
		w.WriteHeader(http.StatusOK)
	}
}
