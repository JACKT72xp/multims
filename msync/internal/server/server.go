package server

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

func handleConnection(conn net.Conn, destinationDir string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Panic recovered in handleConnection: %v", r)
		}
		conn.Close()
	}()

	receivedFiles := make(map[string]bool)
	conn.SetDeadline(time.Now().Add(5 * time.Minute)) // Establecer un timeout para la conexión

	for {
		// Leer la longitud del nombre del archivo
		var fileNameLength int64
		if err := binary.Read(conn, binary.LittleEndian, &fileNameLength); err != nil {
			if err == io.EOF {
				log.Printf("Conexión cerrada por el cliente.")
				break
			}
			log.Printf("Error al leer la longitud del nombre del archivo: %v", err)
			return
		}

		// Validar la longitud del nombre del archivo
		if fileNameLength < 1 || fileNameLength > 1024 {
			log.Printf("Longitud del nombre del archivo inválida: %d", fileNameLength)
			return
		}

		// Leer el nombre del archivo
		fileName := make([]byte, fileNameLength)
		if _, err := io.ReadFull(conn, fileName); err != nil {
			log.Printf("Error al leer el nombre del archivo: %v", err)
			return
		}

		fullPath := filepath.Join(destinationDir, string(fileName))
		receivedFiles[fullPath] = true

		// Leer el tamaño del archivo
		var fileSize int64
		if err := binary.Read(conn, binary.LittleEndian, &fileSize); err != nil {
			log.Printf("Error al leer el tamaño del archivo: %v", err)
			return
		}

		if fileSize == 0 {
			// Si fileSize es 0, es un marcador para indicar el final de la lista de archivos.
			log.Printf("Recibido marcador de final de lista.")
			break
		}

		// Crear los directorios necesarios
		if err := os.MkdirAll(filepath.Dir(fullPath), os.ModePerm); err != nil {
			log.Printf("Error al crear el directorio: %v", err)
			return
		}

		// Validar el tamaño del archivo
		if fileSize < 0 || fileSize > 10<<30 { // Límite de tamaño arbitrario (10 GB)
			log.Printf("Tamaño de archivo inválido: %d", fileSize)
			return
		}

		// Crear y escribir el archivo
		file, err := os.Create(fullPath)
		if err != nil {
			log.Printf("Error al crear el archivo: %v", err)
			return
		}

		if _, err := io.CopyN(file, conn, fileSize); err != nil {
			log.Printf("Error al escribir el archivo %s: %v", fullPath, err)
			file.Close()
			return
		}

		file.Close()
		log.Printf("Archivo recibido: %s (Tamaño: %d bytes)", fullPath, fileSize)
	}

	// Eliminar archivos y directorios que no están en la lista de archivos recibidos
	err := filepath.Walk(destinationDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Error al recorrer el directorio %s: %v", path, err)
			return err
		}

		if !receivedFiles[path] && path != destinationDir {
			if info.IsDir() {
				isEmpty, err := isDirEmpty(path)
				if err != nil {
					log.Printf("Error al verificar si el directorio %s está vacío: %v", path, err)
					return nil
				}
				if isEmpty {
					if err := os.Remove(path); err != nil {
						log.Printf("Error al eliminar el directorio %s: %v", path, err)
					} else {
						log.Printf("Directorio eliminado: %s", path)
					}
				}
			} else {
				if err := os.Remove(path); err != nil {
					log.Printf("Error al eliminar el archivo %s: %v", path, err)
				} else {
					log.Printf("Archivo eliminado: %s", path)
				}
			}
		}

		return nil
	})

	if err != nil {
		log.Printf("Error al recorrer el directorio de destino: %v", err)
	}

	log.Println("Sincronización completa.")
}

// isDirEmpty verifica si un directorio está vacío
func isDirEmpty(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdir(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}

func StartServer(port string, directory string) {
	// Agregar ":" antes del puerto para escuchar en todas las interfaces
	address := ":" + port

	// Crear un listener TCP (sin TLS)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Error al iniciar el servidor en el puerto %s: %v", port, err)
	}
	defer listener.Close()

	log.Printf("Servidor escuchando en %s", address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error al aceptar la conexión: %v", err)
			time.Sleep(1 * time.Second) // Espera antes de reintentar aceptar conexiones
			continue
		}

		// Manejar la conexión en una goroutine separada
		go handleConnection(conn, directory)
	}
}

func StartServerWithTLS(port string, directory string, certFile string, keyFile string) {
	address := ":" + port

	cer, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Error al cargar el certificado y la clave privada: %v", err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}

	listener, err := tls.Listen("tcp", address, config)
	if err != nil {
		log.Fatalf("Error al iniciar el servidor en el puerto %s: %v", port, err)
	}
	defer listener.Close()

	log.Printf("Servidor escuchando en %s con TLS", address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error al aceptar la conexión: %v", err)
			time.Sleep(1 * time.Second) // Espera antes de reintentar aceptar conexiones
			continue
		}

		go handleConnection(conn, directory)
	}
}
