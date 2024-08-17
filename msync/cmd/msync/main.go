package main

import (
	"flag"
	"log"

	"github.com/jacktorpoco/msync/internal/client"
	"github.com/jacktorpoco/msync/internal/server"
)

func main() {
	// Define flags for operation mode, address, port, and directory
	mode := flag.String("mode", "client", "Operation mode: 'client' or 'server'")
	address := flag.String("address", "localhost", "Server address (for client mode only)")
	port := flag.String("port", "6060", "Port to run the server or connect the client")
	directory := flag.String("directory", "", "Directory to sync (client mode) or the target directory (server mode)")
	excludes := flag.String("exclude", "", "Comma-separated exclude patterns (client mode only)")
	useTLS := flag.Bool("useTLS", false, "Enable TLS for client mode")
	certFile := flag.String("certFile", "", "TLS certificate file (server mode)")

	flag.Parse()

	// Convert exclude patterns into a slice of strings
	excludePatterns := []string{}
	if *excludes != "" {
		excludePatterns = append(excludePatterns, *excludes)
	}
	stateFile := "sync_state.json" // Path to store the sync state

	switch *mode {
	case "client":
		if *directory == "" {
			log.Fatal("You must specify a directory to sync in client mode")
		}
		client.RunClient(*directory, *address, *port, stateFile, excludePatterns)
	case "autoclient":
		if *directory == "" {
			log.Fatal("You must specify a directory to sync in autoclient mode")
		}
		client.AutoClient(*directory, *address, *port, stateFile, excludePatterns)
	case "server":
		if *directory == "" {
			log.Fatal("You must specify a target directory in server mode")
		}
		if *certFile == "" && *useTLS {
			log.Fatal("You must specify certificate files for TLS in server mode")
		}
		if *useTLS {
			server.StartServerWithTLS(*port, *directory, *certFile, "server.key")
		} else {
			server.StartServer(*port, *directory)
		}
	case "clientHttp":
		if *directory == "" {
			log.Fatal("You must specify a directory to sync in clientHttp mode")
		}
		stateFile := "sync_state.json" // Ruta del archivo para almacenar el estado de sincronización
		client.RunClientHTTP(*directory, *address, *port, stateFile, excludePatterns)
	case "serverHttp":
		if *directory == "" {
			log.Fatal("You must specify a target directory in serverHttp mode")
		}
		server.StartServerHTTP(*port, *directory)
	default:
		log.Fatalf("Unknown mode: %s", *mode)
	}
}
