package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "multims",
	Short: "Multims is a CLI tool for managing Kubernetes",
	Long:  `Multims by JT. A CLI tool to interact with Kubernetes and manage deployments.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}

// Aquí deberías incluir la inicialización de subcomandos
func init() {
	// Aquí añadirías tus subcomandos, por ejemplo:
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(uiCmd)
	// Etc...
}
