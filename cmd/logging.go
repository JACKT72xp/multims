package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Define el comando logging
var loggingCmd = &cobra.Command{
	Use:   "logging",
	Short: "Manage Kubernetes logging",
	Long:  `The logging command allows you to configure and view logs from Kubernetes deployments.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Logging: You can configure or view logs from Kubernetes.")
		// Aquí añades el código que ejecutará las funcionalidades de logging
	},
}

func init() {
	rootCmd.AddCommand(loggingCmd)
}
