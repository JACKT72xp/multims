package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// configCmd represents the command to manage Kubernetes configurations
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage Kubernetes configurations",
	Long:  `Manage your Kubernetes configurations including contexts and credentials.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Config command not implemented yet")
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
