package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var localFlag string

var localCmd = &cobra.Command{
	Use:   "local",
	Short: "Run the multims environment",
	Long:  `Initialize the multims environment by setting up necessary configurations and directories.`,
	Run:   local,
}

func init() {
	runCmd.Flags().StringVar(&localFlag, "local", "onlyoneservice", "Specify the type of service to run (multiservice or onlyoneservice)")
}

func local(cmd *cobra.Command, args []string) {
	switch localFlag {
	case "docker-compose":
		fmt.Println("Running in multi-service mode.")
	case "docker-run":
		// El código para manejar onlyoneservice aquí
		fmt.Println("Running in multi-service mode.")
	default:
		fmt.Println("Unexpected type value. Running default single-service mode.")
	}
}
