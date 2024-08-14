package cmd

import (
	"fmt"
	"multims/operations"

	"github.com/spf13/cobra"
)

var typeFlag string

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the multims environment",
	Long:  `Initialize the multims environment by setting up necessary configurations and directories.`,
	Run:   run,
}

func init() {
	runCmd.Flags().StringVar(&typeFlag, "type", "onlyoneservice", "Specify the type of service to run (multiservice or onlyoneservice)")
}

func run(cmd *cobra.Command, args []string) {
	switch typeFlag {
	case "multiservice":
		operations.MultiServiceHandler()
		fmt.Println("Running in multi-service mode.")
	case "onlyoneservice":
		// El código para manejar onlyoneservice aquí
		operations.OnlyOneServiceHandlerV2()
	default:
		fmt.Println("Unexpected type value. Running default single-service mode.")
		operations.OnlyOneServiceHandlerV2() // Aquí puedes reutilizar la misma función para manejar onlyoneservice
	}
}
