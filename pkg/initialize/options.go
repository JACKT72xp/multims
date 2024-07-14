package initialize

import (
	"fmt"
	"log"

	"github.com/manifoldco/promptui"
)

func SelectTechnology() string {
	prompt := promptui.Select{
		Label: "Select the technology stack for your project",
		Items: TechnologyOptions,
	}

	_, result, err := prompt.Run()
	if err != nil {
		log.Fatalf("Prompt failed %v\n", err)
	}
	return result
}

func SelectRegistry() string {
	prompt := promptui.Select{
		Label: "Select the container registry to use",
		Items: RegistryOptions,
	}
	_, result, err := prompt.Run()
	if err != nil {
		log.Fatalf("Prompt failed %v\n", err)
	}
	return result
}

func ConfirmSelection(technology, registry string) bool {
	prompt := promptui.Prompt{
		Label:     fmt.Sprintf("Confirm your selections: Technology: %s, Registry: %s (y/n)", technology, registry),
		IsConfirm: true,
	}

	result, err := prompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return false
	}

	return result == "y" || result == "Y"
}
