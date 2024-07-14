package initialize

import (
	"bufio"
	"fmt"
	"multims/pkg/config"
	"os"
	"strconv"
	"strings"
)

func HandleUserInput() (command string, port int, err error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("Please enter the command to start your application (default: %s): ", defaultCommand)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", 0, fmt.Errorf(errorReadingInput, err)
	}
	command = strings.TrimSpace(input)
	if command == "" {
		command = defaultCommand
	}

	reader2 := bufio.NewReader(os.Stdin)
	fmt.Printf("Please enter the number of port to start your application (default: %s): ", defaultCommandPort)
	input2, err := reader2.ReadString('\n')
	if err != nil {
		return "", 0, fmt.Errorf(errorReadingInput, err)
	}
	port, err = strconv.Atoi(strings.TrimSuffix(input2, "\n"))
	if err != nil {
		return "", 0, fmt.Errorf(errorConvertingPort, err)
	}

	return command, port, nil
}

func GetAWSConfig() (accountID string, region string, err error) {
	accountID, region, err = config.GetAWSAccountInfo()
	if err != nil {
		return "", "", fmt.Errorf(errorAWSAccountInfo, err)
	}
	return accountID, region, nil
}
