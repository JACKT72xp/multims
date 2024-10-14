package auth

import (
	"log"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
)

func checkECRLogin() bool {
	sess, err := session.NewSession()
	if err != nil {
		log.Println("Error creating AWS session:", err)
		return false
	}

	svc := ecr.New(sess)
	_, err = svc.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		log.Println("Failed to authenticate to AWS ECR:", err)
		return false
	}
	return true
}

// HandleECRLogin verifica el login en AWS ECR y retorna true si tiene éxito, o false si falla
func HandleECRLogin() bool {
	if !checkECRLogin() {
		log.Println("You need to log in to AWS first.")
		return false
	}
	log.Println("Logged into AWS ECR successfully.")
	return true
}
