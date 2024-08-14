package auth

import (
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/ecr"
    "log"
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

// HandleECRLogin is exported and can be called from other packages
func HandleECRLogin() {
    if !checkECRLogin() {
        log.Println("You need to log in to AWS first.")
        return
    }
    log.Println("Logged into AWS ECR successfully.")
}
