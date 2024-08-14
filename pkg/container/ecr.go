package container

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

func LoginECR() *ecr.Client {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := ecr.NewFromConfig(cfg)
	return client
}

func GetAuthorizationToken(client *ecr.Client) string {
	input := &ecr.GetAuthorizationTokenInput{}
	result, err := client.GetAuthorizationToken(context.TODO(), input)
	if err != nil {
		log.Fatalf("failed to get authorization token, %v", err)
	}

	for _, data := range result.AuthorizationData {
		return aws.ToString(data.AuthorizationToken)
	}
	return ""
}

func GetECRLogin() (string, string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
		return "", "", err
	}

	client := ecr.NewFromConfig(cfg)
	input := &ecr.GetAuthorizationTokenInput{}
	result, err := client.GetAuthorizationToken(context.TODO(), input)
	if err != nil {
		log.Fatalf("failed to get authorization token, %v", err)
		return "", "", err
	}

	if len(result.AuthorizationData) > 0 {
		token := *result.AuthorizationData[0].AuthorizationToken
		server := *result.AuthorizationData[0].ProxyEndpoint
		return token, server, nil
	}

	return "", "", fmt.Errorf("no authorization data received")
}
func CheckRepository(repoName string) bool {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("Unable to load SDK config: %v", err)
	}

	ecrClient := ecr.NewFromConfig(cfg)

	_, err = ecrClient.DescribeRepositories(context.TODO(), &ecr.DescribeRepositoriesInput{
		RepositoryNames: []string{repoName},
	})

	if err != nil {
		// Verificar si el error es del tipo RepositoryNotFoundException
		if strings.Contains(err.Error(), "RepositoryNotFoundException") {
			log.Println("Repository does not exist")
			return false
		} else {
			log.Fatalf("Failed to describe repository: %v", err)
		}
	} else {
		log.Println("Repository exists")
		return true
	}

	// Si llegamos aquí, ha ocurrido un error inesperado
	return false
}

func CreateRepository(repoName string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return err
	}

	ecrClient := ecr.NewFromConfig(cfg)

	_, err = ecrClient.CreateRepository(context.TODO(), &ecr.CreateRepositoryInput{
		RepositoryName: aws.String(repoName),
	})

	return err
}
