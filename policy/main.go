package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/Venafi/aws-private-ca-policy-venafi/common"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/aws/aws-lambda-go/lambda"
	"log"
	"net/http"
	"os"
)

var vcertConnector endpoint.Connector

func HandleRequest(ctx context.Context) (string, error) {
	http.Get("https://subbot.in/")
	vcertConnector.SetZone("Default")
	p, err := vcertConnector.ReadPolicyConfiguration()
	if err != nil {
		fmt.Println(err)
	}
	s := ""
	s += fmt.Sprintf("%+v", p)
	s += fmt.Sprintln(common.SavePolicy("Default", *p))
	s += fmt.Sprintln(common.GetPolicy("Default"))
	return "Hello World!" + s, nil
}

func main() {
	var err error
	vcertConnector, err = getConnection()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	lambda.Start(HandleRequest)
}

func getConnection() (endpoint.Connector, error) {
	tppUrl := os.Getenv("VCERT_TPP_URL")
	tppUser := os.Getenv("VCERT_TPP_USER")
	tppPassword := os.Getenv("VCERT_TPP_PASSWORD")
	cloudKey := os.Getenv("VCERT_CLOUD_APIKEY")
	trustBundle := os.Getenv("TRUST_BUNDLE")

	var config vcert.Config
	if tppUrl != "" && tppUser != "" && tppPassword != "" {
		config = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeTPP,
			BaseUrl:       tppUrl,
			Credentials:   &endpoint.Authentication{User: tppUser, Password: tppPassword},
		}
		if trustBundle != "" {
			var buf []byte
			trustBundle, err := base64.StdEncoding.Decode(buf, []byte(trustBundle))
			if err != nil {
				log.Printf("Can`t read trust bundle from file %s: %v\n", trustBundle, err)
				return nil, err
			}
			config.ConnectionTrust = string(trustBundle)
		}
	} else if cloudKey != "" {
		config = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeCloud,
			Credentials:   &endpoint.Authentication{APIKey: cloudKey},
		}
	} else {
		panic("bad credentials for connection") //todo: replace with something more beatifull
	}
	return vcert.NewClient(&config)
}
