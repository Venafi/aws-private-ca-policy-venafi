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
	"os"
)

var vcertConnector endpoint.Connector

func HandleRequest(ctx context.Context) error {
	names, err := common.GetAllPoliciesNames()
	if err != nil {
		fmt.Println(err)
		return err
	}
	for _, name := range names {
		vcertConnector.SetZone(name)
		p, err := vcertConnector.ReadPolicyConfiguration()
		if err == endpoint.VenafiErrorZoneNotFound {
			err = common.DeletePolicy(name)
			if err != nil {
				return err
			}
			continue
		} else if err != nil {
			fmt.Println(err)
			return err
		}
		err = common.SavePolicy(name, *p)
		if err != nil {
			fmt.Println(err)
			return err
		}
	}
	return nil
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
	cloudUrl := os.Getenv("VCERT_CLOUD_URL")
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
			BaseUrl:       cloudUrl,
		}
	} else {
		panic("bad credentials for connection") //todo: replace with something more beatifull
	}
	return vcert.NewClient(&config)
}
