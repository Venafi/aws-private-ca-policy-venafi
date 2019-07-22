package main

import (
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

func HandleRequest() error {
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
	vcertConnector, err = getConnection(
		os.Getenv("TPPURL"),
		os.Getenv("TPPUSER"),
		os.Getenv("TPPPASSWORD"),
		os.Getenv("CLOUDURL"),
		os.Getenv("CLOUDAPIKEY"),
		os.Getenv("TRUST_BUNDLE"),
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	lambda.Start(HandleRequest)
}

func getConnection(tppUrl, tppUser, tppPassword, cloudUrl, cloudKey, trustBundle string) (endpoint.Connector, error) {
	var config vcert.Config
	if tppUrl != "" && tppUser != "" && tppPassword != "" {
		config = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeTPP,
			BaseUrl:       tppUrl,
			Credentials:   &endpoint.Authentication{User: tppUser, Password: tppPassword},
		}
		if trustBundle != "" {
			buf, err := base64.StdEncoding.DecodeString(trustBundle)
			if err != nil {
				log.Printf("Can`t read trust bundle from file %s: %v\n", trustBundle, err)
				return nil, err
			}
			config.ConnectionTrust = string(buf)
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
