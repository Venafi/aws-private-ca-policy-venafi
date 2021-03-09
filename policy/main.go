package main

import (
	"context"
	"encoding/base64"
	"github.com/Venafi/aws-private-ca-policy-venafi/common"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/verror"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"log"
	"os"
	"strings"
)

var vcertConnector endpoint.Connector

func HandleRequest() error {
	log.Println("Getting policies")
	names, err := common.GetAllPoliciesNames()
	if err != nil {
		log.Println("getting policies names error:", err)
		return err
	}
	for _, name := range names {
		log.Printf("Getting policy %s", name)
		vcertConnector.SetZone(name)
		p, err := vcertConnector.ReadPolicyConfiguration()
		if err == verror.ZoneNotFoundError {
			log.Printf("Policy %s not found. Deleting.", name)
			err = common.DeletePolicy(name)
			if err != nil {
				log.Println("delete policy error:", err)
			}
			continue
		} else if err != nil {
			log.Println(err)
			return err
		}
		log.Printf("Saving policy %s", name)
		err = common.SavePolicy(name, *p)
		if err != nil {
			log.Println("save policy error:", err)
		}
	}
	log.Println("success policies processing")
	return nil
}

func kmsDecrypt(encrypted string) (string, error) {
	log.Printf("Decrypting encrypted variable")
	if encrypted == "" {
		return "", nil
	}
	decodedBytes, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		log.Println("can`t load aws config", err)
		return "", err
	}

	svc := kms.New(cfg)
	input := &kms.DecryptInput{
		CiphertextBlob: decodedBytes,
	}

	req := svc.DecryptRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		log.Println("can`t decrypt", encrypted, ":", err)
		return "", err
	}
	return string(result.Plaintext[:]), nil
}

func main() {
	log.Println("Starting policy lambda.")
	var err error

	apiKey := os.Getenv("CLOUDAPIKEY")
	password := os.Getenv("TPPPASSWORD")
	accessToken := os.Getenv("TPP_ACCESS_TOKEN")
	refreshToken := os.Getenv("TPP_REFRESH_TOKEN")

	plainTextCreds := strings.HasPrefix(strings.ToLower(os.Getenv("ENCRYPTED_CREDENTIALS")), "f")
	if !plainTextCreds {
		var err error
		apiKey, err = kmsDecrypt(apiKey)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		password, err = kmsDecrypt(password)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		accessToken, err = kmsDecrypt(accessToken)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		refreshToken, err = kmsDecrypt(refreshToken)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
	}

	vcertConnector, err = getConnection(
		os.Getenv("TPPURL"),
		os.Getenv("TPPUSER"),
		password,
		accessToken,
		refreshToken,
		apiKey,
		os.Getenv("TRUST_BUNDLE"),
	)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	lambda.Start(HandleRequest)
}

func getConnection(tppUrl, tppUser, tppPassword, accessToken, refreshToken, apiKey, trustBundle string) (endpoint.Connector, error) {
	log.Println("Getting Venafi connection")
	var config vcert.Config
	if tppUrl != "" && tppUser != "" && tppPassword != "" {
		config = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeTPP,
			BaseUrl:       tppUrl,
			Credentials: &endpoint.Authentication{
				User:     tppUser,
				Password: tppPassword,
			},
		}

	} else if tppUrl != "" && (accessToken != "" || refreshToken != "") {
		config = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeTPP,
			BaseUrl:       tppUrl,
			Credentials: &endpoint.Authentication{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				ClientId:     ClientId,
			},
		}
	} else if apiKey != "" {
		config = vcert.Config{
			ConnectorType: endpoint.ConnectorTypeCloud,
			Credentials: &endpoint.Authentication{
				APIKey: apiKey,
			},
		}

	} else {
		panic("bad credentials for connection") //todo: replace with something more beautiful
	}

	if config.ConnectorType == endpoint.ConnectorTypeTPP && trustBundle != "" {
		buf, err := base64.StdEncoding.DecodeString(trustBundle)
		if err != nil {
			log.Printf("Can`t read trust bundle from file %s: %v\n", trustBundle, err)
			return nil, err
		}
		config.ConnectionTrust = string(buf)
	}

	// When we have a refresh token, we want to consume it with the purpose of gaining exclusive ownership
	// of the token. So, no other plugin/entity/user can refresh it and make it invalid.
	if config.ConnectorType == endpoint.ConnectorTypeTPP && config.Credentials.RefreshToken != "" {
		newAuth, err := consumeToken(&config)
		if err != nil {
			log.Printf("Error while consuming refresh token: %v\n", err)
			return nil, err
		}
		config.Credentials = &newAuth
	}

	return vcert.NewClient(&config)
}

func consumeToken(cfg *vcert.Config) (auth endpoint.Authentication, err error) {
	log.Println("Trying to consume Refresh Token")

	tppConnector, err := getTppConnector(cfg)
	if err != nil {
		return
	}
	httpClient, err := getHTTPClient(cfg.ConnectionTrust)
	if err != nil {
		return
	}

	tppConnector.SetHTTPClient(httpClient)

	tokenInfoResponse, err := tppConnector.RefreshAccessToken(&endpoint.Authentication{
		RefreshToken: cfg.Credentials.RefreshToken,
		ClientId:     ClientId,
		Scope:        Scope,
	})

	if err != nil {
		log.Printf("Error while refreshing access token: %v\n", err)
		return
	}

	auth = endpoint.Authentication{
		User:         cfg.Credentials.User,
		Password:     cfg.Credentials.Password,
		APIKey:       cfg.Credentials.APIKey,
		RefreshToken: tokenInfoResponse.Refresh_token,
		Scope:        Scope,
		ClientId:     ClientId,
		AccessToken:  tokenInfoResponse.Access_token,
		ClientPKCS12: cfg.Credentials.ClientPKCS12,
	}

	return
}
