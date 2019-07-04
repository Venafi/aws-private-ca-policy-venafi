package common

import (
	"fmt"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/endpoint"
	"io/ioutil"
	"log"
	"os"
)

func ClientVenafi() (endpoint.Connector, error) {

	TPPUser := os.Getenv("TPPUSER")
	TPPPassword := os.Getenv("TPPPASSWORD")
	TrustBundle := os.Getenv("TRUST_BUNDLE")
	Apikey := os.Getenv("CLOUDAPIKEY")
	TPPURL := os.Getenv("TPPURL")
	Zone := os.Getenv("ZONE")
	CloudURL := os.Getenv("CLOUDURL")

	cfg := vcert.Config{
		Zone:       Zone,
		LogVerbose: true,
	}

	if TPPURL != "" && TPPUser != "" && TPPPassword != "" {
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		cfg.BaseUrl = TPPURL
		cfg.Credentials = &endpoint.Authentication{
			User:     TPPUser,
			Password: TPPPassword,
		}

		if TrustBundle != "" {
			trustBundle, err := ioutil.ReadFile(TrustBundle)
			if err != nil {
				log.Printf("Can`t read trust bundle from file %s: %v\n", TrustBundle, err)
				return nil, err
			}
			cfg.ConnectionTrust = string(trustBundle)
		}
	} else if Apikey != "" {
		cfg.ConnectorType = endpoint.ConnectorTypeCloud
		cfg.BaseUrl = CloudURL
		cfg.Credentials = &endpoint.Authentication{
			APIKey: Apikey,
		}
	} else {
		return nil, fmt.Errorf("failed to build config for Venafi conection")
	}
	client, err := vcert.NewClient(&cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get Venafi issuer client: %s", err)
	}
	return client, nil
}
