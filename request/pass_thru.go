package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"net/http"
)

func passThru(request events.APIGatewayProxyRequest, acmCli acmpca.Client, ctx context.Context, target string) (events.APIGatewayProxyResponse, error) {

	var respoBodyJSON []byte
	var err error

	switch target {
	case "ACMPrivateCA.ListCertificateAuthorities":
		var req = &acmpca.ListCertificateAuthoritiesInput{}
		err = json.Unmarshal([]byte(request.Body), req)
		if err != nil {
			return clientError(http.StatusUnprocessableEntity, fmt.Sprintf("Error unmarshaling JSON: %s", err))
		}

		listCA := acmCli.ListCertificateAuthoritiesRequest(req)
		var listCAresp *acmpca.ListCertificateAuthoritiesResponse
		listCAresp, err = listCA.Send(ctx)
		if err != nil {
			return clientError(http.StatusInternalServerError, fmt.Sprintf("could not get certificate response: %s", err))
		}
		respoBodyJSON, err = json.Marshal(listCAresp)
	default:
		return clientError(http.StatusUnprocessableEntity, fmt.Sprintf("Don't know hot to pass thru target: %s", target))
	}

	if err != nil {
		return clientError(http.StatusUnprocessableEntity, fmt.Sprintf("Error marshaling response JSON: %s", err))
	}
	return events.APIGatewayProxyResponse{
		Body:       string(respoBodyJSON),
		StatusCode: http.StatusOK,
	}, nil
}
