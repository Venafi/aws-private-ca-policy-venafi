package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"net/http"
)

const (
	acmDescribeCertificate = "CertificateManager.DescribeCertificate"
	acmExportCertificate   = "CertificateManager.ExportCertificate"
	acmGetCertificate      = "CertificateManager.GetCertificate"
	acmListCertificates    = "CertificateManager.ListCertificates"
	acmRenewCertificate    = "CertificateManager.RenewCertificate"

	acmpcaGetCertificate                     = "ACMPrivateCA.GetCertificate"
	acmpcaListCertificateAuthorities         = "ACMPrivateCA.ListCertificateAuthorities"
	acmpcaGetCertificateAuthorityCertificate = "ACMPrivateCA.GetCertificateAuthorityCertificate"
	acmpcaRevokeCertificate                  = "ACMPrivateCA.RevokeCertificate"
)

func passThru(request events.APIGatewayProxyRequest, acmCli acmpca.Client, ctx context.Context, target string) (events.APIGatewayProxyResponse, error) {

	//## ACM methods that must be accepted by Request Lamdba function:
	//TODO: DescribeCertificate|https://docs.aws.amazon.com/acm/latest/APIReference/API_DescribeCertificate.html (pass-thru)
	//TODO: ExportCertificate|https://docs.aws.amazon.com/acm/latest/APIReference/API_ExportCertificate.html (pass-thru)
	//TODO: GetCertificate|https://docs.aws.amazon.com/acm/latest/APIReference/API_GetCertificate.html] (pass-thru)
	//TODO: ListCertificates|https://docs.aws.amazon.com/acm/latest/APIReference/API_ListCertificates.html] (pass-thru)
	//TODO: RenewCertificate|https://docs.aws.amazon.com/acm/latest/APIReference/API_RenewCertificate.html] (pass-thru)

	//## ACM PCA methods that must be accepted by Request Lamdba function:
	//TODO: [GetCertificate|https://docs.aws.amazon.com/acm-pca/latest/APIReference/API_GetCertificate.html] (pass-thru)
	//TODO: [GetCertificateAuthorityCertificate|https://docs.aws.amazon.com/acm-pca/latest/APIReference/API_GetCertificateAuthorityCertificate.html] (pass-thru)
	//TODO: [RevokeCertificate|https://docs.aws.amazon.com/acm-pca/latest/APIReference/API_RevokeCertificate.html] (pass-thru)

	var respoBodyJSON []byte
	var err error

	switch target {
	case acmDescribeCertificate:
	case acmExportCertificate:
	case acmGetCertificate:
	case acmListCertificates:
	case acmRenewCertificate:

	case acmpcaGetCertificateAuthorityCertificate:
	case acmpcaRevokeCertificate:

	case acmpcaGetCertificate:
		var req = &acmpca.GetCertificateInput{}
		err = json.Unmarshal([]byte(request.Body), req)
		if err != nil {
			return clientError(http.StatusUnprocessableEntity, fmt.Sprintf("Error unmarshaling JSON for %s: %s", target, err))
		}

		doRequest := acmCli.GetCertificateRequest(req)
		var doRequestResponse *acmpca.GetCertificateResponse
		doRequestResponse, err = doRequest.Send(ctx)
		if err != nil {
			return clientError(http.StatusInternalServerError, fmt.Sprintf("Could not get response from target %s: %s", target, err))
		}
		respoBodyJSON, err = json.Marshal(doRequestResponse)
	case acmpcaListCertificateAuthorities:
		var req = &acmpca.ListCertificateAuthoritiesInput{}
		err = json.Unmarshal([]byte(request.Body), req)
		if err != nil {
			return clientError(http.StatusUnprocessableEntity, fmt.Sprintf("Error unmarshaling JSON for %s: %s", target, err))
		}

		doRequest := acmCli.ListCertificateAuthoritiesRequest(req)
		var doRequestResponse *acmpca.ListCertificateAuthoritiesResponse
		doRequestResponse, err = doRequest.Send(ctx)
		if err != nil {
			return clientError(http.StatusInternalServerError, fmt.Sprintf("Could not get response from target %s: %s", target, err))
		}
		respoBodyJSON, err = json.Marshal(doRequestResponse)
	default:
		return clientError(http.StatusUnprocessableEntity, fmt.Sprintf("Don't know hot to pass thru target: %s", target))
	}

	if err != nil {
		return clientError(http.StatusUnprocessableEntity, fmt.Sprintf("Error marshaling response JSON for target %s: %s", target, err))
	}
	return events.APIGatewayProxyResponse{
		Body:       string(respoBodyJSON),
		StatusCode: http.StatusOK,
	}, nil
}
