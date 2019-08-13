package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"net/http"
)

const (
	acmDescribeCertificate = "CertificateManagerDescribeCertificate"
	acmExportCertificate   = "CertificateManagerExportCertificate"
	acmGetCertificate      = "CertificateManagerGetCertificate"
	acmListCertificates    = "CertificateManagerListCertificates"
	acmRenewCertificate    = "CertificateManagerRenewCertificate"

	acmpcaGetCertificate                     = "ACMPrivateCAGetCertificate"
	acmpcaListCertificateAuthorities         = "ACMPrivateCAListCertificateAuthorities"
	acmpcaGetCertificateAuthorityCertificate = "ACMPrivateCAGetCertificateAuthorityCertificate"
	acmpcaRevokeCertificate                  = "ACMPrivateCARevokeCertificate"
)

const (
	errUnmarshalJson = "Error unmarshaling JSON for %s: %s"
	errNoResponse    = "Could not get response from target %s: %s"
)

func passThru(request events.APIGatewayProxyRequest, ctx context.Context, target string) (events.APIGatewayProxyResponse, error) {

	var respoBodyJSON []byte
	var err error

	awsCfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return clientError(http.StatusInternalServerError, fmt.Sprintf("Error loading client: %s", err))
	}
	acmpcaCli := acmpca.New(awsCfg)
	acmCli := acm.New(awsCfg)

	switch target {
	case acmDescribeCertificate:
		var req = &acm.DescribeCertificateInput{}
		err = json.Unmarshal([]byte(request.Body), req)
		if err != nil {
			return clientError(http.StatusUnprocessableEntity, fmt.Sprintf(errUnmarshalJson, target, err))
		}

		doRequest := acmCli.DescribeCertificateRequest(req)
		var doRequestResponse *acm.DescribeCertificateResponse
		doRequestResponse, err = doRequest.Send(ctx)
		if err != nil {
			return clientError(http.StatusInternalServerError, fmt.Sprintf(errNoResponse, target, err))
		}
		respoBodyJSON, err = json.Marshal(doRequestResponse)
	case acmExportCertificate:
		var req = &acm.ExportCertificateInput{}
		err = json.Unmarshal([]byte(request.Body), req)
		if err != nil {
			return clientError(http.StatusUnprocessableEntity, fmt.Sprintf(errUnmarshalJson, target, err))
		}

		doRequest := acmCli.ExportCertificateRequest(req)
		var doRequestResponse *acm.ExportCertificateResponse
		doRequestResponse, err = doRequest.Send(ctx)
		if err != nil {
			return clientError(http.StatusInternalServerError, fmt.Sprintf(errNoResponse, target, err))
		}
		respoBodyJSON, err = json.Marshal(doRequestResponse)
	case acmGetCertificate:
		var req = &acm.GetCertificateInput{}
		err = json.Unmarshal([]byte(request.Body), req)
		if err != nil {
			return clientError(http.StatusUnprocessableEntity, fmt.Sprintf(errUnmarshalJson, target, err))
		}

		doRequest := acmCli.GetCertificateRequest(req)
		var doRequestResponse *acm.GetCertificateResponse
		doRequestResponse, err = doRequest.Send(ctx)
		if err != nil {
			return clientError(http.StatusInternalServerError, fmt.Sprintf(errNoResponse, target, err))
		}
		respoBodyJSON, err = json.Marshal(doRequestResponse)
	case acmListCertificates:
		var req = &acm.ListCertificatesInput{}
		err = json.Unmarshal([]byte(request.Body), req)
		if err != nil {
			return clientError(http.StatusUnprocessableEntity, fmt.Sprintf(errUnmarshalJson, target, err))
		}

		doRequest := acmCli.ListCertificatesRequest(req)
		var doRequestResponse *acm.ListCertificatesResponse
		doRequestResponse, err = doRequest.Send(ctx)
		if err != nil {
			return clientError(http.StatusInternalServerError, fmt.Sprintf(errNoResponse, target, err))
		}
		respoBodyJSON, err = json.Marshal(doRequestResponse)
	case acmRenewCertificate:
		var req = &acm.RenewCertificateInput{}
		err = json.Unmarshal([]byte(request.Body), req)
		if err != nil {
			return clientError(http.StatusUnprocessableEntity, fmt.Sprintf(errUnmarshalJson, target, err))
		}

		doRequest := acmCli.RenewCertificateRequest(req)
		var doRequestResponse *acm.RenewCertificateResponse
		doRequestResponse, err = doRequest.Send(ctx)
		if err != nil {
			return clientError(http.StatusInternalServerError, fmt.Sprintf(errNoResponse, target, err))
		}
		respoBodyJSON, err = json.Marshal(doRequestResponse)

	case acmpcaGetCertificateAuthorityCertificate:
		var req = &acmpca.GetCertificateAuthorityCertificateInput{}
		err = json.Unmarshal([]byte(request.Body), req)
		if err != nil {
			return clientError(http.StatusUnprocessableEntity, fmt.Sprintf(errUnmarshalJson, target, err))
		}

		doRequest := acmpcaCli.GetCertificateAuthorityCertificateRequest(req)
		var doRequestResponse *acmpca.GetCertificateAuthorityCertificateResponse
		doRequestResponse, err = doRequest.Send(ctx)
		if err != nil {
			return clientError(http.StatusInternalServerError, fmt.Sprintf(errNoResponse, target, err))
		}
		respoBodyJSON, err = json.Marshal(doRequestResponse)
	case acmpcaRevokeCertificate:
		var req = &acmpca.RevokeCertificateInput{}
		err = json.Unmarshal([]byte(request.Body), req)
		if err != nil {
			return clientError(http.StatusUnprocessableEntity, fmt.Sprintf(errUnmarshalJson, target, err))
		}

		doRequest := acmpcaCli.RevokeCertificateRequest(req)
		var doRequestResponse *acmpca.RevokeCertificateResponse
		doRequestResponse, err = doRequest.Send(ctx)
		if err != nil {
			return clientError(http.StatusInternalServerError, fmt.Sprintf(errNoResponse, target, err))
		}
		respoBodyJSON, err = json.Marshal(doRequestResponse)

	case acmpcaGetCertificate:
		var req = &acmpca.GetCertificateInput{}
		err = json.Unmarshal([]byte(request.Body), req)
		if err != nil {
			return clientError(http.StatusUnprocessableEntity, fmt.Sprintf(errUnmarshalJson, target, err))
		}

		doRequest := acmpcaCli.GetCertificateRequest(req)
		var doRequestResponse *acmpca.GetCertificateResponse
		doRequestResponse, err = doRequest.Send(ctx)
		if err != nil {
			return clientError(http.StatusInternalServerError, fmt.Sprintf(errNoResponse, target, err))
		}
		respoBodyJSON, err = json.Marshal(doRequestResponse)
	case acmpcaListCertificateAuthorities:
		var req = &acmpca.ListCertificateAuthoritiesInput{}
		err = json.Unmarshal([]byte(request.Body), req)
		if err != nil {
			return clientError(http.StatusUnprocessableEntity, fmt.Sprintf(errUnmarshalJson, target, err))
		}

		doRequest := acmpcaCli.ListCertificateAuthoritiesRequest(req)
		var doRequestResponse *acmpca.ListCertificateAuthoritiesResponse
		doRequestResponse, err = doRequest.Send(ctx)
		if err != nil {
			return clientError(http.StatusInternalServerError, fmt.Sprintf(errNoResponse, target, err))
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
