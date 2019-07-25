package main

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"github.com/Venafi/aws-private-ca-policy-venafi/common"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"net/http"
)

type venafiError string

func (e venafiError) Error() string {
	return string(e)
}

const (
	acmRequestCertificate  = "CertificateManager.RequestCertificate"
	acmpcaIssueCertificate = "ACMPrivateCA.IssueCertificate"
	defaultZone            = "Default"

	// ErrNameNotProvided is thrown when a name is not provided
	ErrNameNotProvided venafiError = "no name was provided in the HTTP body"
)

type ACMPCAIssueCertificateRequest struct {
	acmpca.IssueCertificateInput
	VenafiZone string `json:"VenafiZone"`
}

type VenafiRequestCertificateInput struct {
	acm.RequestCertificateInput
	VenafiZone string `json:"VenafiZone"`
}

type ACMPCAIssueCertificateResponse struct {
	CertificateArn string `json:"CertificateArn"`
}

type ACMPCAGetCertificateResponse struct {
	Certificate      string `json:"Certificate"`
	CertificateChain string `json:"CertificateChain"`
}

// ACMPCAHandler is your Lambda function handler
// It uses Amazon API Gateway request/responses provided by the aws-lambda-go/events package,
// However you could use other event sources (S3, Kinesis etc), or JSON-decoded primitive types such as 'string'.
func ACMPCAHandler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	ctx := context.TODO()

	switch request.Headers["X-Amz-Target"] {
	case acmpcaIssueCertificate:
		return venafiACMPCAIssueCertificateRequest(request)
	case acmRequestCertificate:
		return venafiACMRequestCertificate(request)
	case acmDescribeCertificate:
		return passThru(request, ctx, acmDescribeCertificate)
	case acmExportCertificate:
		return passThru(request, ctx, acmExportCertificate)
	case acmGetCertificate:
		return passThru(request, ctx, acmGetCertificate)
	case acmListCertificates:
		return passThru(request, ctx, acmListCertificates)
	case acmRenewCertificate:
		return passThru(request, ctx, acmRenewCertificate)
	case acmpcaGetCertificate:
		return passThru(request, ctx, acmpcaGetCertificate)
	case acmpcaGetCertificateAuthorityCertificate:
		return passThru(request, ctx, acmpcaGetCertificateAuthorityCertificate)
	case acmpcaListCertificateAuthorities:
		return passThru(request, ctx, acmpcaListCertificateAuthorities)
	case acmpcaRevokeCertificate:
		return passThru(request, ctx, acmpcaRevokeCertificate)

	default:
		return clientError(http.StatusMethodNotAllowed, fmt.Sprintf("Can't determine requested method for header: %s", request.Headers["X-Amz-Target"]))
	}

}

func venafiACMPCAIssueCertificateRequest(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	var err error
	ctx := context.TODO()
	//TODO: Parse request body with CSR
	var certRequest ACMPCAIssueCertificateRequest
	err = json.Unmarshal([]byte(request.Body), &certRequest)
	if err != nil {
		return clientError(http.StatusUnprocessableEntity, fmt.Sprintf(errUnmarshalJson, acmpcaIssueCertificate, err))
	}

	var req certificate.Request
	err = req.SetCSR([]byte(certRequest.IssueCertificateInput.Csr))
	if err != nil {
		return clientError(http.StatusUnprocessableEntity, "Can't parse certificate request")
	}

	if certRequest.VenafiZone == "" {
		certRequest.VenafiZone = defaultZone
	}
	policy, err := common.GetPolicy(certRequest.VenafiZone)
	if err == common.PolicyNotFound {
		err = common.CreateEmptyPolicy(certRequest.VenafiZone)
		if err != nil {
			return clientError(http.StatusFailedDependency, err.Error())
		}
		return clientError(http.StatusFailedDependency, fmt.Sprintf("Policy not exist in database. Policy creation is scheduled in policy lambda"))
	} else if err != nil {
		return clientError(http.StatusFailedDependency, fmt.Sprintf("Failed to get policy from database: %s", err))
	}

	err = policy.ValidateCertificateRequest(&req)
	if err != nil {
		return clientError(http.StatusForbidden, err.Error())
	}

	//Issuing ACM certificate
	awsCfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return clientError(http.StatusInternalServerError, fmt.Sprintf("Error loading client: %s", err))
	}
	acmCli := acmpca.New(awsCfg)
	caReqInput := acmCli.IssueCertificateRequest(&certRequest.IssueCertificateInput)

	csrResp, err := caReqInput.Send(ctx)
	if err != nil {
		return clientError(http.StatusInternalServerError, fmt.Sprintf("Could not get certificate response: %s", err))
	}

	respoBodyJSON, err := json.Marshal(csrResp)
	if err != nil {
		return clientError(http.StatusUnprocessableEntity, fmt.Sprintf("Error marshaling response JSON for target %s: %s", acmpcaIssueCertificate, err))
	}

	return events.APIGatewayProxyResponse{
		Body:       string(respoBodyJSON),
		StatusCode: http.StatusOK,
	}, nil
}

func venafiACMRequestCertificate(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	ctx := context.TODO()

	var certRequest VenafiRequestCertificateInput
	err := json.Unmarshal([]byte(request.Body), &certRequest)
	if err != nil {
		return clientError(http.StatusUnprocessableEntity, fmt.Sprintf("Error unmarshaling JSON: %s", err))
	}

	var req certificate.Request
	req.Subject = pkix.Name{CommonName: *certRequest.DomainName}
	req.DNSNames = certRequest.SubjectAlternativeNames

	if certRequest.VenafiZone == "" {
		certRequest.VenafiZone = defaultZone
	}
	policy, err := common.GetPolicy(certRequest.VenafiZone)
	if err == common.PolicyNotFound {
		common.CreateEmptyPolicy(certRequest.VenafiZone)
		return clientError(http.StatusFailedDependency, fmt.Sprintf("Policy not exist in database. Policy creation is scheduled in policy lambda"))
	} else if err != nil {
		return clientError(http.StatusFailedDependency, fmt.Sprintf("Failed to get policy from database: %s", err))
	}
	err = policy.SimpleValidateCertificateRequest(req)
	if err != nil {
		return clientError(http.StatusForbidden, err.Error())
	}
	awsCfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		fmt.Println("Error loading client", err)
	}
	acmCli := acm.New(awsCfg)

	caReqInput := acmCli.RequestCertificateRequest(&certRequest.RequestCertificateInput)

	certResp, err := caReqInput.Send(ctx)
	if err != nil {
		return clientError(http.StatusInternalServerError, fmt.Sprintf("Could not get certificate response: %s", err))
	}

	respoBodyJSON, err := json.Marshal(certResp)
	if err != nil {
		return clientError(http.StatusUnprocessableEntity, fmt.Sprintf("Error marshaling response JSON: %s", err))
	}

	return events.APIGatewayProxyResponse{
		Body:       string(respoBodyJSON),
		StatusCode: http.StatusOK,
	}, nil
}

func clientError(status int, body string) (events.APIGatewayProxyResponse, error) {
	//TODO: try to make error compatible with aws cli commands
	temp := struct {
		Msg string `json:"msg"`
	}{
		body,
	}
	b, _ := json.Marshal(temp)

	return events.APIGatewayProxyResponse{
		StatusCode: status,
		Body:       string(b),
	}, nil
}

func main() {
	lambda.Start(ACMPCAHandler)
}
