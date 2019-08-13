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
	"log"
	"net/http"
	"os"
)

type venafiError string

func (e venafiError) Error() string {
	return string(e)
}

const (
	acmRequestCertificate  = "CertificateManagerRequestCertificate"
	acmpcaIssueCertificate = "ACMPrivateCAIssueCertificate"

	// ErrNameNotProvided is thrown when a name is not provided
	ErrNameNotProvided venafiError = "no name was provided in the HTTP body"
)

var defaultZone = "Default"

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
	target := request.Headers["X-Amz-Target"]
	log.Println("ACMPCAHandler started. Parsing header", target)
	switch target {
	case acmpcaIssueCertificate:
		return venafiACMPCAIssueCertificateRequest(request)
	case acmRequestCertificate:
		return venafiACMRequestCertificate(request)
	case acmDescribeCertificate, acmExportCertificate, acmGetCertificate, acmListCertificates, acmRenewCertificate,
		acmpcaGetCertificate, acmpcaGetCertificateAuthorityCertificate, acmpcaListCertificateAuthorities,
		acmpcaRevokeCertificate:
		return passThru(request, ctx, target)
	default:
		log.Println("Can't determine requested method for header: ", target)
		return clientError(http.StatusMethodNotAllowed, fmt.Sprintf("Can't determine requested method for header: %s", target))
	}

}

func venafiACMPCAIssueCertificateRequest(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	log.Println("Requesting ACMP CA certificate")
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
	//TODO: add SigningAlgorithm validation

	if certRequest.VenafiZone == "" {
		certRequest.VenafiZone = defaultZone
	}
	policy, err := common.GetPolicy(certRequest.VenafiZone)
	if err == common.PolicyNotFound {
		return handlePolcyNotFound(certRequest.VenafiZone)
	} else if err != nil {
		return clientError(http.StatusFailedDependency, fmt.Sprintf("Failed to get policy from database: %s", err))
	}

	//TODO: also validate SigningAlgorithm from request
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
	log.Println("Starting RequestCertificate")
	ctx := context.TODO()
	var certRequest VenafiRequestCertificateInput
	err := json.Unmarshal([]byte(request.Body), &certRequest)
	if err != nil {
		log.Println(err)
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
		return handlePolcyNotFound(certRequest.VenafiZone)
	} else if err != nil {
		log.Println(err)
		return clientError(http.StatusFailedDependency, fmt.Sprintf("Failed to get policy from database: %s", err))
	}
	err = policy.SimpleValidateCertificateRequest(req)
	if err != nil {
		log.Println(err)
		return clientError(http.StatusForbidden, err.Error())
	}
	awsCfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		log.Println("Error loading client", err)
		return clientError(http.StatusInternalServerError, fmt.Sprintf("Can`t load client config: %v", err))
	}
	acmCli := acm.New(awsCfg)

	caReqInput := acmCli.RequestCertificateRequest(&certRequest.RequestCertificateInput)

	certResp, err := caReqInput.Send(ctx)
	if err != nil {
		log.Println(err)
		return clientError(http.StatusInternalServerError, fmt.Sprintf("Could not get certificate response: %s", err))
	}

	respoBodyJSON, err := json.Marshal(certResp)
	if err != nil {
		log.Println(err)
		return clientError(http.StatusUnprocessableEntity, fmt.Sprintf("Error marshaling response JSON: %s", err))
	}

	return events.APIGatewayProxyResponse{
		Body:       string(respoBodyJSON),
		StatusCode: http.StatusOK,
	}, nil
}

func handlePolcyNotFound(venafiZone string) (events.APIGatewayProxyResponse, error) {
	savePolicy := os.Getenv("SAVE_POLICY_FROM_REQUEST") == "true"
	if !savePolicy {
		return clientError(http.StatusFailedDependency, fmt.Sprintf("Policy not exist in database."))
	}
	err := common.CreateEmptyPolicy(venafiZone)
	if err != nil {
		return clientError(http.StatusFailedDependency, err.Error())
	}
	return clientError(http.StatusFailedDependency, fmt.Sprintf("Policy not exist in database. Policy creation is scheduled in policy lambda"))

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

func init() {
	d := os.Getenv("DEFAULT_ZONE")
	if d != "" {
		defaultZone = d
	}
}

func main() {
	lambda.Start(ACMPCAHandler)
}
