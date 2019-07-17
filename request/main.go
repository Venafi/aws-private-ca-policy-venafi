package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Venafi/aws-private-ca-policy-venafi/common"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"log"
	"net/http"
)

var (
	// ErrNameNotProvided is thrown when a name is not provided
	ErrNameNotProvided = errors.New("no name was provided in the HTTP body")
)

//TODO: maybe get those types from sdk somehow
//most similar structure is github.com/aws/aws-sdk-go-v2/service/acmpca/api_op_IssueCertificate.go:13 IssueCertificateInput
type ACMPCAIssueCertificateRequest struct {
	SigningAlgorithm        string `json:"SigningAlgorithm"`
	CertificateAuthorityArn string `json:"CertificateAuthorityArn"`
	Csr                     string `json:"Csr"`
	VenafiZone              string `json:"VenafiZone"`
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

	//TODO: RequestCertificate*|https://docs.aws.amazon.com/acm/latest/APIReference/API_RequestCertificate.html
	//TODO: DescribeCertificate|https://docs.aws.amazon.com/acm/latest/APIReference/API_DescribeCertificate.html (pass-thru)
	//TODO: ExportCertificate|https://docs.aws.amazon.com/acm/latest/APIReference/API_ExportCertificate.html (pass-thru)
	//TODO: GetCertificate|https://docs.aws.amazon.com/acm/latest/APIReference/API_GetCertificate.html] (pass-thru)
	//TODO: ListCertificates|https://docs.aws.amazon.com/acm/latest/APIReference/API_ListCertificates.html] (pass-thru)
	//TODO: RenewCertificate|https://docs.aws.amazon.com/acm/latest/APIReference/API_RenewCertificate.html] (pass-thru)

	//## ACM PCA methods that must be accepted by Request Lamdba function:
	//TODO: [GetCertificate|https://docs.aws.amazon.com/acm-pca/latest/APIReference/API_GetCertificate.html] (pass-thru)
	//TODO: [GetCertificateAuthorityCertificate|https://docs.aws.amazon.com/acm-pca/latest/APIReference/API_GetCertificateAuthorityCertificate.html] (pass-thru)
	//TODO: [*IssueCertificate*|https://docs.aws.amazon.com/acm-pca/latest/APIReference/API_IssueCertificate.html]
	//TODO: [ListCertificateAuthorities|https://docs.aws.amazon.com/acm-pca/latest/APIReference/API_ListCertificateAuthorities.html] (pass-thru)
	//TODO: [RevokeCertificate|https://docs.aws.amazon.com/acm-pca/latest/APIReference/API_RevokeCertificate.html] (pass-thru)

	x_amz_target := request.Headers["X-Amz-Target"]
	switch x_amz_target {
	case "ACMPrivateCA.IssueCertificate":
		return venafiACMPCAIssueCertificateRequest(request)
	case "CertificateManager.RequestCertificate":
		return venafiACMRequestCertificate(request)
	default:
		return clientError(http.StatusMethodNotAllowed, "Can't determine requested method")
	}

}

func venafiACMPCAIssueCertificateRequest(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	var err error
	ctx := context.TODO()
	//TODO: Parse request body with CSR
	var certRequest ACMPCAIssueCertificateRequest
	err = json.Unmarshal([]byte(request.Body), &certRequest)
	if err != nil {
		return clientError(http.StatusUnprocessableEntity, fmt.Sprintf("Error unmarshaling JSON: %s", err))
	}

	csr, _ := base64.StdEncoding.DecodeString(certRequest.Csr)

	var req certificate.Request
	err = req.SetCSR([]byte(csr))
	if err != nil {
		return clientError(http.StatusUnprocessableEntity, "Can't parse certificate request")
	}

	if len(certRequest.VenafiZone) == 0 {
		certRequest.VenafiZone = "Default"
	}

	policy, err := common.GetPolicy(certRequest.VenafiZone)
	if err != nil {
		return clientError(http.StatusFailedDependency, fmt.Sprintf("Failed get policy from database: %s", err))
	}
	err = policy.ValidateCertificateRequest(&req)
	if err != nil {
		return clientError(http.StatusForbidden, err.Error())
	}

	//Issuing ACM certificate
	awsCfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		fmt.Println("Error loading client", err)
	}
	acmCli := acmpca.New(awsCfg)
	caReqInput := acmCli.IssueCertificateRequest(&acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(certRequest.CertificateAuthorityArn),
		Csr:                     []byte(csr),
		SigningAlgorithm:        acmpca.SigningAlgorithmSha256withrsa,
		Validity: &acmpca.Validity{
			Type:  acmpca.ValidityPeriodTypeDays,
			Value: aws.Int64(int64(30)),
		},
	})

	csrResp, err := caReqInput.Send(ctx)
	if err != nil {
		return clientError(500, fmt.Sprintf("could not get certificate response: %s", err))
	}

	getReq := &acmpca.GetCertificateInput{
		CertificateArn:          csrResp.CertificateArn,
		CertificateAuthorityArn: aws.String(certRequest.CertificateAuthorityArn),
	}

	err = acmCli.WaitUntilCertificateIssued(ctx, getReq)
	if err != nil {
		fmt.Println(err)
	}

	getCertificateReq := acmCli.GetCertificateRequest(getReq)

	getCertificateResp, err := getCertificateReq.Send(ctx)
	if err != nil {
		return events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("could not get certificate response: %s", err),
			StatusCode: 500,
		}, err
	}

	// stdout and stderr are sent to AWS CloudWatch Logs
	log.Printf("Processing Lambda request %s\n", request.RequestContext.RequestID)

	// If no name is provided in the HTTP request body, throw an error
	if len(request.Body) < 1 {
		return events.APIGatewayProxyResponse{}, ErrNameNotProvided
	}

	respoBody := &ACMPCAGetCertificateResponse{
		Certificate:      *getCertificateResp.GetCertificateOutput.Certificate,
		CertificateChain: *getCertificateResp.GetCertificateOutput.CertificateChain,
	}
	respoBodyJSON, err := json.Marshal(respoBody)
	if err != nil {
		return clientError(http.StatusUnprocessableEntity, fmt.Sprintf("Error marshaling response JSON: %s", err))
	}

	return events.APIGatewayProxyResponse{
		Body:       string(respoBodyJSON),
		StatusCode: 200,
	}, nil
}

func venafiACMRequestCertificate(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		Body:       string(`{ ryba:mech`),
		StatusCode: 200,
	}, nil
}

//TODO: Include custom error message into body
func clientError(status int, body string) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: status,
		Body:       fmt.Sprintf(`{ "msg" : "%s" }`, body),
	}, nil
}

func main() {
	lambda.Start(ACMPCAHandler)
}
