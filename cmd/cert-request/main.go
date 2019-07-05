package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go/aws"
	"net/http"

	//"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"log"
)

var (
	// ErrNameNotProvided is thrown when a name is not provided
	ErrNameNotProvided = errors.New("no name was provided in the HTTP body")
)

type ACMPCACertificateRequest struct {
	SigningAlgorithm        string `json:"SigningAlgorithm"`
	CertificateAuthorityArn string `json:"CertificateAuthorityArn"`
	Csr                     string `json:"Csr"`
}

// ACMPCAHandler is your Lambda function handler
// It uses Amazon API Gateway request/responses provided by the aws-lambda-go/events package,
// However you could use other event sources (S3, Kinesis etc), or JSON-decoded primitive types such as 'string'.
func ACMPCAHandler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var err error
	ctx := context.TODO()

	//TODO: Parse request body with CSR
	certRequest := new(ACMPCACertificateRequest)
	err = json.Unmarshal([]byte(request.Body), certRequest)
	if err != nil {
		return clientError(http.StatusUnprocessableEntity)
	}

	csr, _ := base64.StdEncoding.DecodeString(certRequest.Csr)
	//TODO: Decode CSR
	pemBlock, _ := pem.Decode([]byte(csr))
	if pemBlock == nil {
		return clientError(http.StatusUnprocessableEntity)
	}
	parsedCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if pemBlock == nil {
		return clientError(http.StatusUnprocessableEntity)
	}

	//TODO: Check CSR against policies
	if parsedCSR.Subject.CommonName != "test-csr-32313131.venafi.example.com" {
		return clientError(http.StatusUnprocessableEntity)
	}

	//TODO: Issuing ACM certificate
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
		return events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("could not get certificate response: %s", err),
			StatusCode: 500,
		}, err
	}

	getReq := &acmpca.GetCertificateInput{
		CertificateArn:          csrResp.CertificateArn,
		CertificateAuthorityArn: aws.String(certRequest.CertificateAuthorityArn),
	}

	err = acmCli.WaitUntilCertificateIssued(ctx, getReq)
	if err != nil {
		fmt.Println(err)
	}

	certReq := acmCli.GetCertificateRequest(getReq)

	certResp, err := certReq.Send(ctx)
	if err != nil {
		return events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("could not get certificate response: %s", err),
			StatusCode: 500,
		}, err
	}

	fmt.Println(*certResp.GetCertificateOutput.Certificate)

	// stdout and stderr are sent to AWS CloudWatch Logs
	log.Printf("Processing Lambda request %s\n", request.RequestContext.RequestID)

	// If no name is provided in the HTTP request body, throw an error
	if len(request.Body) < 1 {
		return events.APIGatewayProxyResponse{}, ErrNameNotProvided
	}

	return events.APIGatewayProxyResponse{
		Body:       "Hello " + request.Body,
		StatusCode: 200,
	}, nil

}

//TODO: Include custom error message into body
func clientError(status int) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: status,
		Body:       http.StatusText(status),
	}, nil
}

func main() {
	lambda.Start(ACMPCAHandler)
}
