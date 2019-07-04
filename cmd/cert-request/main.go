package main

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/Venafi/aws-private-ca-policy-venafi/common"
	vcertificate "github.com/Venafi/vcert/pkg/certificate"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go/aws"
	//"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"log"
	"os"
)

var (
	// ErrNameNotProvided is thrown when a name is not provided
	ErrNameNotProvided = errors.New("no name was provided in the HTTP body")
)

type AWSCertificateRequest struct {
	CommonName string `json:"common_name"`
	SanDNS     string `json:"san_dns"`
	Policy     string `json:"policy"`
}

// Handler is your Lambda function handler
// It uses Amazon API Gateway request/responses provided by the aws-lambda-go/events package,
// However you could use other event sources (S3, Kinesis etc), or JSON-decoded primitive types such as 'string'.
func Handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var err error
	ctx := context.TODO()
	arn := os.Getenv("ACM_ARN")

	//Create CSR with vcert
	vcert, err := common.ClientVenafi()
	if err != nil {
		return events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("could not create vcert client: %s", err),
			StatusCode: 500,
		}, err
	}

	var enrollReq = &vcertificate.Request{}

	enrollReq = &vcertificate.Request{
		Subject: pkix.Name{
			CommonName: "venafi.example.com",
		},
	}

	err = vcert.GenerateRequest(nil, enrollReq)
	if err != nil {
		return events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("could not generate certificate request: %s", err),
			StatusCode: 500,
		}, err
	}

	//Issuing ACM certificate
	awsCfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		fmt.Println("Error loading client", err)
	}
	acmCli := acmpca.New(awsCfg)
	caReqInput := acmCli.IssueCertificateRequest(&acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(arn),
		Csr:                     enrollReq.GetCSR(),
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
		CertificateAuthorityArn: aws.String(arn),
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

func main() {
	lambda.Start(Handler)
}
