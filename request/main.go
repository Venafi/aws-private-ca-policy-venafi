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
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"net/http"
	"regexp"

	"github.com/Venafi/aws-private-ca-policy-venafi/common"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"log"
)

var (
	// ErrNameNotProvided is thrown when a name is not provided
	ErrNameNotProvided = errors.New("no name was provided in the HTTP body")
)

//TODO: maybe get those types from sdk somehow
type ACMPCAIssueCertificateRequest struct {
	SigningAlgorithm        string `json:"SigningAlgorithm"`
	CertificateAuthorityArn string `json:"CertificateAuthorityArn"`
	Csr                     string `json:"Csr"`
	Policy                  string `json:"Policy"`
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
	var err error
	ctx := context.TODO()

	//TODO: Parse request body with CSR
	var certRequest ACMPCAIssueCertificateRequest
	err = json.Unmarshal([]byte(request.Body), &certRequest)
	if err != nil {
		return clientError(http.StatusUnprocessableEntity, fmt.Sprintf("Error unmarshaling JSON: %s", err))
	}

	csr, _ := base64.StdEncoding.DecodeString(certRequest.Csr)
	//Decode CSR
	pemBlock, _ := pem.Decode([]byte(csr))
	if pemBlock == nil {
		return clientError(http.StatusUnprocessableEntity, "PEM block in CSR is nil")
	}

	parsedCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if parsedCSR == nil {
		return clientError(http.StatusUnprocessableEntity, "Can't parse certificate request")
	}

	//TODO: Get policies from DB
	if len(certRequest.Policy) == 0 {
		certRequest.Policy = "Default"
	}

	policy, err := common.GetPolicy(certRequest.Policy)
	if err != nil {
		return clientError(http.StatusFailedDependency, fmt.Sprintf("Failed get policy from database: %s", err))
	}

	log.Println(policy)
	//TODO: Check CSR against policies
	if !checkStringByRegexp(parsedCSR.Subject.CommonName, policy.SubjectCNRegexes) {
		return clientError(http.StatusForbidden, fmt.Sprintf("common name %s is not allowed in this policy", parsedCSR.Subject.CommonName))
	}
	if !checkStringArrByRegexp(parsedCSR.EmailAddresses, policy.EmailSanRegExs, true) {
		return clientError(http.StatusForbidden, fmt.Sprintf("emails %v doesn't match regexps: %v", policy.EmailSanRegExs, policy.EmailSanRegExs))
	}
	if !checkStringArrByRegexp(parsedCSR.DNSNames, policy.DnsSanRegExs, true) {
		return clientError(http.StatusForbidden, fmt.Sprintf("DNS sans %v doesn't match regexps: %v", parsedCSR.DNSNames, policy.DnsSanRegExs))
	}
	ips := make([]string, len(parsedCSR.IPAddresses))
	for i, ip := range parsedCSR.IPAddresses {
		ips[i] = ip.String()
	}
	if !checkStringArrByRegexp(ips, policy.IpSanRegExs, true) {
		return clientError(http.StatusForbidden, fmt.Sprintf("IPs %v doesn't match regexps: %v", policy.IpSanRegExs, policy.IpSanRegExs))
	}
	uris := make([]string, len(parsedCSR.URIs))
	for i, uri := range parsedCSR.URIs {
		uris[i] = uri.String()
	}
	if !checkStringArrByRegexp(uris, policy.UriSanRegExs, true) {
		return clientError(http.StatusForbidden, fmt.Sprintf("URIs %v doesn't match regexps: %v", uris, policy.UriSanRegExs))
	}
	if !checkStringArrByRegexp(parsedCSR.Subject.Organization, policy.SubjectORegexes, false) {
		return clientError(http.StatusForbidden, fmt.Sprintf("Organization %v doesn't match regexps: %v", policy.SubjectORegexes, policy.SubjectORegexes))
	}

	if !checkStringArrByRegexp(parsedCSR.Subject.OrganizationalUnit, policy.SubjectOURegexes, false) {
		return clientError(http.StatusForbidden, fmt.Sprintf("Organization Unit %v doesn't match regexps: %v", parsedCSR.Subject.OrganizationalUnit, policy.SubjectOURegexes))
	}

	if !checkStringArrByRegexp(parsedCSR.Subject.Country, policy.SubjectCRegexes, false) {
		return clientError(http.StatusForbidden, fmt.Sprintf("Country %v doesn't match regexps: %v", parsedCSR.Subject.Country, policy.SubjectCRegexes))
	}

	if !checkStringArrByRegexp(parsedCSR.Subject.Locality, policy.SubjectLRegexes, false) {
		return clientError(http.StatusForbidden, fmt.Sprintf("Location %v doesn't match regexps: %v", parsedCSR.Subject.Locality, policy.SubjectLRegexes))
	}

	if !checkStringArrByRegexp(parsedCSR.Subject.Province, policy.SubjectSTRegexes, false) {
		return clientError(http.StatusForbidden, fmt.Sprintf("State (Province) %v doesn't match regexps: %v", parsedCSR.Subject.Province, policy.SubjectSTRegexes))
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

//TODO: Include custom error message into body
func clientError(status int, body string) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: status,
		Body:       fmt.Sprintf(`{ "msg" : "%s" }`, body),
	}, nil
}

func checkStringByRegexp(s string, regexs []string) (matched bool) {
	var err error
	for _, r := range regexs {
		matched, err = regexp.MatchString(r, s)
		if err == nil && matched {
			return true
		}
	}
	return
}

func checkStringArrByRegexp(ss []string, regexs []string, optional bool) (matched bool) {
	if optional && len(ss) == 0 {
		return true
	}
	if len(ss) == 0 {
		ss = []string{""}
	}
	for _, s := range ss {
		if !checkStringByRegexp(s, regexs) {
			return false
		}
	}
	return true
}

func main() {
	lambda.Start(ACMPCAHandler)
}
