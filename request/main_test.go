package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	mrand "math/rand"
	"os"
	"testing"
	"time"
)

const (
	wrongResponseCode = "Request returned code: %d message: %s"
)
const (
	ACMPCAJSONRequest = `{
		"SigningAlgorithm":"SHA256WITHRSA",
		"Validity": {"Type": "DAYS","Value": 365},
		"CertificateAuthorityArn": "%s","Csr": "%s"
	}`
	acmpcaListCertificateAuthoritiesRequest = `{"MaxResults": 10}`
	acmpcaGetCertificateRequest             = `{
		"CertificateArn": "%s"
		,"CertificateAuthorityArn": "%s"
	}`
)

func TestACMPCACertificate(t *testing.T) {
	ctx := context.TODO()

	acmpcaArn := os.Getenv("ACMPCA_ARN")
	if len(acmpcaArn) < 1 {
		t.Fatalf("ACMPCA is empty")
	}

	awsCfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		t.Fatalf("Can't get AWS configuration: %s", err)
	}
	acmpcaCli := acmpca.New(awsCfg)

	cn := randSeq(9) + ".example.com"
	jsonBody := fmt.Sprintf(ACMPCAJSONRequest, acmpcaArn,
		base64.StdEncoding.EncodeToString(createCSR(cn)))

	headers := map[string]string{"X-Amz-Target": acmpcaIssueCertificate}

	issueCertResp, err := ACMPCAHandler(events.APIGatewayProxyRequest{
		Body:    jsonBody,
		Headers: headers,
	})
	if err != nil {
		t.Fatalf("Request returned error: %s", err)
	}

	if issueCertResp.StatusCode != 200 {
		t.Fatalf(wrongResponseCode, issueCertResp.StatusCode, issueCertResp.Body)
	}

	issueResponse := new(ACMPCAIssueCertificateResponse)
	err = json.Unmarshal([]byte(issueCertResp.Body), issueResponse)
	if err != nil {
		t.Fatalf("Cant process response json: %s", err)
	}

	headers = map[string]string{"X-Amz-Target": acmpcaGetCertificate}
	jsonBody = fmt.Sprintf(acmpcaGetCertificateRequest, issueResponse.CertificateArn, acmpcaArn)

	getReq := &acmpca.GetCertificateInput{
		CertificateArn:          &issueResponse.CertificateArn,
		CertificateAuthorityArn: &acmpcaArn,
	}

	err = acmpcaCli.WaitUntilCertificateIssued(ctx, getReq)
	if err != nil {
		t.Fatalf("Error while waiting for certificate: %s\n", err)
	}

	requestCertResp, err := ACMPCAHandler(events.APIGatewayProxyRequest{
		Body:    jsonBody,
		Headers: headers,
	})
	if err != nil {
		t.Fatalf("Cant get certificate: %s", err)
	}

	if requestCertResp.StatusCode != 200 {
		t.Fatalf(wrongResponseCode, requestCertResp.StatusCode, requestCertResp.Body)
	}

	certResponse := new(ACMPCAGetCertificateResponse)
	err = json.Unmarshal([]byte(requestCertResp.Body), certResponse)

	if err != nil {
		t.Fatalf("Cant process response json: %s", err)
	}

	if len(certResponse.Certificate) < 1 {
		t.Fatalf("Certificate field in json is empty.")
	}
	rawCert := certResponse.Certificate

	checkCertificate(t, rawCert, cn)

}

func TestPassThru(t *testing.T) {
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
	var headers map[string]string
	targets := map[string]string{
		acmpcaListCertificateAuthorities: `{"MaxResults": 10}`,
		acmpcaGetCertificate: `{
		  "CertificateArn": "arn:aws:acm-pca:region:account:certificate-authority/12345678-1234-1234-1234-123456789012/certificate/e8cbd2bedb122329f97706bcfec990f8",
		  "CertificateAuthorityArn": "arn:aws:acm-pca:region:account:certificate-authority/12345678-1234-1234-1234-123456789012"
		}`,
	}

	for target, body := range targets {
		headers = map[string]string{"X-Amz-Target": target}
		certResp, err := ACMPCAHandler(events.APIGatewayProxyRequest{
			Body:    body,
			Headers: headers,
		})
		if err != nil {
			t.Fatalf("Request returned error: %s", err)
		}

		if certResp.StatusCode != 200 {
			t.Fatalf(wrongResponseCode, certResp.StatusCode, certResp.Body)
		}
		t.Logf("Resp is:\n %s", certResp.Body)
	}

}

func checkCertificate(t *testing.T, rawCert string, cn string) {

	var err error

	pemBlock, _ := pem.Decode([]byte(rawCert))
	if pemBlock.Bytes == nil {
		t.Fatalf("Certificate PEM is nil")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Cant parse certificate: %s", err)
	}
	if cert.Subject.CommonName != cn {
		t.Fatalf("Common name is not as expected")
	}
	t.Logf("Certificate is ok:\n %s", rawCert)
}

func createCSR(cn string) []byte {

	csr := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Venafi Inc."},
			CommonName:   cn,
		},
		//EmailAddresses: []string{"some@adress"},
	}
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 1024)
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &csr, keyBytes)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
}

func randSeq(n int) string {
	mrand.Seed(time.Now().UTC().UnixNano())
	var letters = []rune("abcdefghijklmnopqrstuvwxyz1234567890")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[mrand.Intn(len(letters))]
	}
	return string(b)
}
