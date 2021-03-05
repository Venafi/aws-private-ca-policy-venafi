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
	"go/types"
	"log"
	mrand "math/rand"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	wrongResponseCode = "Request returned code: %d message: %s"

	acmpcaListCertificateAuthoritiesRequest = `{"MaxResults": 100}`
	acmpcaIssueCertificateRequest           = `{
		"SigningAlgorithm":"SHA256WITHRSA",
		"Validity": {"Type": "DAYS","Value": 365},
		"CertificateAuthorityArn": "%s",
		"Csr": "%s"
	}`
	acmpcaGetCertificateRequest = `{
		"CertificateArn": "%s",
		"CertificateAuthorityArn": "%s"
	}`

	acmRequestCertificateRequest = `{
   		"CertificateAuthorityArn": "%s",
   		"DomainName": "%s"
	}`
	acmGetCertificateRequest = `{
		"CertificateArn": "%s"
	}`
)

func TestACMPCACertificate(t *testing.T) {
	ctx := context.TODO()

	awsCfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		t.Fatalf("Can't get AWS configuration: %s", err)
	}
	acmpcaCli := acmpca.New(awsCfg)
	acmpcaArn := getACMPCAArn(t)

	cn := randSeq(9) + ".example.com"
	jsonBody := fmt.Sprintf(acmpcaIssueCertificateRequest, acmpcaArn,
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

	log.Printf("Certificate CN is:%s\nCertificate Arn is: %s", cn, issueResponse.CertificateArn)

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

func TestACMCertificate(t *testing.T) {
	cn := randSeq(9) + ".example.com"
	acmpcaArn := getACMPCAArn(t)

	jsonBody := fmt.Sprintf(acmRequestCertificateRequest, acmpcaArn, cn)

	headers := map[string]string{"X-Amz-Target": acmRequestCertificate}

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
	log.Printf("Certificate CN is:%s\nCertificate Arn is: %s", cn, issueResponse.CertificateArn)

	headers = map[string]string{"X-Amz-Target": acmGetCertificate}
	jsonBody = fmt.Sprintf(acmGetCertificateRequest, issueResponse.CertificateArn)

	requestCertResp, err := waitForCertificate(headers, jsonBody, 120000)

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

func TestListCertificateAuthoritiesPassThru(t *testing.T) {
	var headers map[string]string
	targets := map[string]string{
		acmpcaListCertificateAuthorities: acmpcaListCertificateAuthoritiesRequest,
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
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 4096)
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

func getACMPCAArn(t *testing.T) string {
	arnListReq, err := ACMPCAHandler(events.APIGatewayProxyRequest{
		Body:    acmpcaListCertificateAuthoritiesRequest,
		Headers: map[string]string{"X-Amz-Target": acmpcaListCertificateAuthorities},
	})
	if err != nil {
		t.Fatalf("Request returned error: %s", err)
	}
	var arn string
	listArn := &acmpca.ListCertificateAuthoritiesResponse{}
	err = json.Unmarshal([]byte(arnListReq.Body), listArn)
	for _, ca := range listArn.CertificateAuthorities {
		if ca.Status == "ACTIVE" {
			arn = *ca.Arn
			break
		}
	}
	//arn := *listArn.CertificateAuthorities[0].Arn
	if len(arn) < 1 {
		t.Fatalf("ACMPCA is empty")
	}
	return arn
}

//waitForCertificate loops until the certificate gets issued or time runs out.
//This is necessary when the certificate has been recently requested.
func waitForCertificate(headers map[string]string, jsonBody string, timeout int) (events.APIGatewayProxyResponse, error) {
	timeSlept := 0

	var err = types.Error{}

	for timeSlept < timeout {
		requestCertResp, err := ACMPCAHandler(events.APIGatewayProxyRequest{
			Body:    jsonBody,
			Headers: headers,
		})

		if err != nil {
			return requestCertResp, err
		}

		if requestCertResp.StatusCode != 200 {
			if strings.Contains(requestCertResp.Body, "RequestInProgressException") {
				time.Sleep(10 * time.Second)
				timeSlept += 10000
			} else {
				return clientError(http.StatusInternalServerError, fmt.Sprintf("Could not get certificate: %s", err))
			}
		} else {
			return requestCertResp, nil
		}
	}

	return clientError(http.StatusInternalServerError, fmt.Sprintf("Could not get certificate: %s", err))
}
