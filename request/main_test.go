package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	mrand "math/rand"
	"os"
	"testing"
	"time"
)

const (
	ACMPCAJSONRequest = `{
		"SigningAlgorithm":"SHA256WITHRSA",
		"Validity": {"Type": "DAYS","Value": 365},
		"CertificateAuthorityArn": "%s","Csr": "%s"
	}`
	acmpcaListCertificateAuthoritiesRequest = `{"MaxResults": 10}`
	acmpcaGetCertificateRequest             = `{
		"CertificateArn": "arn:aws:acm-pca:region:account:certificate-authority/12345678-1234-1234-1234-123456789012/certificate/e8cbd2bedb122329f97706bcfec990f8"
		,"CertificateAuthorityArn": "%s"
	}`
)

func TestACMPCAHandler(t *testing.T) {
	cn := randSeq(9) + ".example.com"
	jsonBody := fmt.Sprintf(ACMPCAJSONRequest, os.Getenv("ACM_ARN"),
		base64.StdEncoding.EncodeToString(createCSR(cn)))

	headers := map[string]string{"X-Amz-Target": "ACMPrivateCA.IssueCertificate"}

	certResp, err := ACMPCAHandler(events.APIGatewayProxyRequest{
		Body:    jsonBody,
		Headers: headers,
	})
	if err != nil {
		t.Fatalf("Request returned error: %s", err)
	}

	if certResp.StatusCode != 200 {
		t.Fatalf("Request returned code: %d message: %s", certResp.StatusCode, certResp.Body)
	}
	checkCertificate(t, certResp.Body, cn)

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
			t.Fatalf("Request returned code: %d message: %s", certResp.StatusCode, certResp.Body)
		}
		t.Logf("Resp is:\n %s", certResp.Body)
	}

}

func checkCertificate(t *testing.T, body string, cn string) {
	var err error
	certResponse := new(ACMPCAGetCertificateResponse)
	err = json.Unmarshal([]byte(body), certResponse)
	if err != nil {
		t.Fatalf("Cant process response json: %s", err)
	}
	rawCert := certResponse.Certificate
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
	t.Logf("Certificate is ok:\n %s", certResponse.Certificate)
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
