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
	"strings"
	"testing"
	"time"
)

const (
	ACMPCAJSONRequest = `{"SigningAlgorithm":"SHA256WITHRSA","Validity": {"Type": "DAYS","Value": 365},"CertificateAuthorityArn": "%s","Csr": "%s"}`
)

func TestACMPCAHandler(t *testing.T) {
	cn := randSeq(9) + ".example.com"
	jsonBody := strings.TrimSuffix(fmt.Sprintf(ACMPCAJSONRequest, os.Getenv("ACM_ARN"),
		base64.StdEncoding.EncodeToString(createCSR(cn))), "\n")

	certResp, err := ACMPCAHandler(events.APIGatewayProxyRequest{Body: jsonBody})
	if err != nil {
		t.Fatalf("Request returned error: %s", err)
	}

	if certResp.StatusCode != 200 {
		t.Fatalf("Request returned code: %d message: %s", certResp.StatusCode, certResp.Body)
	}
	checkCertificate(t, certResp.Body, cn)

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
