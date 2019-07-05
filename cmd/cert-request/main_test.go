package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
)

const (
	csrString = `-----BEGIN CERTIFICATE REQUEST-----
MIIFbDCCA1QCAQAwgbQxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARVdGFoMRIwEAYD
VQQHDAlTYWx0IExha2UxFDASBgNVBAoMC1ZlbmFmaSBJbmMuMRQwEgYDVQQLDAtJ
bnRlZ3JhdGlvbjEnMCUGCSqGSIb3DQEJARYYZW1haWxAdmVuYWZpLmV4YW1wbGUu
Y29tMS0wKwYDVQQDDCR0ZXN0LWNzci0zMjMxMzEzMS52ZW5hZmkuZXhhbXBsZS5j
b20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC4T0bdjq+mF+DABhF+
XWCwOXXUWbPNWa72VVhxoelbyTS0iIeZEe64AvNGykytFdOuT/F9pdkZa+Io07R1
ZMp6Ak8dp2Wjt4c5rayVZus6ZK+0ZwBRJO7if/cqhEpxy8Wz1RMfVLf2AE1u/xZS
QSYY0BTRWGmPqrFJrIGbnyQfvmGVPk3cA0RfdrwYJZXtZ2/4QNrbNCoSoSmqTHzt
NAtZhvT2dPU9U48Prx4b2460x+ck3xA1OdJNXV7n5u53QbxOIcjdGT0lJ62ml70G
5gvEHmdPcg+t5cw/Sm5cfDSUEDtNEXvD4oJXfP98ty6f1cYsZpcrgxRwk9RfGain
hvoweXhZP3NWnU5nRdn2nOfExv+xMeQOyB/rYv98zqzK6LvwKhwI5UB1l/n9KTpg
jgaNCP4x/KAsrPecbHK91oiqGSbPn4wtTYOmPkDxSzATN317u7fE20iqvVAUy/O+
7SCNNKEDPX2NP9LLz0IPK0roQxLiwd2CVyN6kEXuzs/3psptkNRMSlhyeAZdfrOE
CNOp46Pam9f9HGBqzXxxoIlfzLqHHL584kgFlBm7qmivVrgp6zdLPDa+UayXEl2N
O17SnGS8nkOTmfg3cez7lzX/LPLO9X/Y1xKYqx5hoGZhh754K8mzDWCVCYThWgou
yBOYY8uNXiX6ldqzQUHpbxxQgwIDAQABoHIwcAYJKoZIhvcNAQkOMWMwYTBfBgNV
HREEWDBWgilhbHQxLXRlc3QtY3NyLTMyMzEzMTMxLnZlbmFmaS5leGFtcGxlLmNv
bYIpYWx0Mi10ZXN0LWNzci0zMjMxMzEzMS52ZW5hZmkuZXhhbXBsZS5jb20wDQYJ
KoZIhvcNAQELBQADggIBAJd87BIdeh0WWoyQ4IX+ENpNqmm/sLmdfmUB/hj9NpBL
qbr2UTWaSr1jadoZ+mrDxtm1Z0YJDTTIrEWxkBOW5wQ039lYZNe2tfDXSJZwJn7u
2keaXtWQ2SdduK1wOPDO9Hra6WnH7aEq5D1AyoghvPsZwTqZkNynt/A1BZW5C/ha
J9/mwgWfL4qXBGBOhLwKN5GUo3erUkJIdH0TlMqI906D/c/YAuJ86SRdQtBYci6X
bJ7C+OnoiV6USn1HtQE6dfOMeS8voJuixpSIvHZ/Aim6kSAN1Za1f6FQAkyqbF+o
oKTJHDS1CPWikCeLdpPUcOCDIbsiISTsMZkEvIkzZ7dKBIlIugauxw3vaEpk47jN
Wq09r639RbSv/Qs8D6uY66m1IpL4zHm4lTAknrjM/BqihPxc8YiN76ssajvQ4SFT
DHPrDweEVe4KL1ENw8nv4wdkIFKwJTDarV5ZygbETzIhfa2JSBZFTdN+Wmd2Mh5h
OTu+vuHrJF2TO8g1G48EB/KWGt+yvVUpWAanRMwldnFX80NcUlM7GzNn6IXTeE+j
BttIbvAAVJPG8rVCP8u3DdOf+vgm5macj9oLoVP8RBYo/z0E3e+H50nXv3uS6JhN
xlAKgaU6i03jOm5+sww5L2YVMi1eeBN+kx7o94ogpRemC/EUidvl1PUJ6+e7an9V
-----END CERTIFICATE REQUEST-----`
	ACMPCAJSONRequest = `{"SigningAlgorithm":"SHA256WITHRSA","Validity": {"Type": "DAYS","Value": 365},"CertificateAuthorityArn": "%s","Csr": "%s"}`
)

func TestACMPCAHandler(t *testing.T) {
	json := strings.TrimSuffix(fmt.Sprintf(ACMPCAJSONRequest, os.Getenv("ACM_ARN"),
		base64.StdEncoding.EncodeToString([]byte(csrString))), "\n")

	certResp, err := ACMPCAHandler(events.APIGatewayProxyRequest{Body: json})
	if err != nil {
		t.Errorf("Request returned error: %s", err)
	}

	if certResp.StatusCode != 200 {
		t.Errorf("Request returned code: %d message: %s", certResp.StatusCode, certResp.Body)
	}
	assert.True(t, checkCertificate(t, certResp.Body))

}

func checkCertificate(t *testing.T, body string) bool {
	var err error
	certResponse := new(ACMPCAGetCertificateResponse)
	err = json.Unmarshal([]byte(body), certResponse)
	if err != nil {
		t.Errorf("Cant process response json: %s", err)
	}
	rawCert := certResponse.Certificate
	pemBlock, _ := pem.Decode([]byte(rawCert))
	if pemBlock.Bytes == nil {
		t.Errorf("Certificate PEM is nil")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Errorf("Cant parse certificate: %s", err)
	}
	if cert.Subject.CommonName != "test-csr-32313131.venafi.example.com" {
		t.Log("Common name is not as expected")
		return false
	}
	return true
}
