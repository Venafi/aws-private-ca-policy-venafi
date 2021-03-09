package main

import (
	"encoding/base64"
	"github.com/Venafi/aws-private-ca-policy-venafi/common"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"io/ioutil"
	"os"
	"testing"
)

func TestHandleRequestCloud(t *testing.T) {
	var err error
	vcertConnector, err = getConnection("", "", "", "", "", os.Getenv("CLOUDAPIKEY"), "")
	if err != nil {
		t.Fatal(err)
	}
	testHandleRequest(t, os.Getenv("CLOUDZONE"), "UnexistedZoneOlololololo", "^.*.example.com$")
}

func TestHandleRequestTPP(t *testing.T) {
	f, err := os.Open(os.Getenv("TRUST_BUNDLE"))
	if err != nil {
		t.Fatal(err)
	}
	trustBundle, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}

	vcertConnector, err = getConnection(os.Getenv("TPPURL"), os.Getenv("TPPUSER"), os.Getenv("TPPPASSWORD"), "", "", "", base64.StdEncoding.EncodeToString(trustBundle))
	if err != nil {
		t.Fatal(err)
	}
	testHandleRequest(t, os.Getenv("TPPZONE"), "UnexistedZone\\Olololololo", ".*")
}

func TestHandleRequestTPPToken(t *testing.T) {
	f, err := os.Open(os.Getenv("TRUST_BUNDLE"))
	if err != nil {
		t.Fatal(err)
	}
	trustBundle, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}

	vcertConnector, err = getConnection(os.Getenv("TPP_TOKEN_URL"), "", "", os.Getenv("TPP_ACCESS_TOKEN"), os.Getenv("TPP_REFRESH_TOKEN"), "", base64.StdEncoding.EncodeToString(trustBundle))
	if err != nil {
		t.Fatal(err)
	}
	testHandleRequest(t, os.Getenv("TPPZONE"), "UnexistedZone\\Olololololo", ".*")
}

func testHandleRequest(t *testing.T, zoneName, invalidZone, checkRegexp string) {
	err := cleanDB()
	if err != nil {
		t.Fatal(err)
	}
	err = common.SavePolicy(zoneName, endpoint.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	err = common.SavePolicy(invalidZone, endpoint.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	err = HandleRequest()
	if err != nil {
		t.Fatal(err)
	}
	p, err := common.GetPolicy(zoneName)
	if err != nil {
		t.Fatal(err)
	}
	if p.SubjectCNRegexes[0] != checkRegexp {
		t.Fatalf("bad policy")
	}
	_, err = common.GetPolicy(invalidZone)
	if err == nil {
		t.Fatal("invalid zone should be removed")
	}
}

func cleanDB() error {
	names, err := common.GetAllPoliciesNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		err = common.DeletePolicy(name)
		if err != nil {
			return err
		}
	}
	return nil
}
