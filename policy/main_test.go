package main

import (
	"encoding/base64"
	"github.com/Venafi/aws-private-ca-policy-venafi/common"
	"github.com/Venafi/vcert/pkg/endpoint"
	"io/ioutil"
	"os"
	"testing"
)

func TestHandleRequestCloud(t *testing.T) {
	var err error
	vcertConnector, err = getConnection("", "", "", os.Getenv("CLOUDURL"), os.Getenv("CLOUDAPIKEY"), "")
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
	trust_bundle, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}

	vcertConnector, err = getConnection(os.Getenv("TPPURL"), os.Getenv("TPPUSER"), os.Getenv("TPPPASSWORD"), "", "", base64.StdEncoding.EncodeToString(trust_bundle))
	if err != nil {
		t.Fatal(err)
	}
	testHandleRequest(t, os.Getenv("TPPZONE"), "UnexistedZone\\Olololololo", `^[\p{L}\p{N}-_*]+\.example\.com$`)
}

func testHandleRequest(t *testing.T, zoneName, unexistedZone, checkRegexp string) {
	err := cleanDB()
	if err != nil {
		t.Fatal(err)
	}
	err = common.SavePolicy(zoneName, endpoint.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	err = common.SavePolicy(unexistedZone, endpoint.Policy{})
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
	_, err = common.GetPolicy(unexistedZone)
	if err == nil {
		t.Fatal("unexisted zone should be removed")
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
