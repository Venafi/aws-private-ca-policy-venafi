package main

import (
	"github.com/Venafi/aws-private-ca-policy-venafi/common"
	"github.com/Venafi/vcert/pkg/endpoint"
	"testing"
)

func TestHandleRequestCloud(t *testing.T) {
	var err error
	vcertConnector, err = getConnection("", "", "", "https://api.dev12.venafi.io", " 20257a71-6be6-4c5f-b0fe-3b7ce98c08d9", "")
	zoneName := "Default"
	unexistedZone := "Unexisted zone olololololo"
	if err != nil {
		t.Fatal(err)
	}
	err = cleanDB()
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
	if p.SubjectCNRegexes[0] != "^.*.example.com$" {
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
