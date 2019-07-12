package common

import (
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"math/rand"
	"testing"
	"time"
)

var testPolicy = endpoint.Policy{
	[]string{`^[\p{L}\p{N}-_*]+\.vfidev\.com$`, `^[\p{L}\p{N}-_*]+\.vfidev\.net$`, `^[\p{L}\p{N}-_*]+\.vfide\.org$`},
	[]string{`^Venafi Inc\.$`},
	[]string{"^Integration$"},
	[]string{"^Utah$"},
	[]string{"^Salt Lake$"},
	[]string{"^US$"},
	[]endpoint.AllowedKeyConfiguration{{certificate.KeyTypeRSA, []int{2048, 4096, 8192}, nil}},
	[]string{`^[\p{L}\p{N}-_]+\.vfidev\.com$`, `^[\p{L}\p{N}-_]+\.vfidev\.net$`, `^[\p{L}\p{N}-_]+\.vfide\.org$`},
	[]string{".*"},
	[]string{".*"},
	[]string{".*"},
	[]string{".*"},
	true,
	true,
}

func randSeq() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%d", rand.Int63())
}
func TestGetAllPoliciesNames(t *testing.T) {
	names, err := GetAllPoliciesNames()
	if err != nil {
		t.Fatal(err)
	}
	lenNames := len(names)

	policyName := fmt.Sprintf("policy%stest", randSeq())
	if strInSlice(policyName, names) {
		t.Fatal("policy already exists")
	}

	err = SavePolicy(policyName, testPolicy)
	if err != nil {
		t.Fatal(err)
	}
	names, err = GetAllPoliciesNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != lenNames+1 || !strInSlice(policyName, names) {
		t.Fatal("we should add one policy")
	}
}

func TestDeletePolicy(t *testing.T) {
	policyName := fmt.Sprintf("policy%stest", randSeq())
	err := SavePolicy(policyName, testPolicy)
	if err != nil {
		t.Fatal(err)
	}
	p, err := GetPolicy(policyName)
	if err != nil {
		t.Fatal(err)
	}
	if p.SubjectCNRegexes[0] != testPolicy.SubjectCNRegexes[0] {
		t.Fatal("policies are not identical")
	}
	err = DeletePolicy(policyName)
	if err != nil {
		t.Fatal(err)
	}
	_, err = GetPolicy(policyName)
	if err == nil {
		t.Fatal("Policy should be not found")
	}
}

func strInSlice(s string, sl []string) bool {
	for i := range sl {
		if sl[i] == s {
			return true
		}
	}
	return false
}
