package deploy

import "testing"

func TestNewInheritsCertificateDomainsWithoutMutatingCallerValues(t *testing.T) {
	values := map[string]string{"url": "https://example.com", "token": "test-token"}
	target, err := New("safeline", Config{Values: values, Domains: []string{"one.example.com", "two.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	domains := target.(*Safeline).domains
	if !domains["one.example.com"] || !domains["two.example.com"] || len(domains) != 2 {
		t.Fatalf("inherited domains = %#v", domains)
	}
	if _, ok := values["domainList"]; ok {
		t.Fatal("New mutated the caller's config map")
	}
}

func TestNewKeepsExplicitDeploymentDomainList(t *testing.T) {
	values := map[string]string{"url": "https://example.com", "token": "test-token", "domainList": "only.example.com"}
	target, err := New("safeline", Config{Values: values, Domains: []string{"ignored.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	domains := target.(*Safeline).domains
	if !domains["only.example.com"] || domains["ignored.example.com"] || len(domains) != 1 {
		t.Fatalf("explicit domains = %#v", domains)
	}
}
