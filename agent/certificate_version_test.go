package agent

import "testing"

func TestDeploymentVersionTracksCertificateAndTargetConfiguration(t *testing.T) {
	base := DeploymentConfig{Target: "safeline", Endpoint: "https://example.com", Values: map[string]string{
		"url": "https://example.com", "token": "first",
	}}
	want := deploymentVersion([]byte("certificate-one"), base, []string{"a.example.com", "b.example.com"})
	reordered := DeploymentConfig{Target: base.Target, Endpoint: base.Endpoint, Values: map[string]string{
		"token": "first", "url": "https://example.com",
	}}
	if got := deploymentVersion([]byte("certificate-one"), reordered, []string{"b.example.com", "a.example.com"}); got != want {
		t.Fatal("map or domain order changed the deployment version")
	}
	changed := []struct {
		name    string
		cert    []byte
		target  DeploymentConfig
		domains []string
	}{
		{"certificate", []byte("certificate-two"), base, []string{"a.example.com", "b.example.com"}},
		{"target", []byte("certificate-one"), DeploymentConfig{Target: "opanel", Endpoint: base.Endpoint, Values: base.Values}, []string{"a.example.com", "b.example.com"}},
		{"endpoint", []byte("certificate-one"), DeploymentConfig{Target: base.Target, Endpoint: "https://other.example.com", Values: base.Values}, []string{"a.example.com", "b.example.com"}},
		{"proxy", []byte("certificate-one"), DeploymentConfig{Target: base.Target, Endpoint: base.Endpoint, ProxyURL: "socks5://localhost:1080", Values: base.Values}, []string{"a.example.com", "b.example.com"}},
		{"values", []byte("certificate-one"), DeploymentConfig{Target: base.Target, Endpoint: base.Endpoint, Values: map[string]string{"url": "https://example.com", "token": "second"}}, []string{"a.example.com", "b.example.com"}},
		{"domains", []byte("certificate-one"), base, []string{"a.example.com"}},
	}
	for _, item := range changed {
		if got := deploymentVersion(item.cert, item.target, item.domains); got == want {
			t.Errorf("%s change did not change the deployment version", item.name)
		}
	}
}

func TestManualCertificateTargetValidationDefersDomainList(t *testing.T) {
	config := Config{Certificates: []CertificateConfig{{
		ID: "manual", Authority: "manual", CertFile: "/tmp/dnsgo-manual-cert.pem", KeyFile: "/tmp/dnsgo-manual-key.pem",
		Deployments: []DeploymentConfig{{ID: "edge", Target: "safeline", Endpoint: "https://example.com",
			Values: map[string]string{"token": "test-token"}}},
	}}}
	if _, err := NewRunner(config, &Store{}); err != nil {
		t.Fatalf("manual deployment config should be valid before certificate domains are read: %v", err)
	}
}

func TestCertificateRequestVersions(t *testing.T) {
	base := CertificateConfig{Authority: "letsencrypt", Domains: []string{"A.example.com", "b.example.com."},
		Zones:       []ZoneConfig{{Name: "example.com", ID: "zone-one", Provider: "dns"}},
		Credentials: map[string]string{"token": "one"}}
	issue := certificateIssueVersion(base)
	operation := certificateOperationVersion(base)
	reordered := base
	reordered.Domains = []string{"b.example.com", "a.example.com"}
	reordered.KeyAlgorithm = "RSA"
	reordered.KeySize = 2048
	if certificateIssueVersion(reordered) != issue {
		t.Fatal("equivalent certificate domains or default key settings changed the issuance version")
	}
	changedDomain := base
	changedDomain.Domains = []string{"a.example.com", "c.example.com"}
	if certificateIssueVersion(changedDomain) == issue {
		t.Fatal("new certificate domain did not change issuance version")
	}
	changedZone := base
	changedZone.Zones = []ZoneConfig{{Name: "example.com", ID: "zone-two", Provider: "dns"}}
	if certificateIssueVersion(changedZone) != issue || certificateOperationVersion(changedZone) == operation {
		t.Fatal("DNS binding change should affect only the active operation version")
	}
	changedCredential := base
	changedCredential.Credentials = map[string]string{"token": "two"}
	if certificateIssueVersion(changedCredential) != issue || certificateOperationVersion(changedCredential) == operation {
		t.Fatal("credential change should affect only the active operation version")
	}
	changedProxy := base
	changedProxy.ProxyURL = "http://localhost:8080"
	if certificateIssueVersion(changedProxy) != issue || certificateOperationVersion(changedProxy) == operation {
		t.Fatal("certificate proxy change should affect only the active operation version")
	}
}

func TestCertificateRequestVersionUsesIssuerECCDefault(t *testing.T) {
	for _, authority := range []string{"letsencrypt", "ucloud", "tencent", "aliyun"} {
		config := CertificateConfig{Authority: authority, KeyAlgorithm: "ECC", Domains: []string{"example.com"}}
		implicit := certificateIssueVersion(config)
		defaultSize := 384
		otherSize := 256
		if authority == "tencent" || authority == "aliyun" {
			defaultSize, otherSize = otherSize, defaultSize
		}
		config.KeySize = defaultSize
		if certificateIssueVersion(config) != implicit {
			t.Errorf("%s default ECC key size did not match the issuer", authority)
		}
		config.KeySize = otherSize
		if certificateIssueVersion(config) == implicit {
			t.Errorf("%s explicit ECC size change did not trigger reissuance", authority)
		}
	}
}
