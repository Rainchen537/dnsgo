package cert

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type DNSChallenge struct {
	Name  string // fully qualified challenge record name
	Type  string
	Value string
}

type CloudOrder struct {
	Provider   string
	ID         string
	Domains    []string
	Challenges []DNSChallenge
	Extra      map[string]string
}

type CloudStatus string

const (
	CloudPending  CloudStatus = "pending"
	CloudIssued   CloudStatus = "issued"
	CloudRejected CloudStatus = "rejected"
)

// CloudIssuer exposes the stages needed by consumers and the optional agent.
// Callers persist CloudOrder and create the returned DNS challenges through
// the provider SDK before SubmitValidation.
type CloudIssuer interface {
	Kind() string
	CheckAccount(context.Context) error
	Start(context.Context, IssueRequest) (CloudOrder, error)
	Challenges(context.Context, CloudOrder) ([]DNSChallenge, error)
	SubmitValidation(context.Context, CloudOrder) error
	Status(context.Context, CloudOrder) (CloudStatus, error)
	Download(context.Context, CloudOrder) (IssueResult, error)
	Revoke(context.Context, CloudOrder) ([]DNSChallenge, error)
	Cancel(context.Context, CloudOrder) error
}

func oneCloudDomain(provider string, request IssueRequest) (string, error) {
	if len(request.Domains) != 1 || strings.TrimSpace(request.Domains[0]) == "" {
		return "", &dnsgo.Error{Provider: provider, Operation: "start", Code: dnsgo.CodeInvalidInput,
			Message: "this certificate service requires exactly one domain"}
	}
	domain := strings.TrimSpace(request.Domains[0])
	if strings.HasPrefix(domain, "*.") {
		return "", &dnsgo.Error{Provider: provider, Operation: "start", Code: dnsgo.CodeUnsupported,
			Message: "wildcard certificates are not supported by this reference cloud service"}
	}
	return strings.TrimSuffix(domain, "."), nil
}

func certificateResult(provider string, domains []string, chain, key []byte) (IssueResult, error) {
	if _, err := tls.X509KeyPair(chain, key); err != nil {
		return IssueResult{}, &dnsgo.Error{Provider: provider, Operation: "download", Code: dnsgo.CodeResultUnknown,
			Message: "certificate and private key do not match", Cause: err}
	}
	block, _ := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return IssueResult{}, &dnsgo.Error{Provider: provider, Operation: "download", Code: dnsgo.CodeResultUnknown,
			Message: "invalid certificate chain"}
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return IssueResult{}, err
	}
	for _, domain := range domains {
		if err := leaf.VerifyHostname(strings.TrimSuffix(domain, ".")); err != nil {
			return IssueResult{}, &dnsgo.Error{Provider: provider, Operation: "download", Code: dnsgo.CodeResultUnknown,
				Message: "downloaded certificate does not cover the requested domain", Cause: err}
		}
	}
	return IssueResult{FullChainPEM: chain, PrivateKeyPEM: key, Issuer: leaf.Issuer.CommonName,
		Subject: leaf.Subject.CommonName, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
		Domains: append([]string(nil), domains...)}, nil
}

// ImportPEM validates a manually supplied certificate and private key, then
// returns the same material type used by automated issuers and deploy targets.
func ImportPEM(chain, key []byte) (IssueResult, error) {
	result, err := certificateResult("manual", nil, chain, key)
	if err != nil {
		return IssueResult{}, err
	}
	block, _ := pem.Decode(chain)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	result.Domains = append([]string(nil), leaf.DNSNames...)
	if len(result.Domains) == 0 && leaf.Subject.CommonName != "" {
		result.Domains = []string{leaf.Subject.CommonName}
	}
	return result, nil
}

func downloadCertificateZIP(ctx context.Context, client *http.Client, source string) ([]byte, []byte, error) {
	parsed, err := url.Parse(source)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, nil, errors.New("certificate download URL must use HTTPS")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, nil, errors.New("invalid certificate download request")
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, nil, errors.New("certificate download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("certificate download returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return nil, nil, err
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil, errors.New("invalid certificate ZIP")
	}
	type candidate struct {
		name string
		data []byte
	}
	var certificates, keys []candidate
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || file.UncompressedSize64 > 4<<20 {
			continue
		}
		lower := strings.ToLower(file.Name)
		if !strings.HasSuffix(lower, ".key") && !strings.HasSuffix(lower, ".crt") &&
			!strings.HasSuffix(lower, ".cer") && !strings.HasSuffix(lower, ".pem") {
			continue
		}
		stream, err := file.Open()
		if err != nil {
			return nil, nil, err
		}
		content, readErr := io.ReadAll(io.LimitReader(stream, 4<<20))
		closeErr := stream.Close()
		if readErr != nil {
			return nil, nil, readErr
		}
		if closeErr != nil {
			return nil, nil, closeErr
		}
		if bytes.Contains(content, []byte("BEGIN CERTIFICATE")) {
			certificates = append(certificates, candidate{name: lower, data: content})
		}
		if bytes.Contains(content, []byte("PRIVATE KEY")) {
			keys = append(keys, candidate{name: lower, data: content})
		}
	}
	if len(certificates) == 0 || len(keys) == 0 {
		return nil, nil, errors.New("certificate ZIP contains no matching PEM and key files")
	}
	sort.SliceStable(certificates, func(i, j int) bool {
		priority := func(name string) int {
			if strings.Contains(name, "fullchain") || strings.Contains(name, "bundle") {
				return 0
			}
			if strings.Contains(name, "server") || strings.Contains(name, "domain") {
				return 1
			}
			return 2
		}
		return priority(certificates[i].name) < priority(certificates[j].name)
	})
	for _, certificate := range certificates {
		for _, key := range keys {
			if _, err := tls.X509KeyPair(certificate.data, key.data); err == nil {
				return certificate.data, key.data, nil
			}
		}
	}
	return nil, nil, errors.New("certificate ZIP has no matching certificate and private key")
}
