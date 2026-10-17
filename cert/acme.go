// Package cert provides certificate issuance and renewal building blocks.
// Callers own account and certificate persistence; the optional agent stores
// that state for unattended operation.
package cert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"github.com/rainchen537/dnsgo"
)

type Authority string

const (
	LetsEncrypt Authority = "letsencrypt"
	ZeroSSL     Authority = "zerossl"
	Google      Authority = "google"
	LiteSSL     Authority = "litessl"
	CustomACME  Authority = "customacme"
)

// ACMEConfig includes account state when reusing an existing account. The
// caller must persist AccountKeyPEM and AccountURL returned by Issue.
type ACMEConfig struct {
	Authority          Authority
	Mode               string
	Directory          string
	Email              string
	AcceptTerms        bool
	EABKeyID           string
	EABMACKey          string
	EABMode            string // "manual" or "auto" for ZeroSSL and Google.
	EABEndpoint        string // optional override for automatic EAB retrieval.
	AccountKeyPEM      []byte
	AccountURL         string
	HTTPClient         *http.Client
	Zones              []ZoneBinding
	ChallengeAliases   map[string]string
	ChallengeObserver  ChallengeObserver
	PropagationTimeout time.Duration
	PollInterval       time.Duration
}

// ChallengeObserver lets a persistent caller record DNS write intent and the
// resulting record ID before ACME continues. Callbacks must be safe when
// challenges for different names run concurrently.
type ChallengeObserver interface {
	BeforeCreate(context.Context, ChallengeRecord) error
	Created(context.Context, ChallengeRecord) error
	Removed(context.Context, ChallengeRecord) error
}

// ChallengeReuseObserver optionally records an already-existing matching TXT
// record. Reused records are never deleted by the DNS solver.
type ChallengeReuseObserver interface {
	Reused(context.Context, ChallengeRecord) error
}

type ChallengeRecord struct {
	ChallengeURL string
	Provider     string
	ZoneID       string
	Name         string
	Type         string
	Value        string
	RecordID     string
}

type ACMEIssuer struct{ Config ACMEConfig }

type IssueRequest struct {
	Domains           []string
	KeyAlgorithm      string // ECC or RSA; default RSA, as in the reference flow.
	KeySize           int    // ECC: 256 or 384; RSA: 2048, 3072 or 4096.
	CertificateKeyPEM []byte // optional prepared key; persist before remote issuance
}

type IssueResult struct {
	FullChainPEM  []byte
	PrivateKeyPEM []byte
	AccountKeyPEM []byte
	AccountURL    string
	Issuer        string
	Subject       string
	NotBefore     time.Time
	NotAfter      time.Time
	Domains       []string
}

func (c ACMEConfig) directory() (string, error) {
	if c.Directory != "" {
		return c.Directory, nil
	}
	mode := c.Mode
	if mode == "" {
		mode = "live"
	}
	switch c.Authority {
	case LetsEncrypt:
		if mode == "staging" {
			return "https://acme-staging-v02.api.letsencrypt.org/directory", nil
		}
		return "https://acme-v02.api.letsencrypt.org/directory", nil
	case ZeroSSL:
		return "https://acme.zerossl.com/v2/DV90", nil
	case Google:
		if mode == "staging" {
			return "https://dv.acme-v02.test-api.pki.goog/directory", nil
		}
		return "https://dv.acme-v02.api.pki.goog/directory", nil
	case LiteSSL:
		return "https://acme.litessl.com/acme/v2/directory", nil
	case CustomACME:
		return "", &dnsgo.Error{Provider: string(c.Authority), Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "custom ACME directory is required"}
	default:
		return "", &dnsgo.Error{Provider: string(c.Authority), Operation: "new", Code: dnsgo.CodeUnsupported, Message: "unknown ACME authority"}
	}
}

func (c ACMEConfig) validate() (string, error) {
	directory, err := c.directory()
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(directory, "https://") {
		return "", &dnsgo.Error{Provider: string(c.Authority), Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "ACME directory must use HTTPS"}
	}
	if c.Email == "" {
		return "", &dnsgo.Error{Provider: string(c.Authority), Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "email is required"}
	}
	if c.AccountURL != "" && len(c.AccountKeyPEM) == 0 {
		return "", &dnsgo.Error{Provider: string(c.Authority), Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "account key is required with an account URL"}
	}
	if len(c.Zones) == 0 {
		return "", &dnsgo.Error{Provider: string(c.Authority), Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "at least one DNS zone binding is required"}
	}
	if (c.EABKeyID == "") != (c.EABMACKey == "") {
		return "", &dnsgo.Error{Provider: string(c.Authority), Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "EAB key ID and MAC key must be supplied together"}
	}
	if c.EABMode == "auto" && c.Authority != ZeroSSL && c.Authority != Google {
		return "", &dnsgo.Error{Provider: string(c.Authority), Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "automatic EAB is supported only for ZeroSSL and Google"}
	}
	if c.AccountURL == "" && (c.Authority == ZeroSSL || c.Authority == Google || c.Authority == LiteSSL) && c.EABKeyID == "" && c.EABMode != "auto" {
		return "", &dnsgo.Error{Provider: string(c.Authority), Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "EAB credentials are required"}
	}
	return directory, nil
}

func (i *ACMEIssuer) Issue(ctx context.Context, request IssueRequest) (IssueResult, error) {
	cfg := i.Config
	directory, err := cfg.validate()
	if err != nil {
		return IssueResult{}, err
	}
	if len(request.Domains) == 0 || len(request.Domains) > 100 {
		return IssueResult{}, &dnsgo.Error{Provider: string(cfg.Authority), Operation: "issue", Code: dnsgo.CodeInvalidInput, Message: "1 to 100 domains are required"}
	}
	for _, domain := range request.Domains {
		if strings.TrimSpace(domain) == "" {
			return IssueResult{}, &dnsgo.Error{Provider: string(cfg.Authority), Operation: "issue", Code: dnsgo.CodeInvalidInput, Message: "empty domain"}
		}
	}
	if !cfg.AcceptTerms && cfg.AccountURL == "" {
		return IssueResult{}, &dnsgo.Error{Provider: string(cfg.Authority), Operation: "register", Code: dnsgo.CodeInvalidInput, Message: "ACME terms must be accepted by the caller"}
	}
	solver, err := newDNSSolver(cfg.Zones, cfg.ChallengeAliases, cfg.PropagationTimeout, cfg.PollInterval, cfg.ChallengeObserver)
	if err != nil {
		return IssueResult{}, err
	}
	api := &acme.Client{Directory: directory, HTTPClient: cfg.HTTPClient}
	client := &acmez.Client{Client: api, ChallengeSolvers: map[string]acmez.Solver{acme.ChallengeTypeDNS01: solver}}
	accountKey, accountPEM, err := loadOrCreateAccountKey(cfg.AccountKeyPEM)
	if err != nil {
		return IssueResult{}, err
	}
	partial := IssueResult{AccountKeyPEM: accountPEM}
	certPEM, err := PrepareCertificateKey(request.CertificateKeyPEM, request.KeyAlgorithm, request.KeySize)
	if err != nil {
		return partial, err
	}
	partial.PrivateKeyPEM = certPEM
	certKey, err := parseSigner(certPEM)
	if err != nil {
		return partial, err
	}
	account := acme.Account{Contact: []string{"mailto:" + cfg.Email}, TermsOfServiceAgreed: cfg.AcceptTerms,
		PrivateKey: accountKey, Location: cfg.AccountURL}
	if account.Location == "" {
		eabID, eabKey := cfg.EABKeyID, cfg.EABMACKey
		if eabID == "" && cfg.EABMode == "auto" {
			eabID, eabKey, err = cfg.fetchEAB(ctx)
			if err != nil {
				return partial, err
			}
		}
		if eabID != "" {
			mac, err := normalizeEABKey(eabKey)
			if err != nil {
				return partial, err
			}
			if err := account.SetExternalAccountBinding(ctx, api, acme.EAB{KeyID: eabID, MACKey: mac}); err != nil {
				return partial, fmt.Errorf("prepare ACME EAB: %w", err)
			}
		}
		account, err = api.NewAccount(ctx, account)
		if err != nil {
			return partial, fmt.Errorf("register ACME account: %w", err)
		}
	} else {
		account.Status = "valid"
	}
	partial.AccountURL = account.Location
	chains, err := client.ObtainCertificateForSANs(ctx, account, certKey, request.Domains)
	if err != nil {
		return partial, fmt.Errorf("obtain ACME certificate: %w", err)
	}
	if len(chains) == 0 {
		return partial, &dnsgo.Error{Provider: string(cfg.Authority), Operation: "issue", Code: dnsgo.CodeResultUnknown, Message: "ACME server returned no certificate chain"}
	}
	block, _ := pem.Decode(chains[0].ChainPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return partial, &dnsgo.Error{Provider: string(cfg.Authority), Operation: "issue", Code: dnsgo.CodeResultUnknown, Message: "invalid certificate chain"}
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return partial, &dnsgo.Error{Provider: string(cfg.Authority), Operation: "issue", Code: dnsgo.CodeResultUnknown, Message: "invalid leaf certificate", Cause: err}
	}
	return IssueResult{FullChainPEM: chains[0].ChainPEM, PrivateKeyPEM: certPEM, AccountKeyPEM: accountPEM,
		AccountURL: account.Location, Issuer: leaf.Issuer.CommonName, Subject: leaf.Subject.CommonName,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Domains: append([]string(nil), request.Domains...)}, nil
}

// Renew issues a replacement using the same ACME account. Callers decide when
// renewal is due and must persist the account state returned by Issue.
func (i *ACMEIssuer) Renew(ctx context.Context, request IssueRequest) (IssueResult, error) {
	return i.Issue(ctx, request)
}

// Revoke revokes a certificate with its certificate key when provided, or
// with the stored ACME account key otherwise. Revocation cannot be undone.
func (i *ACMEIssuer) Revoke(ctx context.Context, fullChainPEM, certificateKeyPEM []byte, reason int) error {
	cfg := i.Config
	directory, err := cfg.directory()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(directory, "https://") {
		return &dnsgo.Error{Provider: string(cfg.Authority), Operation: "revoke", Code: dnsgo.CodeInvalidInput, Message: "ACME directory must use HTTPS"}
	}
	if reason < 0 || reason > acme.ReasonAACompromise || reason == 7 {
		return &dnsgo.Error{Provider: string(cfg.Authority), Operation: "revoke", Code: dnsgo.CodeInvalidInput, Message: "invalid revocation reason"}
	}
	if len(cfg.AccountKeyPEM) == 0 || cfg.AccountURL == "" {
		return &dnsgo.Error{Provider: string(cfg.Authority), Operation: "revoke", Code: dnsgo.CodeInvalidInput, Message: "existing ACME account key and URL are required"}
	}
	accountKey, err := parseSigner(cfg.AccountKeyPEM)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(fullChainPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return &dnsgo.Error{Provider: string(cfg.Authority), Operation: "revoke", Code: dnsgo.CodeInvalidInput, Message: "invalid certificate PEM"}
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	key := accountKey
	if len(certificateKeyPEM) > 0 {
		key, err = parseSigner(certificateKeyPEM)
		if err != nil {
			return err
		}
	}
	api := &acme.Client{Directory: directory, HTTPClient: cfg.HTTPClient}
	account := acme.Account{PrivateKey: accountKey, Location: cfg.AccountURL, Status: "valid"}
	return api.RevokeCertificate(ctx, account, leaf, key, reason)
}

func loadOrCreateAccountKey(value []byte) (crypto.Signer, []byte, error) {
	if len(value) != 0 {
		key, err := parseSigner(value)
		return key, value, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ACME account key: %w", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}

// PrepareAccountKey returns a validated existing ACME account key or creates
// one so a resident runner can persist it before starting a network request.
func PrepareAccountKey(value []byte) ([]byte, error) {
	_, encoded, err := loadOrCreateAccountKey(value)
	return encoded, err
}

func newCertificateKey(algorithm string, size int) (crypto.Signer, []byte, error) {
	var signer crypto.Signer
	var err error
	switch strings.ToUpper(algorithm) {
	case "ECC", "EC", "ECDSA":
		if size == 0 {
			size = 384
		}
		curve := elliptic.P384()
		if size == 256 {
			curve = elliptic.P256()
		} else if size != 384 {
			return nil, nil, errors.New("ECC key size must be 256 or 384")
		}
		signer, err = ecdsa.GenerateKey(curve, rand.Reader)
	case "", "RSA":
		if size == 0 {
			size = 2048
		}
		if size != 2048 && size != 3072 && size != 4096 {
			return nil, nil, errors.New("RSA key size must be 2048, 3072 or 4096")
		}
		signer, err = rsa.GenerateKey(rand.Reader, size)
	default:
		return nil, nil, errors.New("unsupported certificate key algorithm")
	}
	if err != nil {
		return nil, nil, err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, nil, err
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}

// PrepareCertificateKey creates or validates the key that will sign an ACME
// certificate request. Persist the returned PEM before calling Issue.
func PrepareCertificateKey(existing []byte, algorithm string, size int) ([]byte, error) {
	if len(existing) == 0 {
		_, encoded, err := newCertificateKey(algorithm, size)
		return encoded, err
	}
	signer, err := parseSigner(existing)
	if err != nil {
		return nil, err
	}
	switch strings.ToUpper(algorithm) {
	case "", "RSA":
		key, ok := signer.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("prepared certificate key is not RSA")
		}
		if size == 0 {
			size = 2048
		}
		if size != 2048 && size != 3072 && size != 4096 || key.N.BitLen() != size {
			return nil, errors.New("prepared RSA key size does not match request")
		}
	case "ECC", "EC", "ECDSA":
		key, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("prepared certificate key is not ECC")
		}
		if size == 0 {
			size = 384
		}
		if size != 256 && size != 384 || key.Curve.Params().BitSize != size {
			return nil, errors.New("prepared ECC key size does not match request")
		}
	default:
		return nil, errors.New("unsupported certificate key algorithm")
	}
	return append([]byte(nil), existing...), nil
}

func parseSigner(value []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(value)
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key PEM")
}

func normalizeEABKey(value string) (string, error) {
	if data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "=")); err == nil {
		return base64.RawURLEncoding.EncodeToString(data), nil
	}
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", &dnsgo.Error{Provider: "acme", Operation: "eab", Code: dnsgo.CodeInvalidInput, Message: "invalid EAB MAC key"}
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func (c ACMEConfig) fetchEAB(ctx context.Context) (string, string, error) {
	endpoint := c.EABEndpoint
	method := http.MethodGet
	var body io.Reader
	switch c.Authority {
	case ZeroSSL:
		if endpoint == "" {
			endpoint = "https://api.zerossl.com/acme/eab-credentials-email"
		}
		method = http.MethodPost
		body = strings.NewReader(url.Values{"email": {c.Email}}.Encode())
	case Google:
		if endpoint == "" {
			// This optional upstream path uses a third-party EAB broker.
			endpoint = "https://gts.rat.dev/eab"
		}
	default:
		return "", "", dnsgo.Unsupported(string(c.Authority), "automatic_eab")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", "", &dnsgo.Error{Provider: string(c.Authority), Operation: "eab", Code: dnsgo.CodeInvalidInput, Message: "automatic EAB endpoint must use HTTPS"}
	}
	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), body)
	if err != nil {
		return "", "", &dnsgo.Error{Provider: string(c.Authority), Operation: "eab", Code: dnsgo.CodeInvalidInput, Message: "invalid EAB request"}
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	response, err := client.Do(req)
	if err != nil {
		return "", "", &dnsgo.Error{Provider: string(c.Authority), Operation: "eab", Code: dnsgo.CodeTransport, Message: "automatic EAB request failed"}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", "", &dnsgo.Error{Provider: string(c.Authority), Operation: "eab", Code: dnsgo.CodeProvider, Message: "automatic EAB endpoint rejected request"}
	}
	var result struct {
		Success bool   `json:"success"`
		KID     string `json:"eab_kid"`
		HMACKey string `json:"eab_hmac_key"`
		Msg     string `json:"msg"`
		Data    struct {
			KeyID  string `json:"key_id"`
			MACKey string `json:"mac_key"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil {
		return "", "", &dnsgo.Error{Provider: string(c.Authority), Operation: "eab", Code: dnsgo.CodeResultUnknown, Message: "invalid automatic EAB response"}
	}
	if c.Authority == ZeroSSL && result.Success && result.KID != "" && result.HMACKey != "" {
		return result.KID, result.HMACKey, nil
	}
	if c.Authority == Google && result.Msg == "success" && result.Data.KeyID != "" && result.Data.MACKey != "" {
		return result.Data.KeyID, result.Data.MACKey, nil
	}
	return "", "", &dnsgo.Error{Provider: string(c.Authority), Operation: "eab", Code: dnsgo.CodeProvider, Message: "automatic EAB response was unsuccessful or incomplete"}
}
