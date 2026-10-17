package cert

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/internal/ucloud"
)

type UCloudConfig struct {
	PublicKey, PrivateKey  string
	UserName, Phone, Email string
	CompanyName            string
	CompanyAddress         string
	CompanyRegion          string
	CompanyCity            string
	CompanyCountry         string
	CompanyDivision        string
	CompanyPostalCode      string
	AdminTitle             string
	Endpoint               string
	HTTPClient             *http.Client
}

type UCloudIssuer struct {
	config UCloudConfig
	api    ucloud.Client
}

func NewUCloud(config UCloudConfig) (*UCloudIssuer, error) {
	if config.PublicKey == "" || config.PrivateKey == "" || config.UserName == "" || config.Phone == "" || config.Email == "" {
		return nil, &dnsgo.Error{Provider: "ucloud", Operation: "new", Code: dnsgo.CodeInvalidInput,
			Message: "PublicKey, PrivateKey, user name, phone and email are required"}
	}
	return &UCloudIssuer{config: config, api: ucloud.Client{PublicKey: config.PublicKey, PrivateKey: config.PrivateKey,
		Endpoint: config.Endpoint, HTTP: config.HTTPClient}}, nil
}

func (u *UCloudIssuer) Kind() string { return "ucloud" }

func (u *UCloudIssuer) CheckAccount(ctx context.Context) error {
	return u.api.Call(ctx, "GetCertificateList", map[string]any{"Mode": "free"}, nil)
}

func (u *UCloudIssuer) certificateID(order CloudOrder) (string, error) {
	if order.Provider != u.Kind() || order.ID == "" {
		return "", &dnsgo.Error{Provider: u.Kind(), Operation: "order", Code: dnsgo.CodeInvalidInput, Message: "invalid UCloud certificate order"}
	}
	return order.ID, nil
}

func (u *UCloudIssuer) Start(ctx context.Context, request IssueRequest) (CloudOrder, error) {
	domain, err := oneCloudDomain(u.Kind(), request)
	if err != nil {
		return CloudOrder{}, err
	}
	algorithm, parameter, err := u.keyParameter(request)
	if err != nil {
		return CloudOrder{}, err
	}
	var purchased struct {
		ID identifier `json:"CertificateID"`
	}
	params := map[string]any{"CertificateBrand": "TrustAsia", "CertificateName": "TrustAsiaC1DVFree",
		"DomainsCount": 1, "ValidYear": 1}
	if err := u.api.Call(ctx, "PurchaseCertificate", params, &purchased); err != nil {
		return CloudOrder{}, err
	}
	if purchased.ID == "" {
		return CloudOrder{}, &dnsgo.Error{Provider: u.Kind(), Operation: "purchase", Code: dnsgo.CodeResultUnknown, Message: "empty CertificateID"}
	}
	order := CloudOrder{Provider: u.Kind(), ID: purchased.ID.String(), Domains: []string{domain}}
	complement := map[string]any{
		"CertificateID": purchased.ID.String(), "Domains": domain, "CSROnline": 1,
		"CSREncryptAlgo": algorithm, "CSRKeyParameter": parameter,
		"CompanyName":       defaultString(u.config.CompanyName, "公司名称"),
		"CompanyAddress":    defaultString(u.config.CompanyAddress, "公司地址"),
		"CompanyRegion":     defaultString(u.config.CompanyRegion, "北京"),
		"CompanyCity":       defaultString(u.config.CompanyCity, "北京"),
		"CompanyCountry":    defaultString(u.config.CompanyCountry, "CN"),
		"CompanyDivision":   defaultString(u.config.CompanyDivision, "部门"),
		"CompanyPhone":      u.config.Phone,
		"CompanyPostalCode": defaultString(u.config.CompanyPostalCode, "110100"),
		"AdminName":         u.config.UserName, "AdminPhone": u.config.Phone, "AdminEmail": u.config.Email,
		"AdminTitle": defaultString(u.config.AdminTitle, "职员"), "DVAuthMethod": "DNS",
	}
	if err := u.api.Call(ctx, "ComplementCSRInfo", complement, nil); err != nil {
		return order, err
	}
	challenges, err := u.Challenges(ctx, order)
	if err != nil {
		return order, err
	}
	order.Challenges = challenges
	return order, nil
}

func (u *UCloudIssuer) Challenges(ctx context.Context, order CloudOrder) ([]DNSChallenge, error) {
	id, err := u.certificateID(order)
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 10; attempt++ {
		var result struct {
			Auths []struct {
				Name  string `json:"AuthKey"`
				Type  string `json:"AuthType"`
				Value string `json:"AuthValue"`
			} `json:"Auths"`
		}
		if err := u.api.Call(ctx, "GetDVAuthInfo", map[string]any{"CertificateID": id}, &result); err != nil {
			return nil, err
		}
		if len(result.Auths) > 0 {
			challenges := make([]DNSChallenge, 0, len(result.Auths))
			for _, auth := range result.Auths {
				kind := "CNAME"
				if auth.Type == "DNS_TXT" {
					kind = "TXT"
				}
				challenges = append(challenges, DNSChallenge{Name: auth.Name, Type: kind, Value: auth.Value})
			}
			return challenges, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return nil, &dnsgo.Error{Provider: u.Kind(), Operation: "challenges", Code: dnsgo.CodeResultUnknown,
		Message: "certificate order exists but DNS authorization details are not ready"}
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func (u *UCloudIssuer) keyParameter(request IssueRequest) (string, string, error) {
	algorithm := strings.ToUpper(request.KeyAlgorithm)
	size := request.KeySize
	if algorithm == "" || algorithm == "RSA" {
		if size == 0 {
			size = 2048
		}
		if size != 2048 && size != 3072 {
			return "", "", errors.New("UCloud RSA key size must be 2048 or 3072")
		}
		return "RSA", strconv.Itoa(size), nil
	}
	if algorithm == "ECC" || algorithm == "EC" || algorithm == "ECDSA" {
		if size == 0 {
			size = 384
		}
		switch size {
		case 256:
			return "ECDSA", "prime256v1", nil
		case 384:
			return "ECDSA", "prime384v1", nil
		}
	}
	return "", "", errors.New("unsupported UCloud certificate key type or size")
}

func (u *UCloudIssuer) SubmitValidation(context.Context, CloudOrder) error { return nil }

func (u *UCloudIssuer) Status(ctx context.Context, order CloudOrder) (CloudStatus, error) {
	id, err := u.certificateID(order)
	if err != nil {
		return CloudPending, err
	}
	var result struct {
		Info struct {
			StateCode string `json:"StateCode"`
			State     string `json:"State"`
		} `json:"CertificateInfo"`
	}
	if err := u.api.Call(ctx, "GetCertificateDetailInfo", map[string]any{"CertificateID": id}, &result); err != nil {
		return CloudPending, err
	}
	switch result.Info.StateCode {
	case "COMPLETED", "RENEWED":
		return CloudIssued, nil
	case "REJECTED", "SECURITY_REVIEW_FAILED":
		return CloudRejected, &dnsgo.Error{Provider: u.Kind(), Operation: "status", Code: dnsgo.CodeProvider, Message: result.Info.State}
	default:
		return CloudPending, nil
	}
}

func (u *UCloudIssuer) Download(ctx context.Context, order CloudOrder) (IssueResult, error) {
	id, err := u.certificateID(order)
	if err != nil {
		return IssueResult{}, err
	}
	var result struct {
		URL string `json:"CertificateUrl"`
	}
	if err := u.api.Call(ctx, "DownloadCertificate", map[string]any{"CertificateID": id}, &result); err != nil {
		return IssueResult{}, err
	}
	chain, key, err := downloadCertificateZIP(ctx, u.config.HTTPClient, result.URL)
	if err != nil {
		return IssueResult{}, err
	}
	return certificateResult(u.Kind(), order.Domains, chain, key)
}

func (u *UCloudIssuer) Revoke(ctx context.Context, order CloudOrder) ([]DNSChallenge, error) {
	id, err := u.certificateID(order)
	if err != nil {
		return nil, err
	}
	err = u.api.Call(ctx, "RevokeCertificate", map[string]any{"CertificateID": id, "Reason": "业务终止"}, nil)
	return nil, err
}

func (u *UCloudIssuer) Cancel(ctx context.Context, order CloudOrder) error {
	id, err := u.certificateID(order)
	if err != nil {
		return err
	}
	if err := u.api.Call(ctx, "CancelCertificateOrder", map[string]any{"CertificateID": id}, nil); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Second):
	}
	return u.api.Call(ctx, "DeleteSSLCertificate", map[string]any{"CertificateID": id, "CertificateMode": "purchase"}, nil)
}

var _ CloudIssuer = (*UCloudIssuer)(nil)
