package cert

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/internal/tc3"
)

type TencentConfig struct {
	SecretID, SecretKey string
	Email               string
	Endpoint            string
	HTTPClient          *http.Client
}

type TencentIssuer struct {
	config TencentConfig
	api    tc3.Client
}

func NewTencent(config TencentConfig) (*TencentIssuer, error) {
	if config.SecretID == "" || config.SecretKey == "" || config.Email == "" {
		return nil, &dnsgo.Error{Provider: "tencent", Operation: "new", Code: dnsgo.CodeInvalidInput,
			Message: "SecretId, SecretKey and email are required"}
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = "ssl.tencentcloudapi.com"
	}
	return &TencentIssuer{config: config, api: tc3.Client{KeyID: config.SecretID, Secret: config.SecretKey,
		Service: "ssl", Version: "2019-12-05", Endpoint: endpoint, HTTP: config.HTTPClient}}, nil
}

func (t *TencentIssuer) Kind() string { return "tencent" }

func (t *TencentIssuer) CheckAccount(ctx context.Context) error {
	return t.api.Call(ctx, "DescribeCertificates", map[string]any{}, nil)
}

func (t *TencentIssuer) certificateID(order CloudOrder) (string, error) {
	if order.Provider != t.Kind() || order.ID == "" {
		return "", &dnsgo.Error{Provider: t.Kind(), Operation: "order", Code: dnsgo.CodeInvalidInput,
			Message: "invalid Tencent certificate order"}
	}
	return order.ID, nil
}

type tencentDetail struct {
	OrderID string `json:"OrderId"`
	Status  int    `json:"Status"`
	Message string `json:"StatusMsg"`
	DVAuth  struct {
		Auths []struct {
			Name  string `json:"DvAuthKey"`
			Type  string `json:"DvAuthVerifyType"`
			Value string `json:"DvAuthValue"`
		} `json:"DvAuths"`
	} `json:"DvAuthDetail"`
}

func (t *TencentIssuer) describe(ctx context.Context, id string) (tencentDetail, error) {
	var detail tencentDetail
	err := t.api.Call(ctx, "DescribeCertificate", map[string]any{"CertificateId": id}, &detail)
	return detail, err
}

func (t *TencentIssuer) Start(ctx context.Context, request IssueRequest) (CloudOrder, error) {
	domain, err := oneCloudDomain(t.Kind(), request)
	if err != nil {
		return CloudOrder{}, err
	}
	algorithm := strings.ToUpper(request.KeyAlgorithm)
	if algorithm == "" {
		algorithm = "RSA"
	}
	parameter := "2048"
	if algorithm == "ECC" || algorithm == "EC" || algorithm == "ECDSA" {
		if request.KeySize != 0 && request.KeySize != 256 {
			return CloudOrder{}, &dnsgo.Error{Provider: t.Kind(), Operation: "start", Code: dnsgo.CodeUnsupported,
				Message: "Tencent certificate request supports ECC 256 in the reference flow"}
		}
		algorithm, parameter = "ECC", "prime256v1"
	} else if algorithm != "RSA" || request.KeySize != 0 && request.KeySize != 2048 {
		return CloudOrder{}, &dnsgo.Error{Provider: t.Kind(), Operation: "start", Code: dnsgo.CodeUnsupported,
			Message: "Tencent certificate request supports RSA 2048 in the reference flow"}
	}
	input := map[string]any{"DvAuthMethod": "DNS", "DomainName": domain, "ContactEmail": t.config.Email,
		"CsrEncryptAlgo": algorithm, "CsrKeyParameter": parameter}
	var result struct {
		ID identifier `json:"CertificateId"`
	}
	if err := t.api.Call(ctx, "ApplyCertificate", input, &result); err != nil {
		return CloudOrder{}, err
	}
	if result.ID == "" {
		return CloudOrder{}, &dnsgo.Error{Provider: t.Kind(), Operation: "start", Code: dnsgo.CodeResultUnknown,
			Message: "empty CertificateId"}
	}
	order := CloudOrder{Provider: t.Kind(), ID: result.ID.String(), Domains: []string{domain}, Extra: map[string]string{}}
	detail, err := t.describe(ctx, result.ID.String())
	if err != nil {
		return order, err
	}
	order.Extra["OrderId"] = detail.OrderID
	challenges, err := t.Challenges(ctx, order)
	if err != nil {
		return order, err
	}
	order.Challenges = challenges
	return order, nil
}

func (t *TencentIssuer) Challenges(ctx context.Context, order CloudOrder) ([]DNSChallenge, error) {
	id, err := t.certificateID(order)
	if err != nil {
		return nil, err
	}
	detail, err := t.describe(ctx, id)
	if err != nil {
		return nil, err
	}
	challenges := make([]DNSChallenge, 0, len(detail.DVAuth.Auths))
	for _, auth := range detail.DVAuth.Auths {
		kind := auth.Type
		if kind == "" {
			kind = "CNAME"
		}
		challenges = append(challenges, DNSChallenge{Name: auth.Name, Type: kind, Value: auth.Value})
	}
	if len(challenges) == 0 {
		return nil, &dnsgo.Error{Provider: t.Kind(), Operation: "challenges", Code: dnsgo.CodeResultUnknown,
			Message: "certificate order exists but DNS authorization details are not ready"}
	}
	return challenges, nil
}

func (t *TencentIssuer) SubmitValidation(ctx context.Context, order CloudOrder) error {
	id, err := t.certificateID(order)
	if err != nil {
		return err
	}
	detail, err := t.describe(ctx, id)
	if err != nil {
		return err
	}
	if detail.Status == 0 || detail.Status == 4 {
		if err := t.api.Call(ctx, "CompleteCertificate", map[string]any{"CertificateId": id}, nil); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return nil
}

func (t *TencentIssuer) Status(ctx context.Context, order CloudOrder) (CloudStatus, error) {
	id, err := t.certificateID(order)
	if err != nil {
		return CloudPending, err
	}
	detail, err := t.describe(ctx, id)
	if err != nil {
		return CloudPending, err
	}
	switch detail.Status {
	case 1:
		return CloudIssued, nil
	case 2:
		return CloudRejected, &dnsgo.Error{Provider: t.Kind(), Operation: "status", Code: dnsgo.CodeProvider,
			Message: detail.Message}
	default:
		return CloudPending, nil
	}
}

func (t *TencentIssuer) Download(ctx context.Context, order CloudOrder) (IssueResult, error) {
	id, err := t.certificateID(order)
	if err != nil {
		return IssueResult{}, err
	}
	if err := t.api.Call(ctx, "ModifyCertificatesExpiringNotificationSwitch",
		map[string]any{"CertificateIds": []string{id}, "SwitchStatus": 1}, nil); err != nil {
		return IssueResult{}, err
	}
	var result struct {
		URL string `json:"DownloadCertificateUrl"`
	}
	if err := t.api.Call(ctx, "DescribeDownloadCertificateUrl", map[string]any{"CertificateId": id,
		"ServiceType": "nginx"}, &result); err != nil {
		return IssueResult{}, err
	}
	chain, key, err := downloadCertificateZIP(ctx, t.config.HTTPClient, result.URL)
	if err != nil {
		return IssueResult{}, err
	}
	return certificateResult(t.Kind(), order.Domains, chain, key)
}

func (t *TencentIssuer) Revoke(ctx context.Context, order CloudOrder) ([]DNSChallenge, error) {
	id, err := t.certificateID(order)
	if err != nil {
		return nil, err
	}
	var result struct {
		Auths []struct {
			Name  string `json:"DomainValidateAuthKey"`
			Value string `json:"DomainValidateAuthValue"`
		} `json:"RevokeDomainValidateAuths"`
	}
	if err := t.api.Call(ctx, "RevokeCertificate", map[string]any{"CertificateId": id}, &result); err != nil {
		return nil, err
	}
	challenges := make([]DNSChallenge, 0, len(result.Auths))
	for _, auth := range result.Auths {
		challenges = append(challenges, DNSChallenge{Name: auth.Name, Type: "TXT", Value: auth.Value})
	}
	return challenges, nil
}

func (t *TencentIssuer) Cancel(ctx context.Context, order CloudOrder) error {
	id, err := t.certificateID(order)
	if err != nil {
		return err
	}
	return t.api.Call(ctx, "CancelAuditCertificate", map[string]any{"CertificateId": id}, nil)
}

var _ CloudIssuer = (*TencentIssuer)(nil)
