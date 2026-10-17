package cert

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/internal/aliyunrpc"
)

type AliyunConfig struct {
	AccessKeyID, AccessKeySecret string
	Endpoint                     string
	HTTPClient                   *http.Client
}

type AliyunIssuer struct {
	api aliyunrpc.Client
}

func NewAliyun(config AliyunConfig) (*AliyunIssuer, error) {
	if config.AccessKeyID == "" || config.AccessKeySecret == "" {
		return nil, &dnsgo.Error{Provider: "aliyun", Operation: "new", Code: dnsgo.CodeInvalidInput,
			Message: "AccessKeyId and AccessKeySecret are required"}
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = "https://cas.aliyuncs.com"
	}
	return &AliyunIssuer{api: aliyunrpc.Client{KeyID: config.AccessKeyID, Secret: config.AccessKeySecret,
		Endpoint: endpoint, Version: "2020-04-07", HTTP: config.HTTPClient}}, nil
}

func (a *AliyunIssuer) Kind() string { return "aliyun" }

func (a *AliyunIssuer) call(ctx context.Context, action string, params url.Values, output any) error {
	return a.api.Call(ctx, http.MethodPost, action, params, output)
}

func (a *AliyunIssuer) CheckAccount(ctx context.Context) error {
	return a.call(ctx, "ListInstances", nil, nil)
}

func (a *AliyunIssuer) instanceID(order CloudOrder) (string, error) {
	if order.Provider != a.Kind() || order.ID == "" {
		return "", &dnsgo.Error{Provider: a.Kind(), Operation: "order", Code: dnsgo.CodeInvalidInput,
			Message: "invalid Aliyun certificate order"}
	}
	return order.ID, nil
}

type aliyunDetail struct {
	Status        string     `json:"Status"`
	CertificateID identifier `json:"CertificateId"`
	Validations   []struct {
		Domain string `json:"Domain"`
		Key    string `json:"ValidationKey"`
		Root   string `json:"RootDomain"`
		Type   string `json:"ValidationType"`
		Value  string `json:"ValidationValue"`
	} `json:"DomainValidationList"`
}

func (a *AliyunIssuer) detail(ctx context.Context, id string) (aliyunDetail, error) {
	var result aliyunDetail
	err := a.call(ctx, "GetInstanceDetail", url.Values{"InstanceId": {id}}, &result)
	return result, err
}

func (a *AliyunIssuer) Start(ctx context.Context, request IssueRequest) (CloudOrder, error) {
	domain, err := oneCloudDomain(a.Kind(), request)
	if err != nil {
		return CloudOrder{}, err
	}
	var summary struct {
		InactiveCount int `json:"InactiveCount"`
	}
	if err := a.call(ctx, "GetInstanceSummary", url.Values{"InstanceType": {"TEST"}}, &summary); err != nil {
		return CloudOrder{}, err
	}
	if summary.InactiveCount == 0 {
		return CloudOrder{}, &dnsgo.Error{Provider: a.Kind(), Operation: "start", Code: dnsgo.CodeNotFound,
			Message: "no inactive test certificate instance is available"}
	}
	id := ""
	seen := 0
	for page := 1; page <= 100; page++ {
		var instances struct {
			TotalCount int `json:"TotalCount"`
			List       []struct {
				ID identifier `json:"InstanceId"`
			} `json:"InstanceList"`
		}
		if err := a.call(ctx, "ListInstances", url.Values{"Status": {"inactive"}, "InstanceType": {"TEST"},
			"CurrentPage": {strconv.Itoa(page)}, "ShowSize": {"50"}}, &instances); err != nil {
			return CloudOrder{}, err
		}
		for _, instance := range instances.List {
			if instance.ID != "" {
				id = instance.ID.String()
				break
			}
		}
		seen += len(instances.List)
		if id != "" || instances.TotalCount > 0 && seen >= instances.TotalCount ||
			instances.TotalCount == 0 && len(instances.List) < 50 {
			break
		}
		if len(instances.List) == 0 {
			return CloudOrder{}, &dnsgo.Error{Provider: a.Kind(), Operation: "start", Code: dnsgo.CodeResultUnknown,
				Message: "Aliyun inactive instance pagination is incomplete"}
		}
		if page == 100 {
			return CloudOrder{}, &dnsgo.Error{Provider: a.Kind(), Operation: "start", Code: dnsgo.CodeResultUnknown,
				Message: "Aliyun inactive instance listing exceeded 100 pages"}
		}
	}
	if id == "" {
		return CloudOrder{}, &dnsgo.Error{Provider: a.Kind(), Operation: "start", Code: dnsgo.CodeNotFound,
			Message: "inactive certificate instance list is empty"}
	}
	order := CloudOrder{Provider: a.Kind(), ID: id, Domains: []string{domain}}
	var contacts struct {
		List []struct {
			ID identifier `json:"ContactId"`
		} `json:"ContactList"`
	}
	if err := a.call(ctx, "ListContact", nil, &contacts); err != nil {
		return order, err
	}
	if len(contacts.List) == 0 {
		return order, &dnsgo.Error{Provider: a.Kind(), Operation: "start", Code: dnsgo.CodeNotFound,
			Message: "certificate contact list is empty"}
	}
	algorithm := "RSA_2048"
	keyType := strings.ToUpper(request.KeyAlgorithm)
	if keyType == "ECC" || keyType == "EC" || keyType == "ECDSA" {
		if request.KeySize != 0 && request.KeySize != 256 {
			return order, &dnsgo.Error{Provider: a.Kind(), Operation: "start", Code: dnsgo.CodeUnsupported,
				Message: "Aliyun test certificates support ECC 256 in the reference flow"}
		}
		algorithm = "ECC_256"
	} else if keyType == "" || keyType == "RSA" {
		if request.KeySize == 3072 {
			algorithm = "RSA_3072"
		} else if request.KeySize != 0 && request.KeySize != 2048 {
			return order, &dnsgo.Error{Provider: a.Kind(), Operation: "start", Code: dnsgo.CodeUnsupported,
				Message: "unsupported Aliyun test certificate RSA key size"}
		}
	} else {
		return order, &dnsgo.Error{Provider: a.Kind(), Operation: "start", Code: dnsgo.CodeInvalidInput,
			Message: "unsupported key algorithm"}
	}
	update := url.Values{"InstanceId": {id}, "Domain": {domain}, "KeyAlgorithm": {algorithm},
		"AutoReissue": {"disable"}, "ContactIdList.1": {contacts.List[0].ID.String()}, "ValidateType": {"DNS"}}
	if err := a.call(ctx, "UpdateInstance", update, nil); err != nil {
		return order, err
	}
	if err := a.call(ctx, "ApplyCertificate", url.Values{"InstanceId": {id}}, nil); err != nil {
		return order, err
	}
	for attempt := 0; attempt < 90; attempt++ {
		var task struct {
			Status  string `json:"TaskStatus"`
			Message string `json:"TaskMessage"`
		}
		if err := a.call(ctx, "GetTaskAttribute", url.Values{"TaskId": {id}}, &task); err != nil {
			return order, err
		}
		if task.Status == "failed" {
			return order, &dnsgo.Error{Provider: a.Kind(), Operation: "start", Code: dnsgo.CodeProvider, Message: task.Message}
		}
		if task.Status != "processing" {
			break
		}
		select {
		case <-ctx.Done():
			return order, ctx.Err()
		case <-time.After(time.Second):
		}
		if attempt == 89 {
			return order, &dnsgo.Error{Provider: a.Kind(), Operation: "start", Code: dnsgo.CodeResultUnknown,
				Message: "certificate task is still processing"}
		}
	}
	challenges, err := a.Challenges(ctx, order)
	if err != nil {
		return order, err
	}
	order.Challenges = challenges
	return order, nil
}

func (a *AliyunIssuer) Challenges(ctx context.Context, order CloudOrder) ([]DNSChallenge, error) {
	id, err := a.instanceID(order)
	if err != nil {
		return nil, err
	}
	detail, err := a.detail(ctx, id)
	if err != nil {
		return nil, err
	}
	challenges := make([]DNSChallenge, 0, len(detail.Validations))
	for _, validation := range detail.Validations {
		name := strings.TrimSuffix(validation.Key, ".") + "." + strings.TrimSuffix(validation.Root, ".")
		challenges = append(challenges, DNSChallenge{Name: name, Type: validation.Type, Value: validation.Value})
	}
	if len(challenges) == 0 {
		return nil, &dnsgo.Error{Provider: a.Kind(), Operation: "challenges", Code: dnsgo.CodeResultUnknown,
			Message: "DNS authorization details are not ready"}
	}
	return challenges, nil
}

func (a *AliyunIssuer) SubmitValidation(context.Context, CloudOrder) error { return nil }

func (a *AliyunIssuer) Status(ctx context.Context, order CloudOrder) (CloudStatus, error) {
	id, err := a.instanceID(order)
	if err != nil {
		return CloudPending, err
	}
	detail, err := a.detail(ctx, id)
	if err != nil {
		return CloudPending, err
	}
	switch detail.Status {
	case "normal":
		return CloudIssued, nil
	case "closed":
		return CloudRejected, &dnsgo.Error{Provider: a.Kind(), Operation: "status", Code: dnsgo.CodeProvider,
			Message: "certificate audit failed"}
	default:
		return CloudPending, nil
	}
}

func (a *AliyunIssuer) Download(ctx context.Context, order CloudOrder) (IssueResult, error) {
	id, err := a.instanceID(order)
	if err != nil {
		return IssueResult{}, err
	}
	detail, err := a.detail(ctx, id)
	if err != nil {
		return IssueResult{}, err
	}
	if detail.CertificateID == "" {
		return IssueResult{}, &dnsgo.Error{Provider: a.Kind(), Operation: "download", Code: dnsgo.CodeNotFound,
			Message: "certificate ID is missing"}
	}
	var result struct {
		Cert string `json:"Cert"`
		Key  string `json:"Key"`
	}
	if err := a.call(ctx, "GetUserCertificateDetail", url.Values{"CertId": {detail.CertificateID.String()}}, &result); err != nil {
		return IssueResult{}, err
	}
	return certificateResult(a.Kind(), order.Domains, []byte(result.Cert), []byte(result.Key))
}

func (a *AliyunIssuer) Revoke(ctx context.Context, order CloudOrder) ([]DNSChallenge, error) {
	id, err := a.instanceID(order)
	if err != nil {
		return nil, err
	}
	err = a.call(ctx, "RevokeCertificate", url.Values{"InstanceId": {id}}, nil)
	return nil, err
}

func (a *AliyunIssuer) Cancel(ctx context.Context, order CloudOrder) error {
	id, err := a.instanceID(order)
	if err != nil {
		return err
	}
	detail, err := a.detail(ctx, id)
	if err != nil {
		return err
	}
	if detail.Status == "pending" {
		return a.call(ctx, "CancelPendingCertificate", url.Values{"InstanceId": {id}}, nil)
	}
	return nil
}

var _ CloudIssuer = (*AliyunIssuer)(nil)
