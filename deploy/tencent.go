package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/internal/tc3"
)

type Tencent struct {
	keyID   string
	secret  string
	product string
	values  map[string]string
	client  *http.Client
}

type TencentDeployDetail struct {
	CertID     string   `json:"CertId"`
	OldCertID  string   `json:"OldCertId"`
	InstanceID string   `json:"InstanceId"`
	Domains    []string `json:"Domains"`
	Status     int      `json:"Status"`
}

type TencentDeployRecord struct {
	TotalCount        int
	SuccessTotalCount int
	FailedTotalCount  int
	RunningTotalCount int
	PendingTotalCount int
	Details           []TencentDeployDetail
}

func init() {
	register("tencent", func(config Config) (Target, error) {
		keyID, secret := strings.TrimSpace(config.Values["SecretId"]), strings.TrimSpace(config.Values["SecretKey"])
		if keyID == "" || secret == "" {
			return nil, errors.New("Tencent Cloud SecretId and SecretKey are required")
		}
		product := strings.TrimSpace(config.Values["product"])
		if product == "" {
			product = "cdn"
		}
		switch product {
		case "cdn", "teo", "waf", "cos", "clb", "tke", "scf", "ddos", "live", "vod", "tse", "tcb", "lighthouse", "upload", "update", "update_new":
		default:
			return nil, errors.New("unknown Tencent Cloud deployment product")
		}
		return &Tencent{keyID: keyID, secret: secret, product: product, values: config.Values, client: client(config)}, nil
	})
}

func (t *Tencent) Kind() string { return "tencent" }

func (t *Tencent) api(endpoint, service, version, region string) *tc3.Client {
	return &tc3.Client{KeyID: t.keyID, Secret: t.secret, Endpoint: endpoint, Service: service, Version: version, Region: region, HTTP: t.client}
}

func (t *Tencent) ssl(region string) *tc3.Client {
	return t.api("ssl.tencentcloudapi.com", "ssl", "2019-12-05", region)
}

func (t *Tencent) Check(ctx context.Context) error {
	return t.ssl("").Call(ctx, "DescribeCertificates", map[string]any{}, nil)
}

func (t *Tencent) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	if t.product == "update" {
		return t.updateCertificate(ctx, material)
	}
	if t.product == "update_new" {
		return t.updateCertificateNew(ctx, material)
	}
	id, uploaded, err := t.uploadCertificate(ctx, material, false)
	result := Result{Target: t.Kind(), Location: id, Written: uploaded}
	if err != nil {
		return result, err
	}
	if t.product == "upload" {
		return result, nil
	}
	switch t.product {
	case "clb":
		err = t.deployCLB(ctx, id, &result)
	case "scf":
		err = t.deploySCF(ctx, id, &result)
	case "teo":
		err = t.deployTEO(ctx, id, &result)
	default:
		err = t.deployCommon(ctx, id, &result)
	}
	return result, err
}

func (t *Tencent) uploadCertificate(ctx context.Context, material Material, repeatable bool) (string, bool, error) {
	leaf, _ := certificate(material)
	name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
	payload := map[string]any{"CertificatePublicKey": string(material.FullChainPEM), "CertificatePrivateKey": string(material.PrivateKeyPEM),
		"CertificateType": "SVR", "Alias": name, "Repeatable": repeatable}
	if repeatable {
		payload["AllowDownload"] = true
	}
	var response struct {
		CertificateID string `json:"CertificateId"`
	}
	if err := t.ssl("").Call(ctx, "UploadCertificate", payload, &response); err != nil {
		return "", false, err
	}
	if response.CertificateID == "" {
		return "", true, errors.New("Tencent Cloud uploaded certificate but returned no ID")
	}
	if err := waitContext(ctx, 300*time.Millisecond); err != nil {
		return response.CertificateID, true, err
	}
	if err := t.ssl("").Call(ctx, "ModifyCertificatesExpiringNotificationSwitch", map[string]any{
		"CertificateIds": []string{response.CertificateID}, "SwitchStatus": 1,
	}, nil); err != nil {
		return response.CertificateID, true, err
	}
	return response.CertificateID, true, nil
}

func (t *Tencent) deployCommon(ctx context.Context, id string, result *Result) error {
	product := t.product
	region := ""
	var instanceIDs []string
	domains := splitList(t.values["domain"])
	switch product {
	case "cos":
		region = t.values["regionid"]
		if region == "" || t.values["cos_bucket"] == "" || len(domains) != 1 {
			return errors.New("Tencent COS region, bucket and one domain are required")
		}
		instanceIDs = []string{region + "|" + t.values["cos_bucket"] + "|" + domains[0]}
	case "tke":
		region = t.values["regionid"]
		if region == "" || t.values["tke_cluster_id"] == "" || t.values["tke_namespace"] == "" || t.values["tke_secret"] == "" {
			return errors.New("Tencent TKE region, cluster, namespace and Secret are required")
		}
		instanceIDs = []string{t.values["tke_cluster_id"] + "|" + t.values["tke_namespace"] + "|" + t.values["tke_secret"]}
	case "lighthouse":
		region = t.values["regionid"]
		if region == "" || t.values["lighthouse_id"] == "" || len(domains) != 1 {
			return errors.New("Tencent Lighthouse region, instance and one domain are required")
		}
		instanceIDs = []string{region + "|" + t.values["lighthouse_id"] + "|" + domains[0]}
	case "ddos":
		if t.values["lighthouse_id"] == "" || len(domains) != 1 {
			return errors.New("Tencent DDoS instance and one domain are required")
		}
		instanceIDs = []string{t.values["lighthouse_id"] + "|" + domains[0] + "|443"}
	default:
		if len(domains) == 0 {
			return errors.New("Tencent deployment domains are required")
		}
		instanceIDs = domains
		if product == "waf" {
			region = t.values["region"]
		}
		if product == "tse" {
			region = t.values["regionid"]
			if region == "" {
				return errors.New("Tencent TSE region is required")
			}
		}
		if product == "cdn" {
			for i := range instanceIDs {
				instanceIDs[i] += "|on"
			}
		}
	}
	payload := map[string]any{"CertificateId": id, "InstanceIdList": instanceIDs, "ResourceType": product}
	if product == "live" {
		payload["Status"] = 1
	}
	var response struct {
		DeployRecordID json.RawMessage `json:"DeployRecordId"`
	}
	result.Written = true
	err := t.ssl(region).Call(ctx, "DeployCertificateInstance", payload, &response)
	if err != nil {
		return err
	}
	recordID := scalarID(response.DeployRecordID)
	if recordID == "" {
		return &dnsgo.Error{Provider: t.Kind(), Operation: "deploy_common", Code: dnsgo.CodeResultUnknown,
			Message: "Tencent deployment task was accepted without a record ID"}
	}
	result.Pending = true
	result.Metadata = map[string]string{"deploy_record_id": recordID,
		"expected_instances": strconv.Itoa(len(instanceIDs)), "product": product}
	return nil
}

// InspectDeploymentRecord reads every detail page for a Tencent Cloud SSL
// deployment task. The task ID comes from Deploy Result.Metadata.
func (t *Tencent) InspectDeploymentRecord(ctx context.Context, recordID string) (TencentDeployRecord, error) {
	if strings.TrimSpace(recordID) == "" {
		return TencentDeployRecord{}, errors.New("Tencent deployment record ID is required")
	}
	result := TencentDeployRecord{}
	for offset := 0; offset < 20000; offset += 200 {
		var page struct {
			TotalCount        int                   `json:"TotalCount"`
			SuccessTotalCount int                   `json:"SuccessTotalCount"`
			FailedTotalCount  int                   `json:"FailedTotalCount"`
			RunningTotalCount int                   `json:"RunningTotalCount"`
			PendingTotalCount int                   `json:"PendingTotalCount"`
			Details           []TencentDeployDetail `json:"DeployRecordDetailList"`
		}
		if err := t.ssl("").Call(ctx, "DescribeHostDeployRecordDetail", map[string]any{
			"DeployRecordId": recordID, "Offset": offset, "Limit": 200,
		}, &page); err != nil {
			return TencentDeployRecord{}, err
		}
		result.TotalCount, result.SuccessTotalCount, result.FailedTotalCount =
			page.TotalCount, page.SuccessTotalCount, page.FailedTotalCount
		result.RunningTotalCount, result.PendingTotalCount = page.RunningTotalCount, page.PendingTotalCount
		result.Details = append(result.Details, page.Details...)
		if page.TotalCount == 0 || offset+len(page.Details) >= page.TotalCount {
			return result, nil
		}
		if len(page.Details) == 0 {
			return TencentDeployRecord{}, &dnsgo.Error{Provider: t.Kind(), Operation: "inspect_deployment",
				Code: dnsgo.CodeResultUnknown, Message: "Tencent deployment detail pagination is incomplete"}
		}
	}
	return TencentDeployRecord{}, &dnsgo.Error{Provider: t.Kind(), Operation: "inspect_deployment",
		Code: dnsgo.CodeResultUnknown, Message: "Tencent deployment details exceeded 100 pages"}
}

func (t *Tencent) Poll(ctx context.Context, result Result) (Result, error) {
	if !result.Pending || result.Metadata == nil || result.Metadata["deploy_record_id"] == "" {
		return result, errors.New("Tencent deployment result has no pending task ID")
	}
	mode := result.Metadata["mode"]
	if result.Metadata["product"] != t.product || result.Location == "" && mode != "update_new" {
		return result, &dnsgo.Error{Provider: t.Kind(), Operation: "poll_deployment", Code: dnsgo.CodeConflict,
			Message: "Tencent deployment configuration changed while a task is pending"}
	}
	if mode == "update_new" && result.Location == "" {
		id, err := t.findNewCertificateID(ctx, result.Metadata["cert_cn"], result.Metadata["cert_sha256"])
		if err != nil {
			return result, err
		}
		result.Location = id
	}
	if mode == "update_new" && result.Metadata["cleanup_pending"] == "true" {
		if err := t.deleteOldCertificateID(ctx, result.Metadata["old_cert_id"], result.Location); err != nil {
			return result, &dnsgo.Error{Provider: t.Kind(), Operation: "cleanup_old_certificate", Code: dnsgo.CodeConflict,
				Message: "replacement deployed but old certificate cleanup needs inspection", Cause: err}
		}
		result.Pending = false
		delete(result.Metadata, "cleanup_pending")
		return result, nil
	}
	if mode == "update" || mode == "update_new" {
		return t.pollUpdate(ctx, result)
	}
	record, err := t.InspectDeploymentRecord(ctx, result.Metadata["deploy_record_id"])
	if err != nil {
		return result, err
	}
	if record.TotalCount == 0 || record.RunningTotalCount > 0 || record.PendingTotalCount > 0 {
		return result, nil
	}
	if record.FailedTotalCount > 0 {
		return result, &dnsgo.Error{Provider: t.Kind(), Operation: "poll_deployment", Code: dnsgo.CodeConflict,
			Message: "Tencent deployment task reported failed resources"}
	}
	expected, _ := strconv.Atoi(result.Metadata["expected_instances"])
	if expected > 0 && record.TotalCount < expected || record.SuccessTotalCount != record.TotalCount ||
		len(record.Details) != record.TotalCount {
		return result, &dnsgo.Error{Provider: t.Kind(), Operation: "poll_deployment", Code: dnsgo.CodeResultUnknown,
			Message: "Tencent deployment task has incomplete results"}
	}
	for _, detail := range record.Details {
		if detail.CertID != result.Location || detail.Status != 1 {
			return result, &dnsgo.Error{Provider: t.Kind(), Operation: "poll_deployment", Code: dnsgo.CodeConflict,
				Message: "Tencent deployment detail does not match this certificate"}
		}
	}
	result.Pending = false
	return result, nil
}

func (t *Tencent) deployCLB(ctx context.Context, id string, result *Result) error {
	region, balancer := t.values["regionid"], t.values["clb_id"]
	if region == "" || balancer == "" {
		return errors.New("Tencent CLB region and load balancer ID are required")
	}
	client := t.api("clb.tencentcloudapi.com", "clb", "2018-03-17", region)
	payload := map[string]any{"LoadBalancerId": balancer, "Protocol": "HTTPS"}
	if listener := t.values["clb_listener_id"]; listener != "" {
		payload["ListenerIds"] = []string{listener}
	}
	var response struct {
		TotalCount int `json:"TotalCount"`
		Listeners  []struct {
			ListenerID  string `json:"ListenerId"`
			SniSwitch   int    `json:"SniSwitch"`
			Certificate struct {
				CertID string `json:"CertId"`
			} `json:"Certificate"`
			Rules []struct {
				Domain      string `json:"Domain"`
				Certificate struct {
					CertID string `json:"CertId"`
				} `json:"Certificate"`
			} `json:"Rules"`
		} `json:"Listeners"`
	}
	if err := client.Call(ctx, "DescribeListeners", payload, &response); err != nil {
		return err
	}
	if response.TotalCount == 0 {
		return errors.New("Tencent CLB has no HTTPS listeners")
	}
	if response.TotalCount > len(response.Listeners) {
		return errors.New("Tencent CLB listener response is incomplete")
	}
	wantSNI := t.values["clb_domain"] != ""
	matched := 0
	for _, listener := range response.Listeners {
		if (listener.SniSwitch == 1) != wantSNI {
			continue
		}
		if wantSNI {
			for _, rule := range listener.Rules {
				if rule.Domain != t.values["clb_domain"] {
					continue
				}
				matched++
				if rule.Certificate.CertID == id {
					continue
				}
				if err := client.Call(ctx, "ModifyDomainAttributes", map[string]any{"LoadBalancerId": balancer, "ListenerId": listener.ListenerID,
					"Domain": rule.Domain, "Certificate": map[string]string{"SSLMode": "UNIDIRECTIONAL", "CertId": id}}, nil); err != nil {
					return err
				}
				result.Written = true
			}
		} else {
			matched++
			if listener.Certificate.CertID == id {
				continue
			}
			if err := client.Call(ctx, "ModifyListener", map[string]any{"LoadBalancerId": balancer, "ListenerId": listener.ListenerID,
				"Certificate": map[string]string{"SSLMode": "UNIDIRECTIONAL", "CertId": id}}, nil); err != nil {
				return err
			}
			result.Written = true
		}
	}
	if matched == 0 {
		return errors.New("Tencent CLB matching listener was not found")
	}
	return nil
}

func (t *Tencent) deploySCF(ctx context.Context, id string, result *Result) error {
	region, domain := t.values["regionid"], t.values["domain"]
	if region == "" || domain == "" {
		return errors.New("Tencent SCF region and domain are required")
	}
	client := t.api("scf.tencentcloudapi.com", "scf", "2018-04-16", region)
	var current struct {
		Protocol   string         `json:"Protocol"`
		CertConfig map[string]any `json:"CertConfig"`
	}
	if err := client.Call(ctx, "GetCustomDomain", map[string]string{"Domain": domain}, &current); err != nil {
		return err
	}
	if current.CertConfig == nil {
		current.CertConfig = map[string]any{}
	}
	if current.CertConfig["CertificateId"] == id {
		return nil
	}
	current.CertConfig["CertificateId"] = id
	if current.Protocol == "HTTP" {
		current.Protocol = "HTTP&HTTPS"
	}
	if err := client.Call(ctx, "UpdateCustomDomain", map[string]any{"Domain": domain, "Protocol": current.Protocol, "CertConfig": current.CertConfig}, nil); err != nil {
		return err
	}
	result.Written = true
	return nil
}

func (t *Tencent) deployTEO(ctx context.Context, id string, result *Result) error {
	siteID, hosts := t.values["site_id"], splitList(t.values["domain"])
	if siteID == "" || len(hosts) == 0 {
		return errors.New("Tencent TEO site ID and hosts are required")
	}
	endpoint := "teo.tencentcloudapi.com"
	if t.values["site_type"] == "intl" {
		endpoint = "teo.intl.tencentcloudapi.com"
	}
	client := t.api(endpoint, "teo", "2022-09-01", "")
	if err := client.Call(ctx, "ModifyHostsCertificate", map[string]any{"ZoneId": siteID, "Hosts": hosts, "Mode": "sslcert",
		"ServerCertInfo": []map[string]string{{"CertId": id}}}, nil); err != nil {
		return err
	}
	result.Written = true
	return nil
}

var _ Target = (*Tencent)(nil)
