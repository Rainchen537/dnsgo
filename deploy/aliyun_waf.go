package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (t *Aliyun) wafEndpoint() string { return "wafopenapi." + t.region + ".aliyuncs.com" }

func (t *Aliyun) wafInstanceID(ctx context.Context) (string, error) {
	var response struct {
		InstanceID string `json:"InstanceId"`
	}
	if err := t.rpc(ctx, t.wafEndpoint(), "2021-10-01", http.MethodGet, "DescribeInstance", map[string]any{"RegionId": t.region}, &response); err != nil {
		return "", err
	}
	if response.InstanceID == "" {
		return "", errors.New("Aliyun WAF instance was not found")
	}
	return response.InstanceID, nil
}

func (t *Aliyun) wafCertID(id string) string {
	if t.region == "ap-southeast-1" {
		return id + "-ap-southeast-1"
	}
	return id + "-cn-hangzhou"
}

func (t *Aliyun) deployWAF(ctx context.Context, id string, result *Result) error {
	domains := splitList(t.values["domain"])
	if len(domains) == 0 {
		return errors.New("Aliyun WAF domains are required")
	}
	instanceID, err := t.wafInstanceID(ctx)
	if err != nil {
		return err
	}
	wafCertID := t.wafCertID(id)
	for _, domain := range domains {
		var details struct {
			Listen   map[string]any `json:"Listen"`
			Redirect map[string]any `json:"Redirect"`
		}
		err := t.rpc(ctx, t.wafEndpoint(), "2021-10-01", http.MethodGet, "DescribeDomainDetail", map[string]any{
			"InstanceId": instanceID, "Domain": domain, "RegionId": t.region,
		}, &details)
		if err != nil {
			return err
		}
		if details.Listen == nil {
			return errors.New("Aliyun WAF domain listener was not found")
		}
		if details.Listen["CertId"] == wafCertID {
			continue
		}
		details.Listen["CertId"] = wafCertID
		if ports, ok := details.Listen["HttpsPorts"].([]any); !ok || len(ports) == 0 {
			details.Listen["HttpsPorts"] = []int{443}
			details.Listen["TLSVersion"] = "tlsv1.1"
			details.Listen["EnableTLSv3"] = true
			details.Listen["CipherSuite"] = 1
		}
		if details.Redirect == nil {
			details.Redirect = map[string]any{}
		}
		if ports, ok := details.Redirect["BackendPorts"].([]any); ok && len(ports) == 1 {
			if first, ok := ports[0].(map[string]any); ok && first["Protocol"] == "http" {
				ports = append(ports, map[string]any{"ListenPort": 443, "Protocol": "https", "BackendPort": first["BackendPort"]})
				details.Redirect["BackendPorts"] = ports
				details.Redirect["FocusHttpBackend"] = true
			}
		}
		if backends, ok := details.Redirect["AllBackends"]; ok {
			details.Redirect["Backends"] = backends
		}
		listenJSON, err := json.Marshal(details.Listen)
		if err != nil {
			return errors.New("encode Aliyun WAF listener failed")
		}
		redirectJSON, err := json.Marshal(details.Redirect)
		if err != nil {
			return errors.New("encode Aliyun WAF redirect failed")
		}
		if err := t.rpc(ctx, t.wafEndpoint(), "2021-10-01", http.MethodPost, "ModifyDomain", map[string]any{
			"InstanceId": instanceID, "Domain": domain, "Listen": string(listenJSON), "Redirect": string(redirectJSON), "RegionId": t.region,
		}, nil); err != nil {
			return err
		}
		result.Written = true
	}
	return nil
}

func (t *Aliyun) deployWAFResource(ctx context.Context, id string, result *Result) error {
	resources := splitList(t.values["waf_resource_id"])
	if len(resources) == 0 {
		return errors.New("Aliyun WAF resource IDs are required")
	}
	instanceID, err := t.wafInstanceID(ctx)
	if err != nil {
		return err
	}
	wafCertID := t.wafCertID(id)
	for _, resourceID := range resources {
		parts := strings.Split(resourceID, "-")
		if len(parts) < 3 {
			return errors.New("invalid Aliyun WAF resource ID")
		}
		resourceInstanceID := parts[len(parts)-3]
		var listing struct {
			CloudResourceList []json.RawMessage `json:"CloudResourceList"`
		}
		err := t.rpc(ctx, t.wafEndpoint(), "2021-10-01", http.MethodGet, "DescribeCloudResourceList", map[string]any{
			"InstanceId": instanceID, "CloudResourceId": resourceID, "RegionId": t.region,
		}, &listing)
		if err != nil {
			return err
		}
		if len(listing.CloudResourceList) == 0 {
			return errors.New("Aliyun WAF protected resource was not found")
		}
		action := "ModifyCloudResourceDefaultCert"
		if t.values["deploy_type"] == "1" {
			action = "CreateCloudResourceExtensionCert"
		}
		err = t.rpc(ctx, t.wafEndpoint(), "2021-10-01", http.MethodPost, action, map[string]any{
			"InstanceId": instanceID, "CloudResourceId": resourceID, "CertId": wafCertID, "RegionId": t.region,
		}, nil)
		if err != nil {
			return err
		}
		result.Written = true
		if action == "CreateCloudResourceExtensionCert" && t.values["cleanup_expired"] == "true" {
			if err := t.cleanWAFExpired(ctx, instanceID, resourceInstanceID, resourceID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *Aliyun) cleanWAFExpired(ctx context.Context, instanceID, resourceInstanceID, resourceID string) error {
	var listing struct {
		Certs []struct {
			CertIdentifier string `json:"CertIdentifier"`
			AfterDate      string `json:"AfterDate"`
		} `json:"Certs"`
	}
	if err := t.rpc(ctx, t.wafEndpoint(), "2021-10-01", http.MethodGet, "DescribeResourceInstanceCerts", map[string]any{
		"InstanceId": instanceID, "ResourceInstanceId": resourceInstanceID, "RegionId": t.region,
	}, &listing); err != nil {
		return err
	}
	for _, cert := range listing.Certs {
		if cert.CertIdentifier == "" || cert.AfterDate == "" {
			continue
		}
		stamp := parseAliyunTime(cert.AfterDate)
		if stamp.IsZero() || !stamp.Before(time.Now()) {
			continue
		}
		if err := t.rpc(ctx, t.wafEndpoint(), "2021-10-01", http.MethodPost, "DeleteCloudResourceExtensionCert", map[string]any{
			"InstanceId": instanceID, "CloudResourceId": resourceID, "CertId": cert.CertIdentifier, "RegionId": t.region,
		}, nil); err != nil {
			return fmt.Errorf("Aliyun WAF expired extension certificate deletion failed: %w", err)
		}
	}
	return nil
}

func (t *Aliyun) deployWAF2(ctx context.Context, id string, result *Result) error {
	domains := splitList(t.values["domain"])
	if len(domains) == 0 {
		return errors.New("Aliyun WAF domains are required")
	}
	var response struct {
		InstanceInfo struct {
			InstanceID string `json:"InstanceId"`
		} `json:"InstanceInfo"`
	}
	if err := t.rpc(ctx, t.wafEndpoint(), "2019-09-10", http.MethodGet, "DescribeInstanceInfo", map[string]any{"RegionId": t.region}, &response); err != nil {
		return err
	}
	if response.InstanceInfo.InstanceID == "" {
		return errors.New("Aliyun WAF instance was not found")
	}
	for _, domain := range domains {
		if err := t.rpc(ctx, t.wafEndpoint(), "2019-09-10", http.MethodPost, "CreateCertificateByCertificateId", map[string]any{
			"InstanceId": response.InstanceInfo.InstanceID, "Domain": domain, "CertificateId": id,
		}, nil); err != nil {
			return err
		}
		result.Written = true
	}
	return nil
}
