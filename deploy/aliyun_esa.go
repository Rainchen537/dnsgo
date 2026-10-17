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
)

func (t *Aliyun) esaEndpoint() string {
	if t.region == "ap-southeast-1" {
		return "esa.ap-southeast-1.aliyuncs.com"
	}
	return "esa.cn-hangzhou.aliyuncs.com"
}

func (t *Aliyun) esaSiteID(ctx context.Context) (string, error) {
	name := strings.TrimSpace(t.values["esa_sitename"])
	if name == "" {
		return "", errors.New("Aliyun ESA site name is required")
	}
	var response struct {
		Sites []struct {
			SiteID   json.RawMessage `json:"SiteId"`
			SiteName string          `json:"SiteName"`
		} `json:"Sites"`
	}
	err := t.rpc(ctx, t.esaEndpoint(), "2024-09-10", http.MethodGet, "ListSites", map[string]any{
		"SiteName": name, "SiteSearchType": "exact",
	}, &response)
	if err != nil {
		return "", err
	}
	for _, site := range response.Sites {
		if site.SiteName == "" || strings.EqualFold(site.SiteName, name) {
			if id := scalarID(site.SiteID); id != "" {
				return id, nil
			}
		}
	}
	return "", errors.New("Aliyun ESA site was not found")
}

func (t *Aliyun) deployESASaaS(ctx context.Context, casID string, result *Result) error {
	siteID, err := t.esaSiteID(ctx)
	if err != nil {
		return err
	}
	hostnames := splitList(t.values["esa_saas_sitename"])
	if len(hostnames) == 0 {
		return errors.New("Aliyun ESA SaaS hostnames are required")
	}
	seen := map[string]bool{}
	failures := 0
	for _, hostname := range hostnames {
		hostname = strings.ToLower(hostname)
		if seen[hostname] {
			continue
		}
		seen[hostname] = true
		var response struct {
			Hostnames []struct {
				Hostname   string          `json:"Hostname"`
				SiteID     json.RawMessage `json:"SiteId"`
				HostnameID json.RawMessage `json:"HostnameId"`
			} `json:"Hostnames"`
		}
		err := t.rpc(ctx, t.esaEndpoint(), "2024-09-10", http.MethodGet, "ListCustomHostnames", map[string]any{
			"Hostname": hostname, "SiteId": siteID, "NameMatchType": "exact",
		}, &response)
		if err != nil {
			failures++
			continue
		}
		var hostnameID string
		matches := 0
		for _, item := range response.Hostnames {
			if strings.EqualFold(item.Hostname, hostname) && scalarID(item.SiteID) == siteID {
				matches++
				hostnameID = scalarID(item.HostnameID)
			}
		}
		if matches != 1 || hostnameID == "" {
			failures++
			continue
		}
		err = t.rpc(ctx, t.esaEndpoint(), "2024-09-10", http.MethodPost, "UpdateCustomHostname", map[string]any{
			"HostnameId": hostnameID, "SslFlag": "on", "CertType": "cas", "CasId": casID, "CasRegion": t.region,
		}, nil)
		if err != nil {
			result.Written = true
			return err
		}
		result.Written = true
	}
	if failures > 0 {
		return fmt.Errorf("Aliyun ESA SaaS deployment failed for %d hostnames", failures)
	}
	return nil
}

func (t *Aliyun) deployESA(ctx context.Context, casID, name string, result *Result) error {
	siteID, err := t.esaSiteID(ctx)
	if err != nil {
		return err
	}
	var list struct {
		Certificates []struct {
			ID         json.RawMessage `json:"Id"`
			Type       string          `json:"Type"`
			SAN        string          `json:"SAN"`
			CreateTime string          `json:"CreateTime"`
			CasID      json.RawMessage `json:"CasId"`
			Name       string          `json:"Name"`
		} `json:"Result"`
	}
	if err := t.rpc(ctx, t.esaEndpoint(), "2024-09-10", http.MethodGet, "ListCertificates", map[string]any{"SiteId": siteID}, &list); err != nil {
		return err
	}
	domains := map[string]bool{}
	for _, domain := range splitList(t.values["domainList"]) {
		domains[strings.ToLower(domain)] = true
	}
	var existingID, existingCasID, oldestID string
	oldestTime := time.Time{}
	for _, item := range list.Certificates {
		if item.Type == "free" {
			continue
		}
		matched := len(splitList(item.SAN)) > 0
		for _, domain := range splitList(item.SAN) {
			if !domains[strings.ToLower(domain)] {
				matched = false
				break
			}
		}
		if matched {
			existingID, existingCasID = scalarID(item.ID), scalarID(item.CasID)
			break
		}
		stamp := parseAliyunTime(item.CreateTime)
		if oldestID == "" || stamp.Before(oldestTime) {
			oldestID, oldestTime = scalarID(item.ID), stamp
		}
	}
	if existingID != "" && existingCasID == casID {
		return nil
	}
	if existingID == "" {
		var quotas struct {
			Quotas []struct {
				Usage      json.RawMessage `json:"Usage"`
				QuotaValue json.RawMessage `json:"QuotaValue"`
			} `json:"Quotas"`
		}
		if err := t.rpc(ctx, t.esaEndpoint(), "2024-09-10", http.MethodGet, "ListInstanceQuotasWithUsage", map[string]any{
			"SiteId": siteID, "QuotaNames": "customHttpCert",
		}, &quotas); err != nil {
			return err
		}
		if len(quotas.Quotas) > 0 {
			usage, _ := strconv.Atoi(scalarID(quotas.Quotas[0].Usage))
			limit, _ := strconv.Atoi(scalarID(quotas.Quotas[0].QuotaValue))
			if limit > 0 && usage >= limit {
				if oldestID == "" || t.values["replace_oldest_on_quota"] != "true" {
					return errors.New("Aliyun ESA certificate quota is full")
				}
				result.Written = true
				if err := t.rpc(ctx, t.esaEndpoint(), "2024-09-10", http.MethodGet, "DeleteCertificate", map[string]any{
					"SiteId": siteID, "Id": oldestID,
				}, nil); err != nil {
					return err
				}
			}
		}
	}
	fields := map[string]any{"SiteId": siteID, "Type": "cas", "CasId": casID, "Name": name, "Region": t.region}
	if existingID != "" {
		fields["Id"] = existingID
	}
	result.Written = true
	if err := t.rpc(ctx, t.esaEndpoint(), "2024-09-10", http.MethodPost, "SetCertificate", fields, nil); err != nil {
		return err
	}
	return nil
}

func parseAliyunTime(value string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05Z"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Time{}
}
