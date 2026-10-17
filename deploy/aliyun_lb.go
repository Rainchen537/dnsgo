package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

func (t *Aliyun) deployCLB(ctx context.Context, casID, certName string, result *Result) error {
	region, balancer, port := t.values["regionid"], t.values["clb_id"], t.values["clb_port"]
	if region == "" || balancer == "" || port == "" {
		return errors.New("Aliyun CLB region, load balancer and HTTPS port are required")
	}
	endpoint := "slb." + region + ".aliyuncs.com"
	var certificates struct {
		ServerCertificates struct {
			List []struct {
				IsAliCloudCertificate int             `json:"IsAliCloudCertificate"`
				AliCloudCertificateID json.RawMessage `json:"AliCloudCertificateId"`
				ServerCertificateID   json.RawMessage `json:"ServerCertificateId"`
			} `json:"ServerCertificate"`
		} `json:"ServerCertificates"`
	}
	if err := t.rpc(ctx, endpoint, "2014-05-15", http.MethodPost, "DescribeServerCertificates", map[string]any{"RegionId": region}, &certificates); err != nil {
		return err
	}
	serverID := ""
	for _, item := range certificates.ServerCertificates.List {
		if item.IsAliCloudCertificate == 1 && scalarID(item.AliCloudCertificateID) == casID {
			serverID = scalarID(item.ServerCertificateID)
			break
		}
	}
	if serverID == "" {
		var uploaded struct {
			ServerCertificateID json.RawMessage `json:"ServerCertificateId"`
		}
		if err := t.rpc(ctx, endpoint, "2014-05-15", http.MethodPost, "UploadServerCertificate", map[string]any{
			"RegionId": region, "AliCloudCertificateId": casID, "AliCloudCertificateName": certName, "AliCloudCertificateRegionId": "cn-hangzhou",
		}, &uploaded); err != nil {
			return err
		}
		serverID = scalarID(uploaded.ServerCertificateID)
		result.Written = true
		if serverID == "" {
			return errors.New("Aliyun CLB uploaded server certificate but returned no ID")
		}
	}
	if t.values["deploy_type"] == "1" {
		domains := map[string]bool{}
		for _, domain := range splitList(t.values["clb_domain"]) {
			domains[domain] = true
		}
		if len(domains) == 0 {
			return errors.New("Aliyun CLB extension domains are required")
		}
		var response struct {
			DomainExtensions struct {
				List []struct {
					Domain              string          `json:"Domain"`
					DomainExtensionID   json.RawMessage `json:"DomainExtensionId"`
					ServerCertificateID json.RawMessage `json:"ServerCertificateId"`
				} `json:"DomainExtension"`
			} `json:"DomainExtensions"`
		}
		if err := t.rpc(ctx, endpoint, "2014-05-15", http.MethodPost, "DescribeDomainExtensions", map[string]any{
			"RegionId": region, "LoadBalancerId": balancer, "ListenerPort": port,
		}, &response); err != nil {
			return err
		}
		extensions := map[string]struct{ id, certificateID string }{}
		for _, item := range response.DomainExtensions.List {
			if !domains[item.Domain] {
				continue
			}
			extensions[item.Domain] = struct{ id, certificateID string }{
				id: scalarID(item.DomainExtensionID), certificateID: scalarID(item.ServerCertificateID)}
		}
		if len(extensions) != len(domains) {
			return errors.New("one or more Aliyun CLB extension domains were not found")
		}
		for _, item := range extensions {
			if item.id == "" {
				return errors.New("Aliyun CLB extension domain ID is missing")
			}
		}
		handled := map[string]bool{}
		for _, domain := range splitList(t.values["clb_domain"]) {
			if handled[domain] {
				continue
			}
			handled[domain] = true
			item := extensions[domain]
			if item.certificateID == serverID {
				continue
			}
			if err := t.rpc(ctx, endpoint, "2014-05-15", http.MethodPost, "SetDomainExtensionAttribute", map[string]any{
				"RegionId": region, "DomainExtensionId": item.id, "ServerCertificateId": serverID,
			}, nil); err != nil {
				return err
			}
			result.Written = true
		}
		return nil
	}
	var listener struct {
		ServerCertificateID json.RawMessage `json:"ServerCertificateId"`
	}
	fields := map[string]any{"RegionId": region, "LoadBalancerId": balancer, "ListenerPort": port}
	if err := t.rpc(ctx, endpoint, "2014-05-15", http.MethodPost, "DescribeLoadBalancerHTTPSListenerAttribute", fields, &listener); err != nil {
		return err
	}
	if scalarID(listener.ServerCertificateID) == serverID {
		return nil
	}
	fields["ServerCertificateId"] = serverID
	if err := t.rpc(ctx, endpoint, "2014-05-15", http.MethodPost, "SetLoadBalancerHTTPSListenerAttribute", fields, nil); err != nil {
		return err
	}
	result.Written = true
	return nil
}

func (t *Aliyun) deployALBorNLB(ctx context.Context, casID string, result *Result) error {
	region := t.values["regionid"]
	listenerID := t.values[t.product+"_listener_id"]
	if region == "" || listenerID == "" {
		return errors.New("Aliyun load balancer region and listener ID are required")
	}
	endpoint := t.product + "." + region + ".aliyuncs.com"
	version, maxResults := "2020-06-16", 100
	if t.product == "nlb" {
		version, maxResults = "2022-04-30", 50
	}
	id := casID + "-cn-hangzhou"
	if t.values["deploy_type"] == "1" {
		var list struct {
			Certificates []struct {
				CertificateID string `json:"CertificateId"`
			} `json:"Certificates"`
		}
		if err := t.rpc(ctx, endpoint, version, http.MethodPost, "ListListenerCertificates", map[string]any{
			"MaxResults": maxResults, "ListenerId": listenerID, "CertificateType": "Server",
		}, &list); err != nil {
			return err
		}
		for _, item := range list.Certificates {
			if item.CertificateID == id {
				return nil
			}
		}
		fields := map[string]any{"ListenerId": listenerID}
		if t.product == "alb" {
			fields["Certificates.1.CertificateId"] = id
		} else {
			fields["AdditionalCertificateIds.1"] = id
		}
		if err := t.rpc(ctx, endpoint, version, http.MethodPost, "AssociateAdditionalCertificatesWithListener", fields, nil); err != nil {
			return err
		}
		result.Written = true
		return nil
	}
	fields := map[string]any{"ListenerId": listenerID}
	if t.product == "alb" {
		fields["Certificates.1.CertificateId"] = id
	} else {
		fields["CertificateIds.1"] = id
	}
	if err := t.rpc(ctx, endpoint, version, http.MethodPost, "UpdateListenerAttribute", fields, nil); err != nil {
		return err
	}
	result.Written = true
	return nil
}

func (t *Aliyun) deployGA(ctx context.Context, casID string, result *Result) error {
	accelerator, listener := t.values["ga_id"], t.values["ga_listener_id"]
	if accelerator == "" || listener == "" {
		return errors.New("Aliyun GA accelerator and listener IDs are required")
	}
	endpoint, version := "ga.cn-hangzhou.aliyuncs.com", "2019-11-20"
	id := casID + "-cn-hangzhou"
	base := map[string]any{"RegionId": "cn-hangzhou", "AcceleratorId": accelerator, "ListenerId": listener}
	if t.values["deploy_type"] != "1" {
		base["Certificates.1.Id"] = id
		if err := t.rpc(ctx, endpoint, version, http.MethodPost, "UpdateListener", base, nil); err != nil {
			return err
		}
		result.Written = true
		return nil
	}
	domains := splitList(t.values["clb_domain"])
	if len(domains) == 0 {
		return errors.New("Aliyun GA extension domains are required")
	}
	var response struct {
		Certificates []struct {
			Domain        string `json:"Domain"`
			CertificateID string `json:"CertificateId"`
		} `json:"Certificates"`
	}
	if err := t.rpc(ctx, endpoint, version, http.MethodPost, "ListListenerCertificates", base, &response); err != nil {
		return err
	}
	current := map[string]string{}
	for _, item := range response.Certificates {
		current[item.Domain] = item.CertificateID
	}
	var missing []string
	for _, domain := range domains {
		if old, exists := current[domain]; !exists {
			missing = append(missing, domain)
		} else if old != id {
			fields := map[string]any{"RegionId": "cn-hangzhou", "AcceleratorId": accelerator, "ListenerId": listener,
				"Domain": domain, "CertificateId": id}
			if err := t.rpc(ctx, endpoint, version, http.MethodPost, "UpdateAdditionalCertificateWithListener", fields, nil); err != nil {
				return err
			}
			result.Written = true
		}
	}
	if len(missing) > 0 {
		fields := map[string]any{"RegionId": "cn-hangzhou", "AcceleratorId": accelerator, "ListenerId": listener}
		for index, domain := range missing {
			position := strconv.Itoa(index + 1)
			fields["Certificates."+position+".Id"] = id
			fields["Certificates."+position+".Domain"] = domain
		}
		if err := t.rpc(ctx, endpoint, version, http.MethodPost, "AssociateAdditionalCertificatesWithListener", fields, nil); err != nil {
			return err
		}
		result.Written = true
	}
	return nil
}
