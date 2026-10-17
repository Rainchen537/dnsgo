package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/rainchen537/dnsgo"
)

func (a *aliyun) GetZoneDetails(ctx context.Context, zone string) (json.RawMessage, error) {
	return a.AliyunDomainInfo(ctx, zone)
}

func (p *dnspod) GetZoneDetails(ctx context.Context, zone string) (json.RawMessage, error) {
	return p.DNSPodDomainInfo(ctx, zone)
}

func (c *cloudflare) GetZoneDetails(ctx context.Context, zone string) (json.RawMessage, error) {
	id := c.zoneID(zone)
	if id == "" {
		return nil, &dnsgo.Error{Provider: c.Kind(), Operation: "zone_details", Code: dnsgo.CodeInvalidInput,
			Message: "zone ID is required"}
	}
	var raw json.RawMessage
	err := c.request(ctx, http.MethodGet, "/zones/"+url.PathEscape(id), nil, nil, &raw, nil)
	return raw, err
}

func (e *aliyunESA) GetZoneDetails(ctx context.Context, zone string) (json.RawMessage, error) {
	id, err := e.siteID(zone)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	err = e.call(ctx, http.MethodGet, "GetSite", url.Values{"SiteId": {id}}, &raw)
	return raw, err
}

func (d *dnsLA) GetZoneDetails(ctx context.Context, zone string) (json.RawMessage, error) {
	id, err := d.zoneID(zone)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	err = d.request(ctx, http.MethodGet, "/api/domain", url.Values{"id": {id}}, nil, &raw)
	return raw, err
}

func (r *rainbowDNS) GetZoneDetails(ctx context.Context, zone string) (json.RawMessage, error) {
	id, err := r.zoneID(zone)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	err = r.request(ctx, "/api/domain/"+url.PathEscape(id), url.Values{"loginurl": {"0"}}, &raw)
	return raw, err
}

func (h *huawei) GetZoneDetails(ctx context.Context, zone string) (json.RawMessage, error) {
	id, err := h.zoneID(zone)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	err = h.api.Call(ctx, http.MethodGet, "/v2/zones/"+url.PathEscape(id), nil, nil, &raw)
	return raw, err
}

func (h *huoShan) GetZoneDetails(ctx context.Context, zone string) (json.RawMessage, error) {
	id, err := h.zoneID(zone)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	err = h.api.Call(ctx, http.MethodGet, "QueryZone", map[string]any{"ZID": id}, &raw)
	return raw, err
}

func (j *jdCloud) GetZoneDetails(ctx context.Context, zone string) (json.RawMessage, error) {
	id, err := j.zoneID(zone)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	err = j.call(ctx, http.MethodGet, "/domain", url.Values{"domainId": {id}}, nil, &raw)
	return raw, err
}

var (
	_ ZoneDetails = (*aliyun)(nil)
	_ ZoneDetails = (*dnspod)(nil)
	_ ZoneDetails = (*cloudflare)(nil)
	_ ZoneDetails = (*aliyunESA)(nil)
	_ ZoneDetails = (*dnsLA)(nil)
	_ ZoneDetails = (*rainbowDNS)(nil)
	_ ZoneDetails = (*huawei)(nil)
	_ ZoneDetails = (*huoShan)(nil)
	_ ZoneDetails = (*jdCloud)(nil)
)
