package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rainchen537/dnsgo"
)

// nameSilo follows the operations used by dnsmgr's NameSilo adapter. NameSilo
// does not expose status, remarks, logs or zone creation through that adapter.
type nameSilo struct {
	dnsgo.Base
	config dnsgo.Config
	http   *http.Client
	base   string
	key    string
}

func init() { register("namesilo", newNameSilo) }

func newNameSilo(config dnsgo.Config) (dnsgo.Provider, error) {
	key := strings.TrimSpace(config.Credentials["apikey"])
	if key == "" {
		return nil, &dnsgo.Error{Provider: "namesilo", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "apikey is required"}
	}
	base := strings.TrimRight(config.Endpoint, "/")
	if base == "" {
		base = "https://www.namesilo.com/api"
	}
	return &nameSilo{Base: dnsgo.Base{ProviderKind: "namesilo", Features: dnsgo.Capabilities{
		RecordTypes: []string{"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA"},
	}},
		config: config, http: client(config), base: base, key: key}, nil
}

// The API key is a query parameter in NameSilo's protocol. Never put the URL
// or the http.Client error (which contains the URL) in a returned error.
func (n *nameSilo) request(ctx context.Context, operation string, values url.Values, output any, write bool) error {
	if values == nil {
		values = url.Values{}
	}
	values.Set("version", "1")
	values.Set("type", "json")
	values.Set("key", n.key)
	endpoint := n.base + "/" + operation + "?" + values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return &dnsgo.Error{Provider: n.Kind(), Operation: operation, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	response, err := n.http.Do(req)
	if err != nil {
		code := dnsgo.CodeTransport
		if write {
			code = dnsgo.CodeResultUnknown
		}
		return &dnsgo.Error{Provider: n.Kind(), Operation: operation, Code: code, Message: "request failed"}
	}
	defer response.Body.Close()
	var envelope struct {
		Reply json.RawMessage `json:"reply"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&envelope); err != nil {
		return &dnsgo.Error{Provider: n.Kind(), Operation: operation, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response"}
	}
	var header struct {
		Code   json.RawMessage `json:"code"`
		Detail string          `json:"detail"`
	}
	if err := json.Unmarshal(envelope.Reply, &header); err != nil {
		return &dnsgo.Error{Provider: n.Kind(), Operation: operation, Code: dnsgo.CodeResultUnknown, Message: "invalid provider reply"}
	}
	code := strings.Trim(string(header.Code), "\"")
	if code != "300" || response.StatusCode < 200 || response.StatusCode >= 300 {
		kind := dnsgo.CodeProvider
		if response.StatusCode == 401 || response.StatusCode == 403 {
			kind = dnsgo.CodeAuthentication
		} else if response.StatusCode == 429 {
			kind = dnsgo.CodeRateLimited
		}
		if write && (response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= http.StatusInternalServerError) {
			kind = dnsgo.CodeResultUnknown
		}
		return &dnsgo.Error{Provider: n.Kind(), Operation: operation, Code: kind, VendorCode: code, Message: header.Detail}
	}
	if output != nil {
		if err := json.Unmarshal(envelope.Reply, output); err != nil {
			return &dnsgo.Error{Provider: n.Kind(), Operation: operation, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}

func (n *nameSilo) domain(zone string) (string, error) {
	if zone == "" {
		zone = n.config.Domain
	}
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if zone == "" {
		return "", &dnsgo.Error{Provider: n.Kind(), Operation: "domain", Code: dnsgo.CodeInvalidInput, Message: "domain is required"}
	}
	return zone, nil
}

func (n *nameSilo) Check(ctx context.Context) error {
	_, err := n.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (n *nameSilo) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	page, size := query.Page, query.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	var result struct {
		Domains []struct {
			Domain string `json:"domain"`
		} `json:"domains"`
		Pager struct {
			Total json.RawMessage `json:"total"`
		} `json:"pager"`
	}
	params := url.Values{"page": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}}
	if err := n.request(ctx, "listDomains", params, &result, false); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(result.Domains))
	for _, row := range result.Domains {
		if query.Keyword == "" || strings.Contains(strings.ToLower(row.Domain), strings.ToLower(query.Keyword)) {
			zones = append(zones, dnsgo.Zone{ID: row.Domain, Name: row.Domain})
		}
	}
	total, err := strconv.Atoi(strings.Trim(string(result.Pager.Total), "\""))
	if err != nil {
		total = len(zones)
	}
	// NameSilo has no server-side keyword filter. A keyword applies only to
	// the requested page; callers needing exhaustive search can scan pages.
	return dnsgo.Page[dnsgo.Zone]{Total: total, Items: zones}, nil
}

type nameSiloRecord struct {
	ID       string          `json:"record_id"`
	Host     string          `json:"host"`
	Type     string          `json:"type"`
	Value    string          `json:"value"`
	TTL      json.RawMessage `json:"ttl"`
	Distance json.RawMessage `json:"distance"`
}

func (n *nameSilo) allRecords(ctx context.Context, domain string) ([]dnsgo.Record, error) {
	var result struct {
		Records []nameSiloRecord `json:"resource_record"`
	}
	if err := n.request(ctx, "dnsListRecords", url.Values{"domain": {domain}}, &result, false); err != nil {
		return nil, err
	}
	records := make([]dnsgo.Record, 0, len(result.Records))
	for _, row := range result.Records {
		ttl, _ := strconv.Atoi(strings.Trim(string(row.TTL), "\""))
		var priority *uint16
		if row.Type == "MX" && len(row.Distance) > 0 {
			value, err := strconv.ParseUint(strings.Trim(string(row.Distance), "\""), 10, 16)
			if err == nil {
				v := uint16(value)
				priority = &v
			}
		}
		enabled := true
		name := strings.TrimSuffix(strings.TrimSuffix(row.Host, "."), "."+domain)
		if name == domain || name == "" {
			name = "@"
		}
		records = append(records, dnsgo.Record{ID: row.ID, ZoneID: domain, Name: name, Type: row.Type, Value: row.Value,
			TTL: ttl, Priority: priority, Line: "default", Enabled: &enabled})
	}
	return records, nil
}

func (n *nameSilo) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	domain, err := n.domain(zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	all, err := n.allRecords(ctx, domain)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	matched := make([]dnsgo.Record, 0, len(all))
	for _, row := range all {
		if query.Name != "" && !strings.EqualFold(row.Name, query.Name) ||
			query.Type != "" && !strings.EqualFold(row.Type, query.Type) ||
			query.Value != "" && row.Value != query.Value ||
			query.Keyword != "" && !strings.Contains(row.Name, query.Keyword) && !strings.Contains(row.Value, query.Keyword) ||
			query.Line != "" && query.Line != "default" && query.Line != "0" ||
			query.Enabled != nil && !*query.Enabled {
			continue
		}
		matched = append(matched, row)
	}
	total := len(matched)
	start, size := offsetPage(query.Page, query.PageSize)
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	return dnsgo.Page[dnsgo.Record]{Total: total, Items: matched[start:end]}, nil
}

func (n *nameSilo) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	page, err := n.ListRecords(ctx, zone, dnsgo.RecordQuery{Page: 1, PageSize: int(^uint(0) >> 1)})
	if err != nil {
		return dnsgo.Record{}, err
	}
	for _, record := range page.Items {
		if record.ID == id {
			return record, nil
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: n.Kind(), Operation: "get_record", Code: dnsgo.CodeNotFound}
}

func (n *nameSilo) recordParams(domain string, record dnsgo.Record) url.Values {
	name := record.Name
	if name == "@" {
		name = ""
	}
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	values := url.Values{"domain": {domain}, "rrtype": {record.Type}, "rrhost": {name},
		"rrvalue": {record.Value}, "rrttl": {strconv.Itoa(ttl)}}
	if record.Type == "MX" {
		priority := uint16(1)
		if record.Priority != nil {
			priority = *record.Priority
		}
		values.Set("rrdistance", strconv.Itoa(int(priority)))
	}
	return values
}

func (n *nameSilo) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(n.Kind(), n.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	domain, err := n.domain(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var result struct {
		ID string `json:"record_id"`
	}
	if err := n.request(ctx, "dnsAddRecord", n.recordParams(domain, record), &result, true); err != nil {
		return dnsgo.Record{}, err
	}
	record.ID, record.ZoneID = result.ID, domain
	return record, nil
}

func (n *nameSilo) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(n.Kind(), n.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	domain, err := n.domain(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: n.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	params := n.recordParams(domain, record)
	params.Set("rrid", record.ID)
	if err := n.request(ctx, "dnsUpdateRecord", params, nil, true); err != nil {
		return dnsgo.Record{}, err
	}
	record.ZoneID = domain
	return record, nil
}

func (n *nameSilo) DeleteRecord(ctx context.Context, zone, id string) error {
	domain, err := n.domain(zone)
	if err != nil {
		return err
	}
	if id == "" {
		return &dnsgo.Error{Provider: n.Kind(), Operation: "delete_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	return n.request(ctx, "dnsDeleteRecord", url.Values{"domain": {domain}, "rrid": {id}}, nil, true)
}

func (n *nameSilo) RecordLines(context.Context, string) ([]dnsgo.RecordLine, error) {
	return []dnsgo.RecordLine{{Code: "default", Name: "默认"}}, nil
}

var _ dnsgo.Provider = (*nameSilo)(nil)
