package providers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/internal/bce"
)

type baidu struct {
	dnsgo.Base
	config dnsgo.Config
	api    bce.Client
}

type baiduRecord struct {
	ID          jsonScalar `json:"id"`
	RR          string     `json:"rr"`
	Type        string     `json:"type"`
	Value       string     `json:"value"`
	Line        string     `json:"line"`
	TTL         int        `json:"ttl"`
	Priority    *uint16    `json:"priority"`
	Status      string     `json:"status"`
	Description string     `json:"description"`
}

func init() { register("baidu", newBaidu) }

func newBaidu(config dnsgo.Config) (dnsgo.Provider, error) {
	id := config.Credentials["AccessKeyId"]
	if id == "" {
		id = config.Credentials["access_key_id"]
	}
	secret := config.Credentials["SecretAccessKey"]
	if secret == "" {
		secret = config.Credentials["secret_access_key"]
	}
	if id == "" || secret == "" {
		return nil, &dnsgo.Error{Provider: "baidu", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "AccessKeyId and SecretAccessKey are required"}
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = "dns.baidubce.com"
	}
	return &baidu{Base: dnsgo.Base{ProviderKind: "baidu", Features: dnsgo.Capabilities{
		Remarks: true, Status: true, CreateZone: true, Lines: true,
	}}, config: config, api: bce.Client{KeyID: id, Secret: secret, Endpoint: endpoint, HTTP: client(config)}}, nil
}

func (b *baidu) domain(zone string) (string, error) {
	if zone == "" {
		zone = b.config.Domain
	}
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if zone == "" {
		return "", &dnsgo.Error{Provider: b.Kind(), Operation: "domain", Code: dnsgo.CodeInvalidInput, Message: "domain is required"}
	}
	return zone, nil
}

func bceToken() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func (b *baidu) Check(ctx context.Context) error {
	_, err := b.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (b *baidu) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	params := url.Values{}
	if query.Keyword != "" {
		params.Set("name", query.Keyword)
	}
	var result struct {
		Zones []struct {
			ID   jsonScalar `json:"id"`
			Name string     `json:"name"`
		} `json:"zones"`
	}
	if err := b.api.Call(ctx, http.MethodGet, "/v1/dns/zone", params, nil, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(result.Zones))
	for _, row := range result.Zones {
		name := strings.TrimSuffix(row.Name, ".")
		if query.Keyword == "" || strings.Contains(strings.ToLower(name), strings.ToLower(query.Keyword)) {
			zones = append(zones, dnsgo.Zone{ID: name, Name: name, Extra: map[string]any{"vendor_id": row.ID.String()}})
		}
	}
	total := len(zones)
	start, size := offsetPage(query.Page, query.PageSize)
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	return dnsgo.Page[dnsgo.Zone]{Total: total, Items: zones[start:end]}, nil
}

func (b *baidu) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	name = strings.TrimSuffix(name, ".")
	token, err := bceToken()
	if err != nil {
		return dnsgo.Zone{}, err
	}
	if err := b.api.Call(ctx, http.MethodPost, "/v1/dns/zone", nil, map[string]string{"clientToken": token, "name": name}, nil); err != nil {
		return dnsgo.Zone{}, err
	}
	page, err := b.ListZones(ctx, dnsgo.ZoneQuery{Keyword: name})
	if err != nil {
		return dnsgo.Zone{}, err
	}
	for _, zone := range page.Items {
		if zone.Name == name {
			return zone, nil
		}
	}
	return dnsgo.Zone{}, &dnsgo.Error{Provider: b.Kind(), Operation: "create_zone", Code: dnsgo.CodeResultUnknown,
		Message: "zone was created but could not be confirmed"}
}

func (b *baidu) toRecord(domain string, row baiduRecord) dnsgo.Record {
	enabled := row.Status == "running"
	return dnsgo.Record{ID: row.ID.String(), ZoneID: domain, Name: row.RR, Type: row.Type, Value: row.Value,
		Line: row.Line, TTL: row.TTL, Priority: row.Priority, Enabled: &enabled, Remark: row.Description}
}

func (b *baidu) recordPath(domain string) string {
	return "/v1/dns/zone/" + url.PathEscape(domain) + "/record"
}

func (b *baidu) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	domain, err := b.domain(zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	params := url.Values{}
	if query.Name != "" {
		params.Set("rr", strings.ToLower(query.Name))
	}
	var result struct {
		Records []baiduRecord `json:"records"`
	}
	if err := b.api.Call(ctx, http.MethodGet, b.recordPath(domain), params, nil, &result); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	matched := make([]dnsgo.Record, 0, len(result.Records))
	for _, row := range result.Records {
		record := b.toRecord(domain, row)
		if query.Name != "" && !strings.EqualFold(record.Name, query.Name) || query.Type != "" && record.Type != query.Type ||
			query.Value != "" && record.Value != query.Value || query.Keyword != "" && !strings.Contains(record.Name, query.Keyword) && !strings.Contains(record.Value, query.Keyword) ||
			query.Line != "" && record.Line != query.Line || query.Enabled != nil && *query.Enabled != *record.Enabled {
			continue
		}
		matched = append(matched, record)
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

func (b *baidu) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	domain, err := b.domain(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var result struct {
		Records []baiduRecord `json:"records"`
	}
	if err := b.api.Call(ctx, http.MethodGet, b.recordPath(domain), url.Values{"id": {id}}, nil, &result); err != nil {
		return dnsgo.Record{}, err
	}
	if len(result.Records) == 0 {
		return dnsgo.Record{}, &dnsgo.Error{Provider: b.Kind(), Operation: "get_record", Code: dnsgo.CodeNotFound}
	}
	return b.toRecord(domain, result.Records[0]), nil
}

func (b *baidu) recordInput(record dnsgo.Record) map[string]any {
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	line := record.Line
	if line == "" {
		line = "0"
	}
	input := map[string]any{"rr": record.Name, "type": record.Type, "value": record.Value,
		"line": line, "ttl": ttl, "description": record.Remark}
	if record.Type == "MX" {
		priority := uint16(1)
		if record.Priority != nil {
			priority = *record.Priority
		}
		input["priority"] = priority
	}
	return input
}

func (b *baidu) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(b.Kind(), b.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	domain, err := b.domain(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	beforePage, err := b.ListRecords(ctx, domain, dnsgo.RecordQuery{Name: record.Name, Type: record.Type, Value: record.Value,
		Page: 1, PageSize: int(^uint(0) >> 1)})
	if err != nil {
		return dnsgo.Record{}, err
	}
	before := make(map[string]bool, len(beforePage.Items))
	for _, existing := range beforePage.Items {
		before[existing.ID] = true
	}
	token, err := bceToken()
	if err != nil {
		return dnsgo.Record{}, err
	}
	var raw json.RawMessage
	if err := b.api.Call(ctx, http.MethodPost, b.recordPath(domain), url.Values{"clientToken": {token}}, b.recordInput(record), &raw); err != nil {
		return dnsgo.Record{}, err
	}
	var result struct {
		ID jsonScalar `json:"id"`
	}
	_ = json.Unmarshal(raw, &result)
	record.ID, record.ZoneID = result.ID.String(), domain
	if record.ID == "" {
		afterPage, err := b.ListRecords(ctx, domain, dnsgo.RecordQuery{Name: record.Name, Type: record.Type, Value: record.Value,
			Page: 1, PageSize: int(^uint(0) >> 1)})
		if err != nil {
			return dnsgo.Record{}, &dnsgo.Error{Provider: b.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
				Message: "record created but readback failed", Cause: err}
		}
		for _, created := range afterPage.Items {
			if !before[created.ID] {
				return applyRequestedStatus(ctx, b, domain, created, record.Enabled, created.Enabled)
			}
		}
		return dnsgo.Record{}, &dnsgo.Error{Provider: b.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
			Message: "record was created but its ID could not be confirmed"}
	}
	return applyRequestedStatus(ctx, b, domain, record, record.Enabled, nil)
}

func (b *baidu) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(b.Kind(), b.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	domain, err := b.domain(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: b.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	current, err := b.GetRecord(ctx, domain, record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	token, err := bceToken()
	if err != nil {
		return dnsgo.Record{}, err
	}
	if err := b.api.Call(ctx, http.MethodPut, b.recordPath(domain)+"/"+url.PathEscape(record.ID),
		url.Values{"clientToken": {token}}, b.recordInput(record), nil); err != nil {
		return dnsgo.Record{}, err
	}
	record.ZoneID = domain
	return applyRequestedStatus(ctx, b, domain, record, record.Enabled, current.Enabled)
}

func (b *baidu) SetRecordRemark(ctx context.Context, zone, id, remark string) error {
	current, err := b.GetRecord(ctx, zone, id)
	if err != nil {
		return err
	}
	current.Remark = remark
	_, err = b.UpdateRecord(ctx, zone, current)
	return err
}

func (b *baidu) DeleteRecord(ctx context.Context, zone, id string) error {
	domain, err := b.domain(zone)
	if err != nil {
		return err
	}
	token, err := bceToken()
	if err != nil {
		return err
	}
	return b.api.Call(ctx, http.MethodDelete, b.recordPath(domain)+"/"+url.PathEscape(id), url.Values{"clientToken": {token}}, nil, nil)
}

func (b *baidu) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	domain, err := b.domain(zone)
	if err != nil {
		return err
	}
	token, err := bceToken()
	if err != nil {
		return err
	}
	action := "disable"
	if enabled {
		action = "enable"
	}
	return b.api.Call(ctx, http.MethodPut, b.recordPath(domain)+"/"+url.PathEscape(id),
		url.Values{"clientToken": {token}, action: {""}}, nil, nil)
}

func (b *baidu) RecordLines(context.Context, string) ([]dnsgo.RecordLine, error) {
	return []dnsgo.RecordLine{{Code: "default", Name: "默认"}, {Code: "ct", Name: "电信"},
		{Code: "cnc", Name: "联通"}, {Code: "cmnet", Name: "移动"},
		{Code: "edu", Name: "教育网"}, {Code: "search", Name: "搜索引擎(百度)"}}, nil
}

var _ dnsgo.Provider = (*baidu)(nil)
