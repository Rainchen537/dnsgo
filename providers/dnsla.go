package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type dnsLA struct {
	dnsgo.Base
	config dnsgo.Config
	http   *http.Client
	base   string
	id     string
	secret string
}

type dnsLARecord struct {
	ID         json.Number `json:"id"`
	Host       string      `json:"host"`
	Type       int         `json:"type"`
	Data       string      `json:"data"`
	LineID     json.Number `json:"lineId"`
	TTL        int         `json:"ttl"`
	Preference *uint16     `json:"preference"`
	Disable    bool        `json:"disable"`
	Weight     *uint16     `json:"weight"`
	Dominant   bool        `json:"domaint"`
	DominantV2 bool        `json:"dominant"`
	UpdatedAt  int64       `json:"updatedAt"`
}

var dnsLATypes = map[string]int{"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28,
	"SRV": 33, "CAA": 257, "REDIRECT_URL": 256, "FORWARD_URL": 256}

func init() { register("dnsla", newDNSLA) }

func newDNSLA(config dnsgo.Config) (dnsgo.Provider, error) {
	id, secret := config.Credentials["apiid"], config.Credentials["apisecret"]
	if id == "" || secret == "" {
		return nil, &dnsgo.Error{Provider: "dnsla", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "apiid and apisecret are required"}
	}
	base := strings.TrimRight(config.Endpoint, "/")
	if base == "" {
		base = "https://api.dns.la"
	}
	return &dnsLA{Base: dnsgo.Base{ProviderKind: "dnsla", Features: dnsgo.Capabilities{
		RecordTypes: []string{"A", "AAAA", "NS", "CNAME", "MX", "TXT", "SRV", "CAA", "REDIRECT_URL", "FORWARD_URL"},
		Status:      true, Redirect: true, Weight: true, CreateZone: true, Lines: true,
	}}, config: config, http: client(config), base: base, id: id, secret: secret}, nil
}

func (d *dnsLA) request(ctx context.Context, method, path string, params url.Values, input, output any) error {
	endpoint := d.base + path
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return &dnsgo.Error{Provider: d.Kind(), Operation: method, Code: dnsgo.CodeInvalidInput, Cause: err}
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return &dnsgo.Error{Provider: d.Kind(), Operation: method, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	req.SetBasicAuth(d.id, d.secret)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	response, err := d.http.Do(req)
	if err != nil {
		code := dnsgo.CodeResultUnknown
		if method == http.MethodGet {
			code = dnsgo.CodeTransport
		}
		return &dnsgo.Error{Provider: d.Kind(), Operation: method, Code: code, Message: "request failed"}
	}
	defer response.Body.Close()
	var envelope struct {
		Code int             `json:"code"`
		Msg  string          `json:"msg"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&envelope); err != nil {
		return &dnsgo.Error{Provider: d.Kind(), Operation: method, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || envelope.Code != 200 {
		code := dnsgo.CodeProvider
		switch response.StatusCode {
		case 401:
			code = dnsgo.CodeAuthentication
		case 403:
			code = dnsgo.CodePermission
		case 404:
			code = dnsgo.CodeNotFound
		case 429:
			code = dnsgo.CodeRateLimited
		}
		if ambiguousWriteResponse(method, response.StatusCode) {
			code = dnsgo.CodeResultUnknown
		}
		return &dnsgo.Error{Provider: d.Kind(), Operation: method, Code: code,
			VendorCode: strconv.Itoa(envelope.Code), Message: envelope.Msg}
	}
	if output != nil && len(envelope.Data) > 0 && string(envelope.Data) != "null" {
		if err := json.Unmarshal(envelope.Data, output); err != nil {
			return &dnsgo.Error{Provider: d.Kind(), Operation: method, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}

func (d *dnsLA) zoneID(zone string) (string, error) {
	if zone == "" {
		zone = d.config.DomainID
	}
	if zone == "" {
		return "", &dnsgo.Error{Provider: d.Kind(), Operation: "zone_id", Code: dnsgo.CodeInvalidInput, Message: "domainId is required"}
	}
	return zone, nil
}

func (d *dnsLA) Check(ctx context.Context) error {
	_, err := d.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (d *dnsLA) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	page, size := query.Page, query.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	params := url.Values{"pageIndex": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}}
	var result struct {
		Total int `json:"total"`
		Rows  []struct {
			ID   json.Number `json:"id"`
			Name string      `json:"displayDomain"`
		} `json:"results"`
	}
	if err := d.request(ctx, http.MethodGet, "/api/domainList", params, nil, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(result.Rows))
	for _, row := range result.Rows {
		name := strings.TrimSuffix(row.Name, ".")
		if query.Keyword == "" || strings.Contains(strings.ToLower(name), strings.ToLower(query.Keyword)) {
			zones = append(zones, dnsgo.Zone{ID: row.ID.String(), Name: name})
		}
	}
	return dnsgo.Page[dnsgo.Zone]{Total: result.Total, Items: zones}, nil
}

func (d *dnsLA) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	name = strings.TrimSuffix(name, ".")
	var result struct {
		ID json.Number `json:"id"`
	}
	if err := d.request(ctx, http.MethodPost, "/api/domain", nil, map[string]any{"domain": name}, &result); err != nil {
		return dnsgo.Zone{}, err
	}
	return dnsgo.Zone{ID: result.ID.String(), Name: name}, nil
}

func (d *dnsLA) toRecord(zone string, row dnsLARecord) dnsgo.Record {
	kind := ""
	for name, id := range dnsLATypes {
		if id == row.Type {
			kind = name
			break
		}
	}
	if row.Type == 256 {
		kind = "FORWARD_URL"
		if row.Dominant || row.DominantV2 {
			kind = "REDIRECT_URL"
		}
	}
	enabled := !row.Disable
	modified := ""
	if row.UpdatedAt != 0 {
		modified = time.Unix(row.UpdatedAt, 0).UTC().Format(time.RFC3339)
	}
	return dnsgo.Record{ID: row.ID.String(), ZoneID: zone, Name: row.Host, Type: kind, Value: row.Data,
		Line: row.LineID.String(), TTL: row.TTL, Priority: row.Preference, Weight: row.Weight, Enabled: &enabled, ModifiedAt: modified}
}

func (d *dnsLA) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	zone, err := d.zoneID(zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	page, size := query.Page, query.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	params := url.Values{"domainId": {zone}, "pageIndex": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}}
	if query.Name != "" {
		params.Set("host", query.Name)
	} else if query.Keyword != "" {
		params.Set("host", query.Keyword)
	}
	if query.Type != "" {
		kind, ok := dnsLATypes[query.Type]
		if !ok {
			return dnsgo.Page[dnsgo.Record]{}, &dnsgo.Error{Provider: d.Kind(), Operation: "list_records", Code: dnsgo.CodeInvalidInput, Message: "unsupported record type"}
		}
		params.Set("type", strconv.Itoa(kind))
	}
	if query.Line != "" {
		params.Set("lineId", query.Line)
	}
	if query.Value != "" {
		params.Set("data", query.Value)
	}
	var result struct {
		Total int           `json:"total"`
		Rows  []dnsLARecord `json:"results"`
	}
	if err := d.request(ctx, http.MethodGet, "/api/recordList", params, nil, &result); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	records := make([]dnsgo.Record, 0, len(result.Rows))
	for _, row := range result.Rows {
		record := d.toRecord(zone, row)
		if query.Type != "" && query.Type != record.Type || query.Enabled != nil && *query.Enabled != *record.Enabled {
			continue
		}
		records = append(records, record)
	}
	return dnsgo.Page[dnsgo.Record]{Total: result.Total, Items: records}, nil
}

func (d *dnsLA) recordInput(zone string, record dnsgo.Record, create bool) (map[string]any, error) {
	kind, ok := dnsLATypes[record.Type]
	if !ok {
		return nil, &dnsgo.Error{Provider: d.Kind(), Operation: "record_input", Code: dnsgo.CodeInvalidInput, Message: "unsupported record type"}
	}
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	line := record.Line
	if line == "" || line == "default" {
		line = "0"
	}
	input := map[string]any{"type": kind, "host": record.Name, "data": record.Value, "ttl": ttl, "lineId": line}
	if record.Type == "MX" {
		priority := uint16(1)
		if record.Priority != nil {
			priority = *record.Priority
		}
		input["preference"] = priority
	}
	if record.Type == "REDIRECT_URL" || record.Type == "FORWARD_URL" {
		input["dominant"] = record.Type == "REDIRECT_URL"
	}
	if record.Weight != nil && *record.Weight > 0 {
		input["weight"] = *record.Weight
	}
	if create {
		input["domainId"] = zone
	} else {
		input["id"] = record.ID
	}
	return input, nil
}

func (d *dnsLA) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(d.Kind(), d.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := d.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	input, err := d.recordInput(zone, record, true)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var result struct {
		ID json.Number `json:"id"`
	}
	if err := d.request(ctx, http.MethodPost, "/api/record", nil, input, &result); err != nil {
		return dnsgo.Record{}, err
	}
	record.ID, record.ZoneID = result.ID.String(), zone
	if record.ID == "" {
		return record, &dnsgo.Error{Provider: d.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
			Message: "record created but provider returned no ID"}
	}
	return applyRequestedStatus(ctx, d, zone, record, record.Enabled, nil)
}

func (d *dnsLA) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(d.Kind(), d.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := d.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: d.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	current, err := d.GetRecord(ctx, zone, record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	input, err := d.recordInput(zone, record, false)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if err := d.request(ctx, http.MethodPut, "/api/record", nil, input, nil); err != nil {
		return dnsgo.Record{}, err
	}
	record.ZoneID = zone
	return applyRequestedStatus(ctx, d, zone, record, record.Enabled, current.Enabled)
}

func (d *dnsLA) DeleteRecord(ctx context.Context, zone, id string) error {
	if _, err := d.zoneID(zone); err != nil {
		return err
	}
	if id == "" {
		return &dnsgo.Error{Provider: d.Kind(), Operation: "delete_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	return d.request(ctx, http.MethodDelete, "/api/record", url.Values{"id": {id}}, nil, nil)
}

func (d *dnsLA) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	if _, err := d.zoneID(zone); err != nil {
		return err
	}
	return d.request(ctx, http.MethodPut, "/api/recordDisable", nil, map[string]any{"id": id, "disable": !enabled}, nil)
}

func (d *dnsLA) RecordLines(ctx context.Context, zone string) ([]dnsgo.RecordLine, error) {
	var rows []struct {
		ID    json.Number `json:"id"`
		Value string      `json:"value"`
		Order int         `json:"order"`
	}
	domain := d.config.Domain
	if domain == "" {
		domain = zone
	}
	if err := d.request(ctx, http.MethodGet, "/api/availableLine", url.Values{"domain": {domain}}, nil, &rows); err != nil {
		return nil, err
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Order < rows[j].Order })
	lines := make([]dnsgo.RecordLine, 0, len(rows))
	for _, row := range rows {
		code := row.ID.String()
		if code == "0" {
			code = ""
		}
		lines = append(lines, dnsgo.RecordLine{Code: code, Name: row.Value})
	}
	return lines, nil
}

func (d *dnsLA) MinTTL(ctx context.Context, zone string) (int, error) {
	zone, err := d.zoneID(zone)
	if err != nil {
		return 0, err
	}
	var result struct {
		MinTTL int `json:"minTTL"`
	}
	if err := d.request(ctx, http.MethodGet, "/api/dnsMeasures", url.Values{"id": {zone}}, nil, &result); err != nil {
		return 0, err
	}
	return result.MinTTL, nil
}

var _ dnsgo.Provider = (*dnsLA)(nil)
