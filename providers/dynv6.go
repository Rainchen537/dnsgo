package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rainchen537/dnsgo"
)

type dynV6 struct {
	dnsgo.Base
	config dnsgo.Config
	http   *http.Client
	base   string
	token  string
}

func init() { register("dynv6", newDynV6) }

func newDynV6(config dnsgo.Config) (dnsgo.Provider, error) {
	token := strings.TrimSpace(config.Credentials["token"])
	if token == "" {
		return nil, &dnsgo.Error{Provider: "dynv6", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "token is required"}
	}
	base := strings.TrimRight(config.Endpoint, "/")
	if base == "" {
		base = "https://dynv6.com/api/v2"
	}
	return &dynV6{Base: dnsgo.Base{ProviderKind: "dynv6", Features: dnsgo.Capabilities{}},
		config: config, http: client(config), base: base, token: token}, nil
}

func (d *dynV6) request(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return &dnsgo.Error{Provider: d.Kind(), Operation: method, Code: dnsgo.CodeInvalidInput, Cause: err}
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, d.base+path, body)
	if err != nil {
		return &dnsgo.Error{Provider: d.Kind(), Operation: method, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := d.http.Do(req)
	if err != nil {
		code := dnsgo.CodeResultUnknown
		if method == http.MethodGet {
			code = dnsgo.CodeTransport
		}
		return &dnsgo.Error{Provider: d.Kind(), Operation: method, Code: code, Message: "request failed"}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		code := dnsgo.CodeProvider
		switch response.StatusCode {
		case 401:
			code = dnsgo.CodeAuthentication
		case 403:
			code = dnsgo.CodePermission
		case 404:
			code = dnsgo.CodeNotFound
		case 409:
			code = dnsgo.CodeConflict
		case 429:
			code = dnsgo.CodeRateLimited
		}
		if ambiguousWriteResponse(method, response.StatusCode) {
			code = dnsgo.CodeResultUnknown
		}
		var detail struct{ Error, Message string }
		_ = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&detail)
		message := detail.Error
		if message == "" {
			message = detail.Message
		}
		return &dnsgo.Error{Provider: d.Kind(), Operation: method, Code: code, Message: message}
	}
	if output != nil && response.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(output); err != nil {
			return &dnsgo.Error{Provider: d.Kind(), Operation: method, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}

type dynV6Zone struct {
	ID   json.Number `json:"id"`
	Name string      `json:"name"`
}

func (d *dynV6) Check(ctx context.Context) error {
	_, err := d.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (d *dynV6) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	var rows []dynV6Zone
	if err := d.request(ctx, http.MethodGet, "/zones", nil, &rows); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(rows))
	for _, row := range rows {
		if query.Keyword == "" || strings.Contains(strings.ToLower(row.Name), strings.ToLower(query.Keyword)) {
			zones = append(zones, dnsgo.Zone{ID: row.ID.String(), Name: row.Name})
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

func (d *dynV6) resolveZone(ctx context.Context, zone string) (string, string, error) {
	if zone == "" {
		zone = d.config.Domain
	}
	if zone == "" {
		zone = d.config.DomainID
	}
	if zone == "" {
		return "", "", &dnsgo.Error{Provider: d.Kind(), Operation: "resolve_zone", Code: dnsgo.CodeInvalidInput, Message: "zone is required"}
	}
	if _, err := strconv.ParseUint(zone, 10, 64); err == nil {
		return zone, strings.TrimSuffix(d.config.Domain, "."), nil
	}
	zone = strings.TrimSuffix(zone, ".")
	var result dynV6Zone
	if err := d.request(ctx, http.MethodGet, "/zones/by-name/"+url.PathEscape(zone), nil, &result); err != nil {
		return "", "", err
	}
	if result.ID == "" {
		return "", "", &dnsgo.Error{Provider: d.Kind(), Operation: "resolve_zone", Code: dnsgo.CodeNotFound, Message: "zone ID missing"}
	}
	return result.ID.String(), zone, nil
}

type dynV6Record struct {
	ID       json.Number `json:"id"`
	Name     string      `json:"name"`
	Type     string      `json:"type"`
	Data     string      `json:"data"`
	Priority *uint16     `json:"priority"`
}

func (d *dynV6) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	id, domain, err := d.resolveZone(ctx, zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	var raw json.RawMessage
	if err := d.request(ctx, http.MethodGet, "/zones/"+url.PathEscape(id)+"/records", nil, &raw); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	var rows []dynV6Record
	if len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		if raw[0] == '{' {
			var single dynV6Record
			if err := json.Unmarshal(raw, &single); err != nil {
				return dnsgo.Page[dnsgo.Record]{}, &dnsgo.Error{Provider: d.Kind(), Operation: "list_records", Code: dnsgo.CodeResultUnknown}
			}
			rows = []dynV6Record{single}
		} else if err := json.Unmarshal(raw, &rows); err != nil {
			return dnsgo.Page[dnsgo.Record]{}, &dnsgo.Error{Provider: d.Kind(), Operation: "list_records", Code: dnsgo.CodeResultUnknown}
		}
	}
	matched := make([]dnsgo.Record, 0, len(rows))
	for _, row := range rows {
		name := strings.TrimSuffix(row.Name, ".")
		if name == domain || name == "" {
			name = "@"
		} else if domain != "" {
			name = strings.TrimSuffix(name, "."+domain)
		}
		enabled := true
		record := dnsgo.Record{ID: row.ID.String(), ZoneID: id, Name: name, Type: strings.ToUpper(row.Type), Value: row.Data,
			TTL: 600, Priority: row.Priority, Line: "default", Enabled: &enabled}
		if query.Name != "" && !strings.EqualFold(query.Name, record.Name) ||
			query.Type != "" && !strings.EqualFold(query.Type, record.Type) ||
			query.Value != "" && query.Value != record.Value ||
			query.Keyword != "" && !strings.Contains(record.Name, query.Keyword) && !strings.Contains(record.Value, query.Keyword) ||
			query.Line != "" && query.Line != "default" && query.Line != "0" ||
			query.Enabled != nil && !*query.Enabled {
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

func (d *dynV6) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	page, err := d.ListRecords(ctx, zone, dnsgo.RecordQuery{Page: 1, PageSize: int(^uint(0) >> 1)})
	if err != nil {
		return dnsgo.Record{}, err
	}
	for _, record := range page.Items {
		if record.ID == id {
			return record, nil
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: d.Kind(), Operation: "get_record", Code: dnsgo.CodeNotFound}
}

func (d *dynV6) recordInput(domain string, record dnsgo.Record) (map[string]any, error) {
	if record.Value == "" {
		return nil, &dnsgo.Error{Provider: d.Kind(), Operation: "record_input", Code: dnsgo.CodeInvalidInput, Message: "record value is required"}
	}
	name := record.Name
	if name == "" || name == "@" {
		name = domain
	}
	value := record.Value
	if (record.Type == "CNAME" || record.Type == "MX") && strings.Contains(value, ".") && !strings.HasSuffix(value, ".") {
		value += "."
	}
	input := map[string]any{"name": name, "type": record.Type, "data": value}
	if record.Type == "MX" {
		priority := uint16(1)
		if record.Priority != nil {
			priority = *record.Priority
		}
		input["priority"] = priority
	}
	return input, nil
}

func (d *dynV6) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(d.Kind(), d.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	id, domain, err := d.resolveZone(ctx, zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	input, err := d.recordInput(domain, record)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var result dynV6Record
	if err := d.request(ctx, http.MethodPost, "/zones/"+url.PathEscape(id)+"/records", input, &result); err != nil {
		return dnsgo.Record{}, err
	}
	record.ID, record.ZoneID = result.ID.String(), id
	return record, nil
}

func (d *dynV6) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(d.Kind(), d.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	id, domain, err := d.resolveZone(ctx, zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: d.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	input, err := d.recordInput(domain, record)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if err := d.request(ctx, http.MethodPatch, "/zones/"+url.PathEscape(id)+"/records/"+url.PathEscape(record.ID), input, nil); err != nil {
		return dnsgo.Record{}, err
	}
	record.ZoneID = id
	return record, nil
}

func (d *dynV6) DeleteRecord(ctx context.Context, zone, recordID string) error {
	id, _, err := d.resolveZone(ctx, zone)
	if err != nil {
		return err
	}
	if recordID == "" {
		return &dnsgo.Error{Provider: d.Kind(), Operation: "delete_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	return d.request(ctx, http.MethodDelete, "/zones/"+url.PathEscape(id)+"/records/"+url.PathEscape(recordID), nil, nil)
}

func (d *dynV6) RecordLines(context.Context, string) ([]dnsgo.RecordLine, error) {
	return []dnsgo.RecordLine{{Code: "default", Name: "默认"}}, nil
}

var _ dnsgo.Provider = (*dynV6)(nil)
