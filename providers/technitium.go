package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rainchen537/dnsgo"
)

type technitium struct {
	dnsgo.Base
	config dnsgo.Config
	http   *http.Client
	base   string
	token  string
}

type techRecord struct {
	Name     string                     `json:"name"`
	Type     string                     `json:"type"`
	TTL      int                        `json:"ttl"`
	Disabled bool                       `json:"disabled"`
	Comments string                     `json:"comments"`
	Data     map[string]json.RawMessage `json:"rData"`
}

type techIdentity struct {
	Name string                     `json:"name"`
	Type string                     `json:"type"`
	Data map[string]json.RawMessage `json:"data"`
}

func init() { register("technitium", newTechnitium) }

func newTechnitium(config dnsgo.Config) (dnsgo.Provider, error) {
	token := config.Credentials["token"]
	base := strings.TrimRight(config.Endpoint, "/")
	if base == "" {
		base = strings.TrimRight(config.Credentials["url"], "/")
	}
	if token == "" || base == "" {
		return nil, &dnsgo.Error{Provider: "technitium", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "token and endpoint are required"}
	}
	if !strings.HasSuffix(base, "/api") {
		base += "/api"
	}
	return &technitium{Base: dnsgo.Base{ProviderKind: "technitium", Features: dnsgo.Capabilities{
		RecordTypes: []string{"A", "AAAA", "CNAME", "NS", "MX", "TXT", "SRV", "PTR", "CAA", "ANAME", "DNAME", "APP", "SOA"},
		Remarks:     true, Status: true, CreateZone: true,
	}}, config: config, http: client(config), base: base, token: token}, nil
}

func (t *technitium) request(ctx context.Context, method, path string, params url.Values, output any) error {
	if params == nil {
		params = url.Values{}
	}
	params.Set("token", t.token)
	endpoint := t.base + path
	var body io.Reader
	if method == http.MethodGet || method == http.MethodDelete {
		endpoint += "?" + params.Encode()
	} else {
		body = strings.NewReader(params.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return &dnsgo.Error{Provider: t.Kind(), Operation: path, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := t.http.Do(req)
	if err != nil {
		code := dnsgo.CodeResultUnknown
		if method == http.MethodGet {
			code = dnsgo.CodeTransport
		}
		// The token can occur in the URL, so never include the request error.
		return &dnsgo.Error{Provider: t.Kind(), Operation: path, Code: code, Message: "request failed"}
	}
	defer response.Body.Close()
	var envelope struct {
		Status       string          `json:"status"`
		ErrorMessage string          `json:"errorMessage"`
		Response     json.RawMessage `json:"response"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&envelope); err != nil {
		return &dnsgo.Error{Provider: t.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || envelope.Status != "ok" {
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
		return &dnsgo.Error{Provider: t.Kind(), Operation: path, Code: code, Message: envelope.ErrorMessage}
	}
	if output != nil && len(envelope.Response) > 0 && string(envelope.Response) != "null" {
		if err := json.Unmarshal(envelope.Response, output); err != nil {
			return &dnsgo.Error{Provider: t.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}

func (t *technitium) zone(zone string) (string, error) {
	if zone == "" {
		zone = t.config.Domain
	}
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if zone == "" {
		return "", &dnsgo.Error{Provider: t.Kind(), Operation: "zone", Code: dnsgo.CodeInvalidInput, Message: "zone name is required"}
	}
	return zone, nil
}

func (t *technitium) Check(ctx context.Context) error {
	_, err := t.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (t *technitium) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	var result struct {
		Zones []struct {
			Name string `json:"name"`
		} `json:"zones"`
	}
	if err := t.request(ctx, http.MethodGet, "/zones/list", nil, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(result.Zones))
	for _, row := range result.Zones {
		if query.Keyword == "" || strings.Contains(strings.ToLower(row.Name), strings.ToLower(query.Keyword)) {
			zones = append(zones, dnsgo.Zone{ID: row.Name, Name: row.Name})
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

func (t *technitium) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	name = strings.TrimSuffix(name, ".")
	var result struct {
		Domain string `json:"domain"`
	}
	if err := t.request(ctx, http.MethodPost, "/zones/create", url.Values{"zone": {name}, "type": {"Primary"}}, &result); err != nil {
		return dnsgo.Zone{}, err
	}
	if result.Domain == "" {
		result.Domain = name
	}
	return dnsgo.Zone{ID: result.Domain, Name: result.Domain}, nil
}

func techDataString(data map[string]json.RawMessage, key string) string {
	raw := data[key]
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	if raw[0] == '"' {
		var value string
		_ = json.Unmarshal(raw, &value)
		return value
	}
	return string(raw)
}

func techValue(row techRecord) (string, *uint16) {
	get := func(key string) string { return techDataString(row.Data, key) }
	switch row.Type {
	case "A", "AAAA":
		return get("ipAddress"), nil
	case "CNAME":
		return get("cname"), nil
	case "NS":
		return get("nameServer"), nil
	case "MX":
		priority := uint16(1)
		if n, err := strconv.ParseUint(get("preference"), 10, 16); err == nil {
			priority = uint16(n)
		}
		return get("exchange"), &priority
	case "TXT":
		return get("text"), nil
	case "SRV":
		return get("priority") + " " + get("weight") + " " + get("port") + " " + get("target"), nil
	case "PTR":
		return get("ptrName"), nil
	case "CAA":
		return get("flags") + " " + get("tag") + " \"" + get("value") + "\"", nil
	case "ANAME":
		return get("aname"), nil
	case "DNAME":
		return get("dname"), nil
	case "APP":
		value := get("appName") + " " + get("classPath")
		if get("recordData") != "" {
			value += " " + get("recordData")
		}
		return strings.TrimSpace(value), nil
	default:
		return "", nil
	}
}

func techID(row techRecord) string {
	encoded, _ := json.Marshal(techIdentity{Name: row.Name, Type: row.Type, Data: row.Data})
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func (t *technitium) toRecord(zone string, row techRecord) dnsgo.Record {
	name := strings.TrimSuffix(row.Name, ".")
	if name == zone {
		name = "@"
	} else {
		name = strings.TrimSuffix(name, "."+zone)
	}
	value, priority := techValue(row)
	enabled := !row.Disabled
	return dnsgo.Record{ID: techID(row), ZoneID: zone, Name: name, Type: row.Type, Value: value,
		TTL: row.TTL, Priority: priority, Line: "default", Enabled: &enabled, Remark: row.Comments}
}

func (t *technitium) allRecords(ctx context.Context, zone string) ([]techRecord, error) {
	var result struct {
		Records []techRecord `json:"records"`
	}
	params := url.Values{"domain": {zone}, "listZone": {"true"}}
	err := t.request(ctx, http.MethodGet, "/zones/records/get", params, &result)
	return result.Records, err
}

func (t *technitium) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	zone, err := t.zone(zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	rows, err := t.allRecords(ctx, zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	matched := make([]dnsgo.Record, 0, len(rows))
	for _, row := range rows {
		record := t.toRecord(zone, row)
		if query.Name != "" && !strings.EqualFold(query.Name, record.Name) || query.Type != "" && query.Type != record.Type ||
			query.Value != "" && query.Value != record.Value || query.Keyword != "" && !strings.Contains(record.Name, query.Keyword) && !strings.Contains(record.Value, query.Keyword) ||
			query.Line != "" && query.Line != "default" && query.Line != "0" || query.Enabled != nil && *query.Enabled != *record.Enabled {
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

func (t *technitium) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	zone, err := t.zone(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	row, err := t.uniqueIdentity(ctx, zone, id)
	if err != nil {
		return dnsgo.Record{}, err
	}
	return t.toRecord(zone, row), nil
}

func (t *technitium) uniqueIdentity(ctx context.Context, zone, id string) (techRecord, error) {
	rows, err := t.allRecords(ctx, zone)
	if err != nil {
		return techRecord{}, err
	}
	var found techRecord
	count := 0
	for _, row := range rows {
		if techID(row) == id {
			found = row
			count++
		}
	}
	if count == 0 {
		return techRecord{}, &dnsgo.Error{Provider: t.Kind(), Operation: "record_identity", Code: dnsgo.CodeNotFound}
	}
	if count > 1 {
		return techRecord{}, &dnsgo.Error{Provider: t.Kind(), Operation: "record_identity", Code: dnsgo.CodeConflict,
			Message: "multiple identical records cannot be safely identified"}
	}
	return found, nil
}

func techOldParams(identity techIdentity) url.Values {
	params := url.Values{}
	fields := map[string][]string{
		"A": {"ipAddress"}, "AAAA": {"ipAddress"}, "CNAME": {"cname"}, "NS": {"nameServer"},
		"MX": {"exchange", "preference"}, "TXT": {"text"},
		"SRV": {"priority", "weight", "port", "target"}, "PTR": {"ptrName"},
		"CAA": {"flags", "tag", "value"}, "ANAME": {"aname"}, "DNAME": {"dname"},
		"APP": {"appName", "classPath", "recordData"},
	}
	for _, key := range fields[identity.Type] {
		if value := techDataString(identity.Data, key); value != "" {
			params.Set(key, value)
		}
	}
	return params
}

func techNewParams(record dnsgo.Record, update bool) (url.Values, error) {
	params := url.Values{}
	set := func(key, value string) {
		if update {
			key = "new" + strings.ToUpper(key[:1]) + key[1:]
		}
		params.Set(key, value)
	}
	switch record.Type {
	case "A", "AAAA":
		set("ipAddress", record.Value)
	case "CNAME":
		set("cname", record.Value)
	case "NS":
		set("nameServer", record.Value)
	case "MX":
		set("exchange", record.Value)
		priority := uint16(1)
		if record.Priority != nil {
			priority = *record.Priority
		}
		set("preference", strconv.Itoa(int(priority)))
	case "TXT":
		set("text", record.Value)
	case "SRV":
		parts := strings.SplitN(record.Value, " ", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("SRV value must be priority weight port target")
		}
		for i, key := range []string{"priority", "weight", "port", "target"} {
			set(key, parts[i])
		}
	case "PTR":
		set("ptrName", record.Value)
	case "CAA":
		parts := strings.SplitN(record.Value, " ", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("CAA value must be flags tag value")
		}
		set("flags", parts[0])
		set("tag", parts[1])
		set("value", strings.Trim(parts[2], "\""))
	case "ANAME":
		if update {
			params.Set("newAName", record.Value)
		} else {
			params.Set("aname", record.Value)
		}
	case "DNAME":
		if update {
			params.Set("newDName", record.Value)
		} else {
			params.Set("dname", record.Value)
		}
	case "APP":
		parts := strings.SplitN(record.Value, " ", 3)
		params.Set("appName", strings.TrimSpace(parts[0]))
		if len(parts) >= 2 {
			params.Set("classPath", parts[1])
		}
		if len(parts) == 3 {
			params.Set("recordData", parts[2])
		}
	case "SOA":
		// Technitium generates SOA fields from the zone configuration.
	default:
		return nil, dnsgo.Unsupported("technitium", "record_type_"+record.Type)
	}
	return params, nil
}

func (t *technitium) fqdn(zone, name string) string {
	if name == "" || name == "@" || name == zone {
		return zone
	}
	if strings.HasSuffix(name, "."+zone) {
		return name
	}
	return name + "." + zone
}

func (t *technitium) findCreated(ctx context.Context, zone string, before map[string]bool, record dnsgo.Record) (dnsgo.Record, error) {
	rows, err := t.allRecords(ctx, zone)
	if err != nil {
		return dnsgo.Record{}, &dnsgo.Error{Provider: t.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
			Message: "record created but readback failed", Cause: err}
	}
	for _, row := range rows {
		created := t.toRecord(zone, row)
		if !before[created.ID] && created.Name == record.Name && created.Type == record.Type && created.Value == record.Value {
			return created, nil
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: t.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
		Message: "record was created but its ID could not be confirmed"}
}

func (t *technitium) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(t.Kind(), t.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := t.zone(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	values, err := techNewParams(record, false)
	if err != nil {
		return dnsgo.Record{}, err
	}
	beforeRows, err := t.allRecords(ctx, zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	before := make(map[string]bool, len(beforeRows))
	for _, row := range beforeRows {
		before[techID(row)] = true
	}
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	values.Set("domain", t.fqdn(zone, record.Name))
	values.Set("zone", zone)
	values.Set("type", record.Type)
	values.Set("ttl", strconv.Itoa(ttl))
	if record.Remark != "" {
		values.Set("comments", record.Remark)
	}
	if err := t.request(ctx, http.MethodPost, "/zones/records/add", values, nil); err != nil {
		return dnsgo.Record{}, err
	}
	created, err := t.findCreated(ctx, zone, before, record)
	if err != nil {
		return created, err
	}
	return applyRequestedStatus(ctx, t, zone, created, record.Enabled, created.Enabled)
}

func (t *technitium) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(t.Kind(), t.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := t.zone(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	old, err := t.uniqueIdentity(ctx, zone, record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	identity := techIdentity{Name: old.Name, Type: old.Type, Data: old.Data}
	if record.Type != identity.Type {
		return dnsgo.Record{}, dnsgo.Unsupported(t.Kind(), "change_record_type")
	}
	beforeRows, err := t.allRecords(ctx, zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	before := make(map[string]bool, len(beforeRows))
	for _, row := range beforeRows {
		before[techID(row)] = true
	}
	values := techOldParams(identity)
	newValues, err := techNewParams(record, true)
	if err != nil {
		return dnsgo.Record{}, err
	}
	for key, row := range newValues {
		values[key] = row
	}
	values.Set("domain", identity.Name)
	values.Set("zone", zone)
	values.Set("type", identity.Type)
	if name := t.fqdn(zone, record.Name); name != identity.Name {
		values.Set("newDomain", name)
	}
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	values.Set("ttl", strconv.Itoa(ttl))
	values.Set("comments", record.Remark)
	if err := t.request(ctx, http.MethodPost, "/zones/records/update", values, nil); err != nil {
		return dnsgo.Record{}, err
	}
	rows, err := t.allRecords(ctx, zone)
	if err != nil {
		return record, &dnsgo.Error{Provider: t.Kind(), Operation: "update_record", Code: dnsgo.CodeResultUnknown,
			Message: "record updated but readback failed", Cause: err}
	}
	var match dnsgo.Record
	count := 0
	for _, row := range rows {
		updated := t.toRecord(zone, row)
		if updated.Name == record.Name && updated.Type == record.Type && updated.Value == record.Value {
			match = updated
			count++
		}
	}
	if count > 1 || count == 1 && match.ID != record.ID && before[match.ID] {
		return record, &dnsgo.Error{Provider: t.Kind(), Operation: "update_record", Code: dnsgo.CodeResultUnknown,
			Message: "updated record cannot be distinguished from an existing record"}
	}
	if count == 1 {
		return applyRequestedStatus(ctx, t, zone, match, record.Enabled, match.Enabled)
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: t.Kind(), Operation: "update_record", Code: dnsgo.CodeResultUnknown,
		Message: "record was updated but the new identity could not be confirmed"}
}

func (t *technitium) identityParams(ctx context.Context, zone, id string) (url.Values, error) {
	row, err := t.uniqueIdentity(ctx, zone, id)
	if err != nil {
		return nil, err
	}
	identity := techIdentity{Name: row.Name, Type: row.Type, Data: row.Data}
	values := techOldParams(identity)
	values.Set("domain", identity.Name)
	values.Set("zone", zone)
	values.Set("type", identity.Type)
	return values, nil
}

func (t *technitium) SetRecordRemark(ctx context.Context, zone, id, remark string) error {
	zone, err := t.zone(zone)
	if err != nil {
		return err
	}
	values, err := t.identityParams(ctx, zone, id)
	if err != nil {
		return err
	}
	values.Set("comments", remark)
	return t.request(ctx, http.MethodPost, "/zones/records/update", values, nil)
}

func (t *technitium) DeleteRecord(ctx context.Context, zone, id string) error {
	zone, err := t.zone(zone)
	if err != nil {
		return err
	}
	values, err := t.identityParams(ctx, zone, id)
	if err != nil {
		return err
	}
	return t.request(ctx, http.MethodPost, "/zones/records/delete", values, nil)
}

func (t *technitium) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	zone, err := t.zone(zone)
	if err != nil {
		return err
	}
	values, err := t.identityParams(ctx, zone, id)
	if err != nil {
		return err
	}
	values.Set("disable", strconv.FormatBool(!enabled))
	return t.request(ctx, http.MethodPost, "/zones/records/update", values, nil)
}

func (t *technitium) RecordLines(context.Context, string) ([]dnsgo.RecordLine, error) {
	return []dnsgo.RecordLine{{Code: "default", Name: "默认"}}, nil
}

var _ dnsgo.Provider = (*technitium)(nil)
