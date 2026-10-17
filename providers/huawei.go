package providers

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/internal/huaweicloud"
)

//go:embed data/huawei_line.json
var huaweiLineData []byte

type huawei struct {
	dnsgo.Base
	config dnsgo.Config
	api    huaweicloud.Client
}

type huaweiRecord struct {
	ID          string     `json:"id"`
	ZoneName    string     `json:"zone_name"`
	Name        string     `json:"name"`
	Type        string     `json:"type"`
	Records     []string   `json:"records"`
	Line        jsonScalar `json:"line"`
	TTL         int        `json:"ttl"`
	MX          *uint16    `json:"mx"`
	Status      string     `json:"status"`
	Weight      *uint16    `json:"weight"`
	Description string     `json:"description"`
	UpdatedAt   string     `json:"updated_at"`
}

func init() { register("huawei", newHuawei) }

func newHuawei(config dnsgo.Config) (dnsgo.Provider, error) {
	id := config.Credentials["AccessKeyId"]
	if id == "" {
		id = config.Credentials["access_key_id"]
	}
	secret := config.Credentials["SecretAccessKey"]
	if secret == "" {
		secret = config.Credentials["secret_access_key"]
	}
	if id == "" || secret == "" {
		return nil, &dnsgo.Error{Provider: "huawei", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "AccessKeyId and SecretAccessKey are required"}
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = "dns.myhuaweicloud.com"
	}
	return &huawei{Base: dnsgo.Base{ProviderKind: "huawei", Features: dnsgo.Capabilities{
		Remarks: true, Status: true, Weight: true, CreateZone: true, Lines: true, Sort: true,
	}}, config: config, api: huaweicloud.Client{KeyID: id, Secret: secret, Endpoint: endpoint, HTTP: client(config)}}, nil
}

func (h *huawei) zoneID(zone string) (string, error) {
	if zone == "" {
		zone = h.config.DomainID
	}
	if zone == "" {
		return "", &dnsgo.Error{Provider: h.Kind(), Operation: "zone_id", Code: dnsgo.CodeInvalidInput, Message: "zone ID is required"}
	}
	return zone, nil
}

func (h *huawei) zoneName(ctx context.Context, zone string) (string, error) {
	if h.config.Domain != "" {
		return strings.TrimSuffix(h.config.Domain, "."), nil
	}
	var result struct {
		Name string `json:"name"`
	}
	if err := h.api.Call(ctx, http.MethodGet, "/v2/zones/"+url.PathEscape(zone), nil, nil, &result); err != nil {
		return "", err
	}
	return strings.TrimSuffix(result.Name, "."), nil
}

func (h *huawei) Check(ctx context.Context) error {
	_, err := h.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (h *huawei) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	offset, size := offsetPage(query.Page, query.PageSize)
	params := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(size)}}
	if query.Keyword != "" {
		params.Set("name", query.Keyword)
	}
	var result struct {
		Zones []struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Count int    `json:"record_num"`
		} `json:"zones"`
		Metadata struct {
			Total int `json:"total_count"`
		} `json:"metadata"`
	}
	if err := h.api.Call(ctx, http.MethodGet, "/v2/zones", params, nil, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(result.Zones))
	for _, row := range result.Zones {
		zones = append(zones, dnsgo.Zone{ID: row.ID, Name: strings.TrimSuffix(row.Name, "."), RecordCount: row.Count})
	}
	return dnsgo.Page[dnsgo.Zone]{Total: result.Metadata.Total, Items: zones}, nil
}

func (h *huawei) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	var result struct{ ID, Name string }
	if err := h.api.Call(ctx, http.MethodPost, "/v2/zones", nil, map[string]string{"name": strings.TrimSuffix(name, ".")}, &result); err != nil {
		return dnsgo.Zone{}, err
	}
	return dnsgo.Zone{ID: result.ID, Name: strings.TrimSuffix(result.Name, ".")}, nil
}

func (h *huawei) toRecord(zone string, row huaweiRecord) dnsgo.Record {
	domain := strings.TrimSuffix(row.ZoneName, ".")
	if domain == "" {
		domain = strings.TrimSuffix(h.config.Domain, ".")
	}
	name := strings.TrimSuffix(row.Name, ".")
	if name == domain {
		name = "@"
	} else if domain != "" {
		name = strings.TrimSuffix(name, "."+domain)
	}
	values := append([]string(nil), row.Records...)
	value := ""
	if len(values) > 0 {
		value = values[0]
		if row.Type == "TXT" {
			value = strings.Trim(value, "\"")
		}
	}
	enabled := row.Status == "ACTIVE"
	return dnsgo.Record{ID: row.ID, ZoneID: zone, Name: name, Type: row.Type, Value: value, Values: values,
		Line: row.Line.String(), TTL: row.TTL, Priority: row.MX, Weight: row.Weight,
		Enabled: &enabled, Remark: row.Description, ModifiedAt: row.UpdatedAt}
}

func (h *huawei) recordPath(zone string) string {
	return "/v2.1/zones/" + url.PathEscape(zone) + "/recordsets"
}

func (h *huawei) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	zone, err := h.zoneID(zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	offset, size := offsetPage(query.Page, query.PageSize)
	params := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(size)}}
	for key, value := range map[string]string{"type": query.Type, "line_id": query.Line, "records": query.Value} {
		if value != "" {
			params.Set(key, value)
		}
	}
	if query.Enabled != nil {
		if *query.Enabled {
			params.Set("status", "ACTIVE")
		} else {
			params.Set("status", "DISABLE")
		}
	}
	if query.Name != "" {
		domain, err := h.zoneName(ctx, zone)
		if err != nil {
			return dnsgo.Page[dnsgo.Record]{}, err
		}
		params.Set("name", h.fqdn(domain, query.Name))
		params.Set("search_mode", "equal")
	} else if query.Keyword != "" {
		params.Set("name", query.Keyword)
	}
	allowedSort := map[string]string{"Name": "name", "Type": "type", "UpdateTime": "updated_at"}
	if sortKey := allowedSort[query.SortField]; sortKey != "" {
		params.Set("sort_key", sortKey)
		if query.SortDesc {
			params.Set("sort_dir", "desc")
		} else {
			params.Set("sort_dir", "asc")
		}
	}
	var result struct {
		Records  []huaweiRecord `json:"recordsets"`
		Metadata struct {
			Total int `json:"total_count"`
		} `json:"metadata"`
	}
	if err := h.api.Call(ctx, http.MethodGet, h.recordPath(zone), params, nil, &result); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	records := make([]dnsgo.Record, 0, len(result.Records))
	for _, row := range result.Records {
		records = append(records, h.toRecord(zone, row))
	}
	return dnsgo.Page[dnsgo.Record]{Total: result.Metadata.Total, Items: records}, nil
}

func (h *huawei) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	zone, err := h.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var result huaweiRecord
	if err := h.api.Call(ctx, http.MethodGet, h.recordPath(zone)+"/"+url.PathEscape(id), nil, nil, &result); err != nil {
		return dnsgo.Record{}, err
	}
	return h.toRecord(zone, result), nil
}

func (h *huawei) fqdn(domain, name string) string {
	if name == "" || name == "@" || name == domain {
		return domain + "."
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	if strings.HasSuffix(name, "."+domain) {
		return name + "."
	}
	return name + "." + domain + "."
}

func (h *huawei) recordInput(domain string, record dnsgo.Record) map[string]any {
	values := append([]string(nil), record.Values...)
	if len(values) == 0 {
		values = []string{record.Value}
	}
	if record.Type == "TXT" {
		for i, value := range values {
			if !strings.HasPrefix(value, "\"") {
				values[i] = strconv.Quote(value)
			}
		}
	}
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	line := record.Line
	if line == "" || line == "default" {
		line = "0"
	}
	input := map[string]any{"name": h.fqdn(domain, record.Name), "type": record.Type,
		"records": values, "line": line, "ttl": ttl, "description": record.Remark}
	if record.Weight != nil && *record.Weight > 0 {
		input["weight"] = *record.Weight
	}
	return input
}

func (h *huawei) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(h.Kind(), h.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := h.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	domain, err := h.zoneName(ctx, zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var result huaweiRecord
	if err := h.api.Call(ctx, http.MethodPost, h.recordPath(zone), nil, h.recordInput(domain, record), &result); err != nil {
		return dnsgo.Record{}, err
	}
	created := h.toRecord(zone, result)
	return applyRequestedStatus(ctx, h, zone, created, record.Enabled, created.Enabled)
}

func (h *huawei) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(h.Kind(), h.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := h.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: h.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	current, err := h.GetRecord(ctx, zone, record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if len(record.Values) == 0 && len(current.Values) > 1 {
		return dnsgo.Record{}, &dnsgo.Error{Provider: h.Kind(), Operation: "update_record", Code: dnsgo.CodeConflict,
			Message: "multi-value record set requires explicit Values to avoid dropping members"}
	}
	if len(record.Values) > 0 && slices.Equal(record.Values, current.Values) && record.Value != current.Value {
		record.Values = append([]string(nil), record.Values...)
		record.Values[0] = record.Value
	}
	domain, err := h.zoneName(ctx, zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var result huaweiRecord
	if err := h.api.Call(ctx, http.MethodPut, h.recordPath(zone)+"/"+url.PathEscape(record.ID), nil, h.recordInput(domain, record), &result); err != nil {
		return dnsgo.Record{}, err
	}
	updated := h.toRecord(zone, result)
	return applyRequestedStatus(ctx, h, zone, updated, record.Enabled, current.Enabled)
}

func (h *huawei) SetRecordRemark(ctx context.Context, zone, id, remark string) error {
	record, err := h.GetRecord(ctx, zone, id)
	if err != nil {
		return err
	}
	record.Remark = remark
	_, err = h.UpdateRecord(ctx, zone, record)
	return err
}

func (h *huawei) DeleteRecord(ctx context.Context, zone, id string) error {
	zone, err := h.zoneID(zone)
	if err != nil {
		return err
	}
	return h.api.Call(ctx, http.MethodDelete, h.recordPath(zone)+"/"+url.PathEscape(id), nil, nil, nil)
}

func (h *huawei) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	if _, err := h.zoneID(zone); err != nil {
		return err
	}
	status := "DISABLE"
	if enabled {
		status = "ENABLE"
	}
	return h.api.Call(ctx, http.MethodPut, "/v2.1/recordsets/"+url.PathEscape(id)+"/statuses/set", nil,
		map[string]string{"status": status}, nil)
}

func (h *huawei) RecordLines(context.Context, string) ([]dnsgo.RecordLine, error) {
	var rows map[string]struct {
		Name   string     `json:"name"`
		Parent jsonScalar `json:"parent"`
	}
	if err := json.Unmarshal(huaweiLineData, &rows); err != nil {
		return nil, &dnsgo.Error{Provider: h.Kind(), Operation: "record_lines", Code: dnsgo.CodeResultUnknown, Cause: err}
	}
	codes := make([]string, 0, len(rows))
	for code := range rows {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	lines := make([]dnsgo.RecordLine, 0, len(rows))
	for _, code := range codes {
		lines = append(lines, dnsgo.RecordLine{Code: code, Name: rows[code].Name, Parent: rows[code].Parent.String()})
	}
	return lines, nil
}

var _ dnsgo.Provider = (*huawei)(nil)
