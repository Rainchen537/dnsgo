package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/internal/jdcloud"
)

type jdCloud struct {
	dnsgo.Base
	config dnsgo.Config
	api    jdcloud.Client
}

type jdRecord struct {
	ID        jsonScalar   `json:"id"`
	Name      string       `json:"hostRecord"`
	Type      string       `json:"type"`
	Value     string       `json:"hostValue"`
	Views     []jsonScalar `json:"viewValue"`
	TTL       int          `json:"ttl"`
	Priority  *uint16      `json:"mxPriority"`
	Weight    *uint16      `json:"weight"`
	Port      int          `json:"port"`
	Status    jsonScalar   `json:"resolvingStatus"`
	UpdatedAt int64        `json:"updateTime"`
}

func init() { register("jdcloud", newJDCloud) }

func newJDCloud(config dnsgo.Config) (dnsgo.Provider, error) {
	id := config.Credentials["AccessKeyId"]
	if id == "" {
		id = config.Credentials["access_key_id"]
	}
	secret := config.Credentials["AccessKeySecret"]
	if secret == "" {
		secret = config.Credentials["access_key_secret"]
	}
	if id == "" || secret == "" {
		return nil, &dnsgo.Error{Provider: "jdcloud", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "AccessKeyId and AccessKeySecret are required"}
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = "domainservice.jdcloud-api.com"
	}
	return &jdCloud{Base: dnsgo.Base{ProviderKind: "jdcloud", Features: dnsgo.Capabilities{
		Status: true, Redirect: true, Weight: true, CreateZone: true, Lines: true,
	}}, config: config, api: jdcloud.Client{KeyID: id, Secret: secret, Endpoint: endpoint,
		Service: "domainservice", Region: "cn-north-1", HTTP: client(config)}}, nil
}

func (j *jdCloud) path(path string) string { return "/v2/regions/cn-north-1" + path }

func (j *jdCloud) call(ctx context.Context, method, path string, query url.Values, input, output any) error {
	return j.api.Call(ctx, method, j.path(path), query, input, output)
}

func (j *jdCloud) zoneID(zone string) (string, error) {
	if zone == "" {
		zone = j.config.DomainID
	}
	if zone == "" {
		return "", &dnsgo.Error{Provider: j.Kind(), Operation: "zone_id", Code: dnsgo.CodeInvalidInput, Message: "domain ID is required"}
	}
	return zone, nil
}

func (j *jdCloud) Check(ctx context.Context) error {
	_, err := j.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (j *jdCloud) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	page, size := query.Page, query.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	params := url.Values{"pageNumber": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}}
	if query.Keyword != "" {
		params.Set("domainName", query.Keyword)
	}
	var result struct {
		Total int `json:"totalCount"`
		Rows  []struct {
			ID   jsonScalar `json:"id"`
			Name string     `json:"domainName"`
		} `json:"dataList"`
	}
	if err := j.call(ctx, http.MethodGet, "/domain", params, nil, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(result.Rows))
	for _, row := range result.Rows {
		zones = append(zones, dnsgo.Zone{ID: row.ID.String(), Name: row.Name})
	}
	return dnsgo.Page[dnsgo.Zone]{Total: result.Total, Items: zones}, nil
}

func (j *jdCloud) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	var result struct {
		Data struct {
			ID   jsonScalar `json:"id"`
			Name string     `json:"domainName"`
		} `json:"data"`
	}
	if err := j.call(ctx, http.MethodPost, "/domain", nil, map[string]any{"packId": 0, "domainName": strings.TrimSuffix(name, ".")}, &result); err != nil {
		return dnsgo.Zone{}, err
	}
	return dnsgo.Zone{ID: result.Data.ID.String(), Name: result.Data.Name}, nil
}

func (j *jdCloud) toRecord(zone string, row jdRecord) dnsgo.Record {
	value := row.Value
	kind := row.Type
	if kind == "EXPLICIT_URL" {
		kind = "REDIRECT_URL"
	} else if kind == "IMPLICIT_URL" {
		kind = "FORWARD_URL"
	}
	if kind == "SRV" {
		priority, weight := uint16(0), uint16(0)
		if row.Priority != nil {
			priority = *row.Priority
		}
		if row.Weight != nil {
			weight = *row.Weight
		}
		value = strconv.Itoa(int(priority)) + " " + strconv.Itoa(int(weight)) + " " + strconv.Itoa(row.Port) + " " + value
	}
	line := ""
	if len(row.Views) > 0 {
		line = row.Views[len(row.Views)-1].String()
	}
	enabled := row.Status.String() == "2"
	modified := ""
	if row.UpdatedAt > 0 {
		modified = time.Unix(row.UpdatedAt, 0).UTC().Format(time.RFC3339)
	}
	return dnsgo.Record{ID: row.ID.String(), ZoneID: zone, Name: row.Name, Type: kind, Value: value,
		Line: line, TTL: row.TTL, Priority: row.Priority, Weight: row.Weight, Enabled: &enabled, ModifiedAt: modified}
}

func (j *jdCloud) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	zone, err := j.zoneID(zone)
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
	if size > 99 {
		size = 99
	}
	params := url.Values{"pageNumber": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}}
	if query.Name != "" {
		params.Set("search", strings.ToLower(query.Name))
	} else if query.Keyword != "" {
		params.Set("search", query.Keyword)
	}
	var result struct {
		Total int        `json:"totalCount"`
		Rows  []jdRecord `json:"dataList"`
	}
	if err := j.call(ctx, http.MethodGet, "/domain/"+url.PathEscape(zone)+"/ResourceRecord", params, nil, &result); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	records := make([]dnsgo.Record, 0, len(result.Rows))
	for _, row := range result.Rows {
		record := j.toRecord(zone, row)
		if query.Name != "" && !strings.EqualFold(query.Name, record.Name) || query.Type != "" && query.Type != record.Type ||
			query.Value != "" && query.Value != record.Value || query.Line != "" && query.Line != record.Line ||
			query.Enabled != nil && *query.Enabled != *record.Enabled {
			continue
		}
		records = append(records, record)
	}
	return dnsgo.Page[dnsgo.Record]{Total: result.Total, Items: records}, nil
}

func (j *jdCloud) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	seen := 0
	for page := 1; page <= 10000; page++ {
		result, err := j.ListRecords(ctx, zone, dnsgo.RecordQuery{Page: page, PageSize: 99})
		if err != nil {
			return dnsgo.Record{}, err
		}
		for _, row := range result.Items {
			if row.ID == id {
				return row, nil
			}
		}
		seen += len(result.Items)
		if !morePages(result.Total, seen, len(result.Items), 99) {
			break
		}
		if page == 10000 {
			return dnsgo.Record{}, &dnsgo.Error{Provider: j.Kind(), Operation: "get_record", Code: dnsgo.CodeResultUnknown,
				Message: "record listing exceeded the page limit"}
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: j.Kind(), Operation: "get_record", Code: dnsgo.CodeNotFound}
}

func (j *jdCloud) recordInput(record dnsgo.Record, update bool) (map[string]any, error) {
	kind := record.Type
	if kind == "REDIRECT_URL" {
		kind = "EXPLICIT_URL"
	} else if kind == "FORWARD_URL" {
		kind = "IMPLICIT_URL"
	}
	line := 0
	if record.Line != "" && record.Line != "default" {
		parsed, err := strconv.Atoi(record.Line)
		if err != nil {
			return nil, &dnsgo.Error{Provider: j.Kind(), Operation: "record_input", Code: dnsgo.CodeInvalidInput, Message: "numeric line ID is required"}
		}
		line = parsed
	}
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	input := map[string]any{"hostRecord": record.Name, "type": kind, "hostValue": record.Value,
		"viewValue": line, "ttl": ttl}
	if update {
		input["domainName"] = j.config.Domain
	}
	if kind == "MX" {
		priority := uint16(1)
		if record.Priority != nil {
			priority = *record.Priority
		}
		input["mxPriority"] = priority
	}
	if record.Weight != nil {
		input["weight"] = *record.Weight
	}
	if kind == "SRV" {
		parts := strings.SplitN(record.Value, " ", 4)
		if len(parts) != 4 {
			return nil, &dnsgo.Error{Provider: j.Kind(), Operation: "record_input", Code: dnsgo.CodeInvalidInput, Message: "SRV value must be priority weight port target"}
		}
		priority, err1 := strconv.Atoi(parts[0])
		weight, err2 := strconv.Atoi(parts[1])
		port, err3 := strconv.Atoi(parts[2])
		if err1 != nil || err2 != nil || err3 != nil {
			return nil, &dnsgo.Error{Provider: j.Kind(), Operation: "record_input", Code: dnsgo.CodeInvalidInput, Message: "invalid SRV value"}
		}
		input["mxPriority"], input["weight"], input["port"], input["hostValue"] = priority, weight, port, parts[3]
	}
	return input, nil
}

func (j *jdCloud) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(j.Kind(), j.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := j.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	input, err := j.recordInput(record, false)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var result struct {
		Data struct {
			ID jsonScalar `json:"id"`
		} `json:"dataList"`
	}
	if err := j.call(ctx, http.MethodPost, "/domain/"+url.PathEscape(zone)+"/ResourceRecord", nil,
		map[string]any{"req": input}, &result); err != nil {
		return dnsgo.Record{}, err
	}
	record.ID, record.ZoneID = result.Data.ID.String(), zone
	if record.ID == "" {
		return record, &dnsgo.Error{Provider: j.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
			Message: "record created but provider returned no ID"}
	}
	return applyRequestedStatus(ctx, j, zone, record, record.Enabled, nil)
}

func (j *jdCloud) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(j.Kind(), j.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := j.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: j.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	current, err := j.GetRecord(ctx, zone, record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	input, err := j.recordInput(record, true)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if err := j.call(ctx, http.MethodPut, "/domain/"+url.PathEscape(zone)+"/ResourceRecord/"+url.PathEscape(record.ID), nil,
		map[string]any{"req": input}, nil); err != nil {
		return dnsgo.Record{}, err
	}
	record.ZoneID = zone
	return applyRequestedStatus(ctx, j, zone, record, record.Enabled, current.Enabled)
}

func (j *jdCloud) DeleteRecord(ctx context.Context, zone, id string) error {
	zone, err := j.zoneID(zone)
	if err != nil {
		return err
	}
	return j.call(ctx, http.MethodDelete, "/domain/"+url.PathEscape(zone)+"/ResourceRecord/"+url.PathEscape(id), nil, nil, nil)
}

func (j *jdCloud) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	zone, err := j.zoneID(zone)
	if err != nil {
		return err
	}
	action := "disable"
	if enabled {
		action = "enable"
	}
	return j.call(ctx, http.MethodPut, "/domain/"+url.PathEscape(zone)+"/ResourceRecord/"+url.PathEscape(id)+"/status", nil,
		map[string]string{"action": action}, nil)
}

func (j *jdCloud) RecordLines(ctx context.Context, zone string) ([]dnsgo.RecordLine, error) {
	zone, err := j.zoneID(zone)
	if err != nil {
		return nil, err
	}
	var domainInfo struct {
		Rows []struct {
			PackID jsonScalar `json:"packId"`
		} `json:"dataList"`
	}
	if err := j.call(ctx, http.MethodGet, "/domain", url.Values{"domainId": {zone}}, nil, &domainInfo); err != nil {
		return nil, err
	}
	if len(domainInfo.Rows) == 0 {
		return nil, &dnsgo.Error{Provider: j.Kind(), Operation: "record_lines", Code: dnsgo.CodeNotFound, Message: "domain not found"}
	}
	var result struct {
		Data []struct {
			Value    jsonScalar        `json:"value"`
			Label    string            `json:"label"`
			Disabled bool              `json:"disabled"`
			Leaf     bool              `json:"leaf"`
			Children []json.RawMessage `json:"children"`
		} `json:"data"`
	}
	if err := j.call(ctx, http.MethodGet, "/domain/"+url.PathEscape(zone)+"/viewTree",
		url.Values{"packId": {domainInfo.Rows[0].PackID.String()}, "viewId": {"0"}}, nil, &result); err != nil {
		return nil, err
	}
	lines := []dnsgo.RecordLine{}
	var visit func([]json.RawMessage, string) error
	visit = func(items []json.RawMessage, parent string) error {
		for _, raw := range items {
			var row struct {
				Value    jsonScalar        `json:"value"`
				Label    string            `json:"label"`
				Disabled bool              `json:"disabled"`
				Children []json.RawMessage `json:"children"`
			}
			if err := json.Unmarshal(raw, &row); err != nil {
				return err
			}
			if row.Disabled {
				continue
			}
			lines = append(lines, dnsgo.RecordLine{Code: row.Value.String(), Name: row.Label, Parent: parent})
			if err := visit(row.Children, row.Value.String()); err != nil {
				return err
			}
		}
		return nil
	}
	encoded, _ := json.Marshal(result.Data)
	var roots []json.RawMessage
	if err := json.Unmarshal(encoded, &roots); err != nil {
		return nil, err
	}
	if err := visit(roots, ""); err != nil {
		return nil, err
	}
	return lines, nil
}

var _ dnsgo.Provider = (*jdCloud)(nil)
