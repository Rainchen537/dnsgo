package providers

import (
	"context"
	"strings"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/internal/tc3"
)

type tencentEO struct {
	dnsgo.Base
	config dnsgo.Config
	api    tc3.Client
}

type eoRecord struct {
	ID         string  `json:"RecordId"`
	Name       string  `json:"Name"`
	Type       string  `json:"Type"`
	Content    string  `json:"Content"`
	Location   string  `json:"Location"`
	TTL        int     `json:"TTL"`
	Priority   *uint16 `json:"Priority"`
	Status     string  `json:"Status"`
	Weight     int     `json:"Weight"`
	ModifiedOn string  `json:"ModifiedOn"`
}

func init() { register("tencenteo", newTencentEO) }

func newTencentEO(config dnsgo.Config) (dnsgo.Provider, error) {
	id := config.Credentials["SecretId"]
	if id == "" {
		id = config.Credentials["secret_id"]
	}
	secret := config.Credentials["SecretKey"]
	if secret == "" {
		secret = config.Credentials["secret_key"]
	}
	if id == "" || secret == "" {
		return nil, &dnsgo.Error{Provider: "tencenteo", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "SecretId and SecretKey are required"}
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = "teo.tencentcloudapi.com"
		if config.Credentials["site_type"] == "intl" {
			endpoint = "teo.intl.tencentcloudapi.com"
		}
	}
	return &tencentEO{Base: dnsgo.Base{ProviderKind: "tencenteo", Features: dnsgo.Capabilities{
		MinTTL: 60, Status: true, Weight: true, Lines: true, Sort: true,
	}}, config: config, api: tc3.Client{KeyID: id, Secret: secret, Service: "teo", Version: "2022-09-01", Endpoint: endpoint,
		HTTP: client(config)}}, nil
}

func (e *tencentEO) Check(ctx context.Context) error {
	_, err := e.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (e *tencentEO) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	offset, limit := podOffset(query.Page, query.PageSize)
	filters := []map[string]any{{"Name": "zone-type", "Values": []string{"full"}}}
	if query.Keyword != "" {
		filters = append(filters, map[string]any{"Name": "zone-name", "Values": []string{query.Keyword}})
	}
	var result struct {
		Total int `json:"TotalCount"`
		Zones []struct {
			ID   string `json:"ZoneId"`
			Name string `json:"ZoneName"`
		} `json:"Zones"`
	}
	if err := e.api.Call(ctx, "DescribeZones", map[string]any{"Offset": offset, "Limit": limit, "Filters": filters}, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	page := dnsgo.Page[dnsgo.Zone]{Total: result.Total, Items: make([]dnsgo.Zone, 0, len(result.Zones))}
	for _, row := range result.Zones {
		page.Items = append(page.Items, dnsgo.Zone{ID: row.ID, Name: row.Name})
	}
	return page, nil
}

func (e *tencentEO) zoneID(zone string) (string, error) {
	if zone == "" {
		zone = e.config.DomainID
	}
	if zone == "" {
		return "", &dnsgo.Error{Provider: e.Kind(), Operation: "zone_id", Code: dnsgo.CodeInvalidInput, Message: "ZoneId is required"}
	}
	return zone, nil
}

func (e *tencentEO) domain() (string, error) {
	domain := strings.TrimSuffix(e.config.Domain, ".")
	if domain == "" {
		return "", &dnsgo.Error{Provider: e.Kind(), Operation: "domain", Code: dnsgo.CodeInvalidInput, Message: "domain is required for DNS records"}
	}
	return domain, nil
}

func (e *tencentEO) fqdn(name string) (string, error) {
	domain, err := e.domain()
	if err != nil {
		return "", err
	}
	if name == "@" || name == "" || name == domain {
		return domain, nil
	}
	if strings.HasSuffix(name, "."+domain) {
		return name, nil
	}
	return name + "." + domain, nil
}

func (e *tencentEO) toRecord(zone string, row eoRecord) dnsgo.Record {
	domain := strings.TrimSuffix(e.config.Domain, ".")
	name := row.Name
	if name == domain {
		name = "@"
	} else if domain != "" {
		name = strings.TrimSuffix(name, "."+domain)
	}
	enabled := row.Status == "enable"
	var weight *uint16
	if row.Weight >= 0 {
		v := uint16(row.Weight)
		weight = &v
	}
	return dnsgo.Record{ID: row.ID, ZoneID: zone, Name: name, Type: row.Type, Value: row.Content,
		Line: row.Location, TTL: row.TTL, Priority: row.Priority, Enabled: &enabled, Weight: weight, ModifiedAt: row.ModifiedOn}
}

func (e *tencentEO) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	zone, err := e.zoneID(zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	if _, err := e.domain(); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	offset, limit := podOffset(query.Page, query.PageSize)
	filters := []map[string]any{}
	if query.Name != "" || query.Keyword != "" {
		name := query.Name
		if name == "" {
			name = query.Keyword
		}
		full, err := e.fqdn(name)
		if err != nil {
			return dnsgo.Page[dnsgo.Record]{}, err
		}
		filters = append(filters, map[string]any{"Name": "name", "Values": []string{full}})
	}
	if query.Value != "" {
		filters = append(filters, map[string]any{"Name": "content", "Values": []string{query.Value}, "Fuzzy": true})
	}
	if query.Type != "" {
		filters = append(filters, map[string]any{"Name": "type", "Values": []string{query.Type}})
	}
	param := map[string]any{"ZoneId": zone, "Offset": offset, "Limit": limit, "Filters": filters}
	allowedSort := map[string]string{"Name": "name", "Type": "type", "Value": "content", "UpdateTime": "modified-on"}
	if field := allowedSort[query.SortField]; field != "" {
		param["SortBy"] = field
		if query.SortDesc {
			param["SortOrder"] = "desc"
		} else {
			param["SortOrder"] = "asc"
		}
	}
	var result struct {
		Total   int        `json:"TotalCount"`
		Records []eoRecord `json:"DnsRecords"`
	}
	if err := e.api.Call(ctx, "DescribeDnsRecords", param, &result); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	page := dnsgo.Page[dnsgo.Record]{Total: result.Total, Items: make([]dnsgo.Record, 0, len(result.Records))}
	for _, row := range result.Records {
		record := e.toRecord(zone, row)
		if query.Line != "" && query.Line != record.Line || query.Enabled != nil && *query.Enabled != *record.Enabled {
			continue
		}
		page.Items = append(page.Items, record)
	}
	return page, nil
}

func (e *tencentEO) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	zone, err := e.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if _, err := e.domain(); err != nil {
		return dnsgo.Record{}, err
	}
	var result struct {
		Records []eoRecord `json:"DnsRecords"`
	}
	filters := []map[string]any{{"Name": "id", "Values": []string{id}}}
	if err := e.api.Call(ctx, "DescribeDnsRecords", map[string]any{"ZoneId": zone, "Filters": filters}, &result); err != nil {
		return dnsgo.Record{}, err
	}
	if len(result.Records) == 0 {
		return dnsgo.Record{}, &dnsgo.Error{Provider: e.Kind(), Operation: "get_record", Code: dnsgo.CodeNotFound}
	}
	return e.toRecord(zone, result.Records[0]), nil
}

func (e *tencentEO) recordInput(zone string, record dnsgo.Record) (map[string]any, error) {
	name, err := e.fqdn(record.Name)
	if err != nil {
		return nil, err
	}
	line := record.Line
	if line == "" || line == "default" {
		line = "0"
	}
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	weight := -1
	if record.Weight != nil && *record.Weight > 0 {
		weight = int(*record.Weight)
	}
	param := map[string]any{"ZoneId": zone, "Name": name, "Type": record.Type, "Content": record.Value,
		"Location": line, "TTL": ttl, "Weight": weight}
	if record.Type == "MX" {
		priority := uint16(1)
		if record.Priority != nil {
			priority = *record.Priority
		}
		param["Priority"] = priority
	}
	return param, nil
}

func (e *tencentEO) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(e.Kind(), e.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := e.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	param, err := e.recordInput(zone, record)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var result struct {
		ID string `json:"RecordId"`
	}
	if err := e.api.Call(ctx, "CreateDnsRecord", param, &result); err != nil {
		return dnsgo.Record{}, err
	}
	record.ID, record.ZoneID = result.ID, zone
	if record.ID == "" {
		return record, &dnsgo.Error{Provider: e.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
			Message: "record created but provider returned no ID"}
	}
	return applyRequestedStatus(ctx, e, zone, record, record.Enabled, nil)
}

func (e *tencentEO) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(e.Kind(), e.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := e.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: e.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	current, err := e.GetRecord(ctx, zone, record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	param, err := e.recordInput(zone, record)
	if err != nil {
		return dnsgo.Record{}, err
	}
	param["DnsRecordId"] = record.ID
	if err := e.api.Call(ctx, "ModifyDnsRecord", param, nil); err != nil {
		return dnsgo.Record{}, err
	}
	record.ZoneID = zone
	return applyRequestedStatus(ctx, e, zone, record, record.Enabled, current.Enabled)
}

func (e *tencentEO) DeleteRecord(ctx context.Context, zone, id string) error {
	zone, err := e.zoneID(zone)
	if err != nil {
		return err
	}
	if id == "" {
		return &dnsgo.Error{Provider: e.Kind(), Operation: "delete_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	return e.api.Call(ctx, "DeleteDnsRecords", map[string]any{"ZoneId": zone, "RecordIds": []string{id}}, nil)
}

func (e *tencentEO) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	zone, err := e.zoneID(zone)
	if err != nil {
		return err
	}
	param := map[string]any{"ZoneId": zone}
	if enabled {
		param["RecordsToEnable"] = []string{id}
	} else {
		param["RecordsToDisable"] = []string{id}
	}
	return e.api.Call(ctx, "ModifyDnsRecordsStatus", param, nil)
}

func (e *tencentEO) RecordLines(context.Context, string) ([]dnsgo.RecordLine, error) {
	return []dnsgo.RecordLine{{Code: "Default", Name: "默认"}}, nil
}

func (e *tencentEO) MinTTL(context.Context, string) (int, error) { return 60, nil }

var _ dnsgo.Provider = (*tencentEO)(nil)
