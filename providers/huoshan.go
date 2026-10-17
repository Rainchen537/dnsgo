package providers

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/internal/volc"
)

type huoShan struct {
	dnsgo.Base
	config dnsgo.Config
	api    volc.Client
}

type huoRecord struct {
	ID        jsonScalar `json:"RecordID"`
	Host      string     `json:"Host"`
	Type      string     `json:"Type"`
	Value     string     `json:"Value"`
	Line      string     `json:"Line"`
	TTL       int        `json:"TTL"`
	Enable    bool       `json:"Enable"`
	Weight    *uint16    `json:"Weight"`
	Remark    string     `json:"Remark"`
	UpdatedAt string     `json:"UpdatedAt"`
}

var huoPlans = map[string]struct{ level, ttl int }{
	"free_inner": {1, 600}, "professional_inner": {2, 300}, "enterprise_inner": {3, 60},
	"ultimate_inner": {4, 1}, "ultimate_exclusive_inner": {5, 1},
}

func init() { register("huoshan", newHuoShan) }

func newHuoShan(config dnsgo.Config) (dnsgo.Provider, error) {
	id := config.Credentials["AccessKeyId"]
	if id == "" {
		id = config.Credentials["access_key_id"]
	}
	secret := config.Credentials["SecretAccessKey"]
	if secret == "" {
		secret = config.Credentials["secret_access_key"]
	}
	if id == "" || secret == "" {
		return nil, &dnsgo.Error{Provider: "huoshan", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "AccessKeyId and SecretAccessKey are required"}
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = "open.volcengineapi.com"
	}
	return &huoShan{Base: dnsgo.Base{ProviderKind: "huoshan", Features: dnsgo.Capabilities{
		Remarks: true, Status: true, Weight: true, CreateZone: true, Lines: true,
	}}, config: config, api: volc.Client{KeyID: id, Secret: secret, Endpoint: endpoint, Service: "DNS",
		Version: "2018-08-01", Region: "cn-north-1", HTTP: client(config)}}, nil
}

func (h *huoShan) zoneID(zone string) (int64, error) {
	if zone == "" {
		zone = h.config.DomainID
	}
	id, err := strconv.ParseInt(zone, 10, 64)
	if err != nil || id <= 0 {
		return 0, &dnsgo.Error{Provider: h.Kind(), Operation: "zone_id", Code: dnsgo.CodeInvalidInput, Message: "numeric zone ID is required"}
	}
	return id, nil
}

func (h *huoShan) Check(ctx context.Context) error {
	_, err := h.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (h *huoShan) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	page, size := query.Page, query.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	param := map[string]any{"PageNumber": page, "PageSize": size}
	if query.Keyword != "" {
		param["Key"] = query.Keyword
	}
	var result struct {
		Total int `json:"Total"`
		Zones []struct {
			ID    jsonScalar `json:"ZID"`
			Name  string     `json:"ZoneName"`
			Count int        `json:"RecordCount"`
		} `json:"Zones"`
	}
	if err := h.api.Call(ctx, http.MethodGet, "ListZones", param, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(result.Zones))
	for _, row := range result.Zones {
		zones = append(zones, dnsgo.Zone{ID: row.ID.String(), Name: row.Name, RecordCount: row.Count})
	}
	return dnsgo.Page[dnsgo.Zone]{Total: result.Total, Items: zones}, nil
}

func (h *huoShan) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	var result struct {
		ID   jsonScalar `json:"ZID"`
		Name string     `json:"ZoneName"`
	}
	if err := h.api.Call(ctx, http.MethodPost, "CreateZone", map[string]any{"ZoneName": strings.TrimSuffix(name, ".")}, &result); err != nil {
		return dnsgo.Zone{}, err
	}
	return dnsgo.Zone{ID: result.ID.String(), Name: result.Name}, nil
}

func (h *huoShan) toRecord(zone string, row huoRecord) dnsgo.Record {
	value := row.Value
	var priority *uint16
	if row.Type == "MX" {
		parts := strings.SplitN(value, " ", 2)
		if len(parts) == 2 {
			if n, err := strconv.ParseUint(parts[0], 10, 16); err == nil {
				v := uint16(n)
				priority = &v
				value = parts[1]
			}
		}
	}
	enabled := row.Enable
	return dnsgo.Record{ID: row.ID.String(), ZoneID: zone, Name: row.Host, Type: row.Type, Value: value,
		Line: row.Line, TTL: row.TTL, Priority: priority, Weight: row.Weight, Enabled: &enabled,
		Remark: row.Remark, ModifiedAt: row.UpdatedAt}
}

func (h *huoShan) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	id, err := h.zoneID(zone)
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
	param := map[string]any{"ZID": id, "PageNumber": page, "PageSize": size, "SearchOrder": "desc"}
	if query.Name != "" || query.Type != "" || query.Line != "" || query.Value != "" {
		param["SearchMode"] = "exact"
		for key, value := range map[string]string{"Host": query.Name, "Value": query.Value, "Type": query.Type, "Line": query.Line} {
			if value != "" {
				param[key] = value
			}
		}
	} else if query.Keyword != "" {
		param["Host"] = query.Keyword
	}
	var result struct {
		Total   int         `json:"TotalCount"`
		Records []huoRecord `json:"Records"`
	}
	if err := h.api.Call(ctx, http.MethodGet, "ListRecords", param, &result); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	records := make([]dnsgo.Record, 0, len(result.Records))
	for _, row := range result.Records {
		record := h.toRecord(strconv.FormatInt(id, 10), row)
		if query.Name != "" && !strings.EqualFold(query.Name, record.Name) || query.Type != "" && query.Type != record.Type ||
			query.Line != "" && query.Line != record.Line || query.Value != "" && query.Value != record.Value ||
			query.Enabled != nil && *query.Enabled != *record.Enabled {
			continue
		}
		records = append(records, record)
	}
	return dnsgo.Page[dnsgo.Record]{Total: result.Total, Items: records}, nil
}

func (h *huoShan) GetRecord(ctx context.Context, zone, recordID string) (dnsgo.Record, error) {
	id, err := h.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var row huoRecord
	if err := h.api.Call(ctx, http.MethodGet, "QueryRecord", map[string]any{"RecordID": recordID}, &row); err != nil {
		return dnsgo.Record{}, err
	}
	return h.toRecord(strconv.FormatInt(id, 10), row), nil
}

func (h *huoShan) recordInput(zone int64, record dnsgo.Record, create bool) map[string]any {
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	line := record.Line
	if line == "" {
		line = "0"
	}
	value := record.Value
	if record.Type == "MX" {
		priority := uint16(1)
		if record.Priority != nil {
			priority = *record.Priority
		}
		value = strconv.Itoa(int(priority)) + " " + value
	}
	param := map[string]any{"Host": record.Name, "Type": record.Type, "Value": value,
		"Line": line, "TTL": ttl, "Remark": record.Remark}
	if create {
		param["ZID"] = zone
	} else {
		param["RecordID"] = record.ID
	}
	if record.Weight != nil && *record.Weight > 0 {
		param["Weight"] = *record.Weight
	}
	return param
}

func (h *huoShan) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(h.Kind(), h.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	id, err := h.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var result struct {
		ID jsonScalar `json:"RecordID"`
	}
	if err := h.api.Call(ctx, http.MethodPost, "CreateRecord", h.recordInput(id, record, true), &result); err != nil {
		return dnsgo.Record{}, err
	}
	record.ID, record.ZoneID = result.ID.String(), strconv.FormatInt(id, 10)
	if record.ID == "" {
		return record, &dnsgo.Error{Provider: h.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
			Message: "record created but provider returned no ID"}
	}
	return applyRequestedStatus(ctx, h, record.ZoneID, record, record.Enabled, nil)
}

func (h *huoShan) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(h.Kind(), h.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	id, err := h.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: h.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	current, err := h.GetRecord(ctx, strconv.FormatInt(id, 10), record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if err := h.api.Call(ctx, http.MethodPost, "UpdateRecord", h.recordInput(id, record, false), nil); err != nil {
		return dnsgo.Record{}, err
	}
	record.ZoneID = strconv.FormatInt(id, 10)
	return applyRequestedStatus(ctx, h, record.ZoneID, record, record.Enabled, current.Enabled)
}

func (h *huoShan) DeleteRecord(ctx context.Context, zone, recordID string) error {
	if _, err := h.zoneID(zone); err != nil {
		return err
	}
	return h.api.Call(ctx, http.MethodPost, "DeleteRecord", map[string]any{"RecordID": recordID}, nil)
}

func (h *huoShan) SetRecordStatus(ctx context.Context, zone, recordID string, enabled bool) error {
	if _, err := h.zoneID(zone); err != nil {
		return err
	}
	return h.api.Call(ctx, http.MethodPost, "UpdateRecordStatus", map[string]any{"RecordID": recordID, "Enable": enabled}, nil)
}

func (h *huoShan) zonePlan(ctx context.Context, zone string) (struct{ level, ttl int }, error) {
	id, err := h.zoneID(zone)
	if err != nil {
		return struct{ level, ttl int }{}, err
	}
	var result struct {
		TradeCode string `json:"TradeCode"`
	}
	if err := h.api.Call(ctx, http.MethodGet, "QueryZone", map[string]any{"ZID": id}, &result); err != nil {
		return struct{ level, ttl int }{}, err
	}
	if plan, ok := huoPlans[result.TradeCode]; ok {
		return plan, nil
	}
	return huoPlans["free_inner"], nil
}

func (h *huoShan) RecordLines(ctx context.Context, zone string) ([]dnsgo.RecordLine, error) {
	plan, err := h.zonePlan(ctx, zone)
	if err != nil {
		return nil, err
	}
	var available struct {
		Lines []struct {
			Value  string `json:"Value"`
			Name   string `json:"Name"`
			Level  int    `json:"Level"`
			Parent string `json:"FatherValue"`
		} `json:"Lines"`
	}
	if err := h.api.Call(ctx, http.MethodGet, "ListLines", nil, &available); err != nil {
		return nil, err
	}
	lines := []dnsgo.RecordLine{{Code: "default", Name: "默认"}}
	for _, row := range available.Lines {
		if row.Value != "default" && row.Level <= plan.level {
			lines = append(lines, dnsgo.RecordLine{Code: row.Value, Name: row.Name, Parent: row.Parent})
		}
	}
	var custom struct {
		Total int `json:"TotalCount"`
		Lines []struct {
			Value string `json:"Line"`
			Name  string `json:"NameCN"`
		} `json:"CustomerLines"`
	}
	if err := h.api.Call(ctx, http.MethodGet, "ListCustomLines", nil, &custom); err != nil {
		return nil, err
	}
	if custom.Total > 0 {
		lines = append(lines, dnsgo.RecordLine{Code: "N.customer_lines", Name: "自定义线路"})
		for _, row := range custom.Lines {
			lines = append(lines, dnsgo.RecordLine{Code: row.Value, Name: row.Name, Parent: "N.customer_lines"})
		}
	}
	return lines, nil
}

func (h *huoShan) MinTTL(ctx context.Context, zone string) (int, error) {
	plan, err := h.zonePlan(ctx, zone)
	return plan.ttl, err
}

var _ dnsgo.Provider = (*huoShan)(nil)
