package providers

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/internal/tc3"
)

type dnspod struct {
	dnsgo.Base
	config dnsgo.Config
	api    tc3.Client
}

type podRecord struct {
	ID           uint64  `json:"RecordId"`
	InfoID       uint64  `json:"Id"`
	Name         string  `json:"Name"`
	Subdomain    string  `json:"SubDomain"`
	Type         string  `json:"Type"`
	RecordType   string  `json:"RecordType"`
	Value        string  `json:"Value"`
	LineID       any     `json:"LineId"`
	RecordLineID any     `json:"RecordLineId"`
	TTL          int     `json:"TTL"`
	MX           *uint16 `json:"MX"`
	Weight       *uint16 `json:"Weight"`
	Status       string  `json:"Status"`
	Enabled      *int    `json:"Enabled"`
	Remark       string  `json:"Remark"`
	UpdatedOn    string  `json:"UpdatedOn"`
}

func init() { register("dnspod", newDNSPod) }

func newDNSPod(config dnsgo.Config) (dnsgo.Provider, error) {
	id := config.Credentials["SecretId"]
	if id == "" {
		id = config.Credentials["secret_id"]
	}
	secret := config.Credentials["SecretKey"]
	if secret == "" {
		secret = config.Credentials["secret_key"]
	}
	if id == "" || secret == "" {
		return nil, &dnsgo.Error{Provider: "dnspod", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "SecretId and SecretKey are required"}
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = "https://dnspod.tencentcloudapi.com"
	}
	return &dnspod{Base: dnsgo.Base{ProviderKind: "dnspod", Features: dnsgo.Capabilities{
		RecordTypes: []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA", "REDIRECT_URL", "FORWARD_URL"},
		MinTTL:      600, Remarks: true, Status: true, Redirect: true, Logs: true, Weight: true, CreateZone: true, Lines: true, Sort: true,
	}}, config: config, api: tc3.Client{KeyID: id, Secret: secret, Service: "dnspod", Version: "2021-03-23", Endpoint: endpoint, HTTP: client(config)}}, nil
}

func (p *dnspod) domain(zone string) string {
	if zone != "" {
		return strings.TrimSuffix(zone, ".")
	}
	return strings.TrimSuffix(p.config.Domain, ".")
}

func podOffset(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return (page - 1) * size, size
}

func (p *dnspod) Check(ctx context.Context) error {
	_, err := p.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (p *dnspod) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	offset, limit := podOffset(query.Page, query.PageSize)
	var result struct {
		List []struct {
			ID    uint64 `json:"DomainId"`
			Name  string `json:"Name"`
			Count int    `json:"RecordCount"`
		} `json:"DomainList"`
		Count struct {
			Total int `json:"DomainTotal"`
		} `json:"DomainCountInfo"`
	}
	if err := p.api.Call(ctx, "DescribeDomainList", map[string]any{"Offset": offset, "Limit": limit, "Keyword": query.Keyword}, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	page := dnsgo.Page[dnsgo.Zone]{Total: result.Count.Total, Items: make([]dnsgo.Zone, 0, len(result.List))}
	for _, row := range result.List {
		page.Items = append(page.Items, dnsgo.Zone{ID: row.Name, Name: row.Name, RecordCount: row.Count})
	}
	return page, nil
}

func (p *dnspod) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	var result struct {
		Info struct {
			ID     uint64 `json:"Id"`
			Domain string `json:"Domain"`
		} `json:"DomainInfo"`
	}
	if err := p.api.Call(ctx, "CreateDomain", map[string]any{"Domain": strings.TrimSuffix(name, ".")}, &result); err != nil {
		return dnsgo.Zone{}, err
	}
	return dnsgo.Zone{ID: result.Info.Domain, Name: result.Info.Domain}, nil
}

func (p *dnspod) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	zone = p.domain(zone)
	offset, limit := podOffset(query.Page, query.PageSize)
	param := map[string]any{"Domain": zone, "Offset": offset, "Limit": limit}
	action := "DescribeRecordList"
	if query.Enabled != nil || query.Value != "" {
		action = "DescribeRecordFilterList"
		if query.Enabled != nil {
			if *query.Enabled {
				param["RecordStatus"] = []string{"ENABLE"}
			} else {
				param["RecordStatus"] = []string{"DISABLE"}
			}
		}
		if query.Value != "" {
			param["RecordValue"] = query.Value
		}
		if query.Name != "" {
			param["SubDomain"] = aliRR(query.Name, zone)
		}
		if query.Keyword != "" {
			param["Keyword"] = query.Keyword
		}
		if query.Type != "" {
			param["RecordType"] = []string{podType(query.Type)}
		}
		if query.Line != "" {
			param["RecordLine"] = []string{podLine(query.Line)}
		}
	} else {
		if query.Name != "" {
			param["Subdomain"] = aliRR(query.Name, zone)
		}
		if query.Type != "" {
			param["RecordType"] = podType(query.Type)
		}
		if query.Line != "" {
			param["RecordLineId"] = podLine(query.Line)
		}
		if query.Keyword != "" {
			param["Keyword"] = query.Keyword
		}
	}
	allowedSort := map[string]string{"Name": "name", "Type": "type", "LineName": "line", "Value": "value", "UpdateTime": "updated_on"}
	if field := allowedSort[query.SortField]; field != "" {
		param["SortField"] = field
		if query.SortDesc {
			param["SortType"] = "DESC"
		} else {
			param["SortType"] = "ASC"
		}
	}
	var result struct {
		Total int         `json:"RecordCount"`
		List  []podRecord `json:"RecordList"`
	}
	if err := p.api.Call(ctx, action, param, &result); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	page := dnsgo.Page[dnsgo.Record]{Total: result.Total, Items: make([]dnsgo.Record, 0, len(result.List))}
	for _, row := range result.List {
		page.Items = append(page.Items, row.record(zone))
	}
	return page, nil
}

func (r podRecord) record(zone string) dnsgo.Record {
	id := r.ID
	if id == 0 {
		id = r.InfoID
	}
	name := r.Name
	if name == "" {
		name = r.Subdomain
	}
	if name == "@" || name == "" {
		name = zone
	} else if !strings.HasSuffix(name, "."+zone) {
		name += "." + zone
	}
	kind := r.Type
	if kind == "" {
		kind = r.RecordType
	}
	if kind == "显性URL" {
		kind = "REDIRECT_URL"
	}
	if kind == "隐性URL" {
		kind = "FORWARD_URL"
	}
	line := fmt.Sprint(r.LineID)
	if r.LineID == nil {
		line = fmt.Sprint(r.RecordLineID)
	}
	if line == "<nil>" {
		line = ""
	}
	enabled := strings.EqualFold(r.Status, "ENABLE")
	if r.Enabled != nil {
		enabled = *r.Enabled == 1
	}
	return dnsgo.Record{ID: strconv.FormatUint(id, 10), ZoneID: zone, Name: name, Type: kind, Value: r.Value,
		TTL: r.TTL, Priority: r.MX, Weight: r.Weight, Line: line, Enabled: &enabled, Remark: r.Remark, ModifiedAt: r.UpdatedOn}
}

func (p *dnspod) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	zone = p.domain(zone)
	recordID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return dnsgo.Record{}, &dnsgo.Error{Provider: p.Kind(), Operation: "get_record", Code: dnsgo.CodeInvalidInput, Cause: err}
	}
	var result struct {
		Info podRecord `json:"RecordInfo"`
	}
	if err := p.api.Call(ctx, "DescribeRecord", map[string]any{"Domain": zone, "RecordId": recordID}, &result); err != nil {
		return dnsgo.Record{}, err
	}
	return result.Info.record(zone), nil
}

func podType(kind string) string {
	switch kind {
	case "REDIRECT_URL":
		return "显性URL"
	case "FORWARD_URL":
		return "隐性URL"
	}
	return kind
}

func podLine(line string) string {
	lines := map[string]string{"default": "0", "unicom": "10=1", "telecom": "10=0", "mobile": "10=3", "edu": "10=2", "oversea": "3=0", "btvn": "10=22", "search": "80=0", "internal": "7=0"}
	if value := lines[line]; value != "" {
		return value
	}
	return line
}

func (p *dnspod) recordParams(zone string, record dnsgo.Record) map[string]any {
	line := record.Line
	if line == "" {
		line = "0"
	}
	value := record.Value
	if value == "" && len(record.Values) == 1 {
		value = record.Values[0]
	}
	ttl := record.TTL
	if ttl == 0 {
		ttl = 600
	}
	param := map[string]any{"Domain": zone, "SubDomain": aliRR(record.Name, zone), "RecordType": podType(record.Type),
		"Value": value, "RecordLine": line, "RecordLineId": podLine(line), "TTL": ttl}
	if record.Weight != nil {
		param["Weight"] = *record.Weight
	}
	if record.Priority != nil && strings.EqualFold(record.Type, "MX") {
		param["MX"] = *record.Priority
	}
	return param
}

func (p *dnspod) validateRecordInput(record dnsgo.Record) error {
	if record.Name == "" || record.Type == "" || record.Value == "" && len(record.Values) != 1 {
		return &dnsgo.Error{Provider: p.Kind(), Operation: "record", Code: dnsgo.CodeInvalidInput,
			Message: "record name, type and a single value are required"}
	}
	if len(record.Values) > 1 || record.Proxied != nil {
		return &dnsgo.Error{Provider: p.Kind(), Operation: "record", Code: dnsgo.CodeUnsupported,
			Message: "multi-value and proxy fields are unsupported by DNSPod record writes"}
	}
	if record.Value != "" && len(record.Values) == 1 && record.Value != record.Values[0] {
		return &dnsgo.Error{Provider: p.Kind(), Operation: "record", Code: dnsgo.CodeConflict,
			Message: "Value and Values disagree"}
	}
	return nil
}

func (p *dnspod) afterRecordWrite(ctx context.Context, zone string, record dnsgo.Record, before *dnsgo.Record) (dnsgo.Record, error) {
	partial := dnsgo.Record{ID: record.ID, ZoneID: zone, Name: record.Name, Type: record.Type,
		Value: record.Value, TTL: record.TTL, Line: record.Line}
	wrap := func(step string, err error) (dnsgo.Record, error) {
		return partial, &dnsgo.Error{Provider: p.Kind(), Operation: "write_record", Code: dnsgo.CodeResultUnknown,
			Message: "record " + step + " did not complete; read record ID before retrying", Cause: err}
	}
	if record.Enabled != nil && (before == nil && !*record.Enabled || before != nil && (before.Enabled == nil || *before.Enabled != *record.Enabled)) {
		if err := p.SetRecordStatus(ctx, zone, record.ID, *record.Enabled); err != nil {
			return wrap("status update", err)
		}
	}
	if before == nil && record.Remark != "" || before != nil && before.Remark != record.Remark {
		if err := p.SetRecordRemark(ctx, zone, record.ID, record.Remark); err != nil {
			return wrap("remark update", err)
		}
	}
	result, err := p.GetRecord(ctx, zone, record.ID)
	if err != nil {
		return wrap("readback", err)
	}
	return result, nil
}

func (p *dnspod) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(p.Kind(), p.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	if err := p.validateRecordInput(record); err != nil {
		return dnsgo.Record{}, err
	}
	zone = p.domain(zone)
	var result struct {
		ID uint64 `json:"RecordId"`
	}
	if err := p.api.Call(ctx, "CreateRecord", p.recordParams(zone, record), &result); err != nil {
		return dnsgo.Record{}, err
	}
	if result.ID == 0 {
		return dnsgo.Record{}, &dnsgo.Error{Provider: p.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
			Message: "DNSPod returned no record ID; list records before retrying"}
	}
	record.ID = strconv.FormatUint(result.ID, 10)
	return p.afterRecordWrite(ctx, zone, record, nil)
}

func (p *dnspod) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(p.Kind(), p.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	if err := p.validateRecordInput(record); err != nil {
		return dnsgo.Record{}, err
	}
	zone = p.domain(zone)
	id, err := strconv.ParseUint(record.ID, 10, 64)
	if err != nil {
		return dnsgo.Record{}, &dnsgo.Error{Provider: p.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Cause: err}
	}
	before, err := p.GetRecord(ctx, zone, record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	param := p.recordParams(zone, record)
	param["RecordId"] = id
	if err := p.api.Call(ctx, "ModifyRecord", param, nil); err != nil {
		return dnsgo.Record{}, err
	}
	return p.afterRecordWrite(ctx, zone, record, &before)
}

func (p *dnspod) SetRecordRemark(ctx context.Context, zone, id, remark string) error {
	recordID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}
	return p.api.Call(ctx, "ModifyRecordRemark", map[string]any{"Domain": p.domain(zone), "RecordId": recordID, "Remark": remark}, nil)
}

func (p *dnspod) DeleteRecord(ctx context.Context, zone, id string) error {
	recordID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}
	return p.api.Call(ctx, "DeleteRecord", map[string]any{"Domain": p.domain(zone), "RecordId": recordID}, nil)
}

func (p *dnspod) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	recordID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}
	status := "DISABLE"
	if enabled {
		status = "ENABLE"
	}
	return p.api.Call(ctx, "ModifyRecordStatus", map[string]any{"Domain": p.domain(zone), "RecordId": recordID, "Status": status}, nil)
}

func (p *dnspod) ListRecordLogs(ctx context.Context, zone string, query dnsgo.LogQuery) (dnsgo.Page[dnsgo.RecordLog], error) {
	offset, limit := podOffset(query.Page, query.PageSize)
	var result struct {
		Total int      `json:"TotalCount"`
		List  []string `json:"LogList"`
	}
	if err := p.api.Call(ctx, "DescribeDomainLogList", map[string]any{"Domain": p.domain(zone), "Offset": offset, "Limit": limit}, &result); err != nil {
		return dnsgo.Page[dnsgo.RecordLog]{}, err
	}
	page := dnsgo.Page[dnsgo.RecordLog]{Total: result.Total, Items: make([]dnsgo.RecordLog, 0, len(result.List))}
	for _, row := range result.List {
		page.Items = append(page.Items, dnsgo.RecordLog{Message: row})
	}
	return page, nil
}

type podLineRow struct {
	ID       any          `json:"LineId"`
	Name     string       `json:"LineName"`
	Useful   bool         `json:"Useful"`
	Children []podLineRow `json:"SubGroup"`
}

func (p *dnspod) RecordLines(ctx context.Context, zone string) ([]dnsgo.RecordLine, error) {
	var result struct {
		List []podLineRow `json:"LineList"`
	}
	if err := p.api.Call(ctx, "DescribeRecordLineCategoryList", map[string]any{"Domain": p.domain(zone)}, &result); err != nil {
		return nil, err
	}
	lines := []dnsgo.RecordLine{}
	var visit func([]podLineRow)
	visit = func(rows []podLineRow) {
		for _, row := range rows {
			if row.Useful {
				lines = append(lines, dnsgo.RecordLine{Code: fmt.Sprint(row.ID), Name: row.Name})
			}
			visit(row.Children)
		}
	}
	visit(result.List)
	return lines, nil
}

func (p *dnspod) MinTTL(ctx context.Context, zone string) (int, error) {
	var result struct {
		List []struct {
			Name  string `json:"Name"`
			Value string `json:"Value"`
		} `json:"PurviewList"`
	}
	if err := p.api.Call(ctx, "DescribeDomainPurview", map[string]any{"Domain": p.domain(zone)}, &result); err != nil {
		return 0, err
	}
	for _, row := range result.List {
		if row.Name == "记录 TTL 最低" || row.Name == "Min TTL value" {
			return strconv.Atoi(row.Value)
		}
	}
	return 0, dnsgo.Unsupported(p.Kind(), "min_ttl")
}
