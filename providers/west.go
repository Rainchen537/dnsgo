package providers

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rainchen537/dnsgo"
	"golang.org/x/text/encoding/simplifiedchinese"
)

type west struct {
	dnsgo.Base
	config   dnsgo.Config
	http     *http.Client
	base     string
	username string
	password string
}

type westRecord struct {
	ID    json.Number `json:"id"`
	Name  string      `json:"item"`
	Type  string      `json:"type"`
	Value string      `json:"value"`
	Line  string      `json:"line"`
	TTL   int         `json:"ttl"`
	Level *uint16     `json:"level"`
	Pause int         `json:"pause"`
}

func init() { register("west", newWest) }

func newWest(config dnsgo.Config) (dnsgo.Provider, error) {
	username, password := config.Credentials["username"], config.Credentials["api_password"]
	if username == "" || password == "" {
		return nil, &dnsgo.Error{Provider: "west", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "username and api_password are required"}
	}
	base := strings.TrimRight(config.Endpoint, "/")
	if base == "" {
		base = "https://api.west.cn/api/v2"
	}
	return &west{Base: dnsgo.Base{ProviderKind: "west", Features: dnsgo.Capabilities{Status: true, Lines: true}},
		config: config, http: client(config), base: base, username: username, password: password}, nil
}

func (w *west) request(ctx context.Context, action string, params url.Values, output any) error {
	if params == nil {
		params = url.Values{}
	}
	now := strconv.FormatInt(time.Now().UnixMilli(), 10)
	digest := md5.Sum([]byte(w.username + w.password + now))
	params.Set("username", w.username)
	params.Set("time", now)
	params.Set("token", hex.EncodeToString(digest[:]))
	params.Set("act", action)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.base+"/domain/", strings.NewReader(params.Encode()))
	if err != nil {
		return &dnsgo.Error{Provider: w.Kind(), Operation: action, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := w.http.Do(req)
	if err != nil {
		return &dnsgo.Error{Provider: w.Kind(), Operation: action, Code: dnsgo.CodeResultUnknown, Message: "request failed"}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return &dnsgo.Error{Provider: w.Kind(), Operation: action, Code: dnsgo.CodeResultUnknown, Message: "response read failed"}
	}
	if !utf8.Valid(body) {
		body, err = simplifiedchinese.GBK.NewDecoder().Bytes(body)
		if err != nil {
			return &dnsgo.Error{Provider: w.Kind(), Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid GBK response"}
		}
	}
	var envelope struct {
		Result int             `json:"result"`
		Msg    string          `json:"msg"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return &dnsgo.Error{Provider: w.Kind(), Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || envelope.Result != 200 {
		code := dnsgo.CodeProvider
		if response.StatusCode == 401 || response.StatusCode == 403 {
			code = dnsgo.CodeAuthentication
		} else if response.StatusCode == 429 {
			code = dnsgo.CodeRateLimited
		}
		if ambiguousWriteResponse(http.MethodPost, response.StatusCode) {
			code = dnsgo.CodeResultUnknown
		}
		return &dnsgo.Error{Provider: w.Kind(), Operation: action, Code: code,
			VendorCode: strconv.Itoa(envelope.Result), Message: envelope.Msg}
	}
	if output != nil && len(envelope.Data) > 0 && string(envelope.Data) != "null" {
		if err := json.Unmarshal(envelope.Data, output); err != nil {
			return &dnsgo.Error{Provider: w.Kind(), Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}

func (w *west) domain(zone string) (string, error) {
	if zone == "" {
		zone = w.config.Domain
	}
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if zone == "" {
		return "", &dnsgo.Error{Provider: w.Kind(), Operation: "domain", Code: dnsgo.CodeInvalidInput, Message: "domain is required"}
	}
	return zone, nil
}

func (w *west) Check(ctx context.Context) error {
	_, err := w.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (w *west) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	page, size := query.Page, query.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	params := url.Values{"page": {strconv.Itoa(page)}, "limit": {strconv.Itoa(size)}}
	if query.Keyword != "" {
		params.Set("domain", query.Keyword)
	}
	var result struct {
		Total int `json:"total"`
		Items []struct {
			Domain string `json:"domain"`
		} `json:"items"`
	}
	if err := w.request(ctx, "getdomains", params, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(result.Items))
	for _, row := range result.Items {
		zones = append(zones, dnsgo.Zone{ID: row.Domain, Name: row.Domain})
	}
	return dnsgo.Page[dnsgo.Zone]{Total: result.Total, Items: zones}, nil
}

func (w *west) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	domain, err := w.domain(zone)
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
	params := url.Values{"domain": {domain}, "pageno": {strconv.Itoa(page)}, "limit": {strconv.Itoa(size)}}
	for key, value := range map[string]string{"type": query.Type, "line": query.Line, "value": query.Value} {
		if value != "" {
			params.Set(key, value)
		}
	}
	if query.Name != "" {
		params.Set("host", query.Name)
	} else if query.Keyword != "" {
		params.Set("host", query.Keyword)
	}
	var result struct {
		Total int          `json:"total"`
		Items []westRecord `json:"items"`
	}
	if err := w.request(ctx, "getdnsrecord", params, &result); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	records := make([]dnsgo.Record, 0, len(result.Items))
	for _, row := range result.Items {
		enabled := row.Pause != 1
		record := dnsgo.Record{ID: row.ID.String(), ZoneID: domain, Name: row.Name, Type: row.Type, Value: row.Value,
			Line: row.Line, TTL: row.TTL, Priority: row.Level, Enabled: &enabled}
		if query.Enabled != nil && *query.Enabled != enabled {
			continue
		}
		records = append(records, record)
	}
	return dnsgo.Page[dnsgo.Record]{Total: result.Total, Items: records}, nil
}

func (w *west) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	seen := 0
	for page := 1; page <= 10000; page++ {
		result, err := w.ListRecords(ctx, zone, dnsgo.RecordQuery{Page: page, PageSize: 100})
		if err != nil {
			return dnsgo.Record{}, err
		}
		for _, row := range result.Items {
			if row.ID == id {
				return row, nil
			}
		}
		seen += len(result.Items)
		if !morePages(result.Total, seen, len(result.Items), 100) {
			break
		}
		if page == 10000 {
			return dnsgo.Record{}, &dnsgo.Error{Provider: w.Kind(), Operation: "get_record", Code: dnsgo.CodeResultUnknown,
				Message: "record listing exceeded the page limit"}
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: w.Kind(), Operation: "get_record", Code: dnsgo.CodeNotFound}
}

func (w *west) recordParams(domain string, record dnsgo.Record, create bool) url.Values {
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	priority := uint16(1)
	if record.Priority != nil {
		priority = *record.Priority
	}
	line := record.Line
	if line == "" || line == "default" {
		line = "0"
	}
	params := url.Values{"domain": {domain}, "type": {record.Type}, "value": {record.Value},
		"level": {strconv.Itoa(int(priority))}, "ttl": {strconv.Itoa(ttl)}, "line": {line}}
	if create {
		params.Set("host", record.Name)
	} else {
		params.Set("id", record.ID)
	}
	return params
}

func (w *west) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(w.Kind(), w.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	domain, err := w.domain(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var result struct {
		ID json.Number `json:"id"`
	}
	if err := w.request(ctx, "adddnsrecord", w.recordParams(domain, record, true), &result); err != nil {
		return dnsgo.Record{}, err
	}
	record.ID, record.ZoneID = result.ID.String(), domain
	return applyRequestedStatus(ctx, w, domain, record, record.Enabled, nil)
}

func (w *west) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(w.Kind(), w.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	domain, err := w.domain(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: w.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	current, err := w.GetRecord(ctx, domain, record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if record.Name != "" && record.Name != current.Name {
		return dnsgo.Record{}, dnsgo.Unsupported(w.Kind(), "rename_record")
	}
	if err := w.request(ctx, "moddnsrecord", w.recordParams(domain, record, false), nil); err != nil {
		return dnsgo.Record{}, err
	}
	record.Name, record.ZoneID = current.Name, domain
	return applyRequestedStatus(ctx, w, domain, record, record.Enabled, current.Enabled)
}

func (w *west) DeleteRecord(ctx context.Context, zone, id string) error {
	domain, err := w.domain(zone)
	if err != nil {
		return err
	}
	if id == "" {
		return &dnsgo.Error{Provider: w.Kind(), Operation: "delete_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	return w.request(ctx, "deldnsrecord", url.Values{"domain": {domain}, "id": {id}}, nil)
}

func (w *west) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	domain, err := w.domain(zone)
	if err != nil {
		return err
	}
	value := "1"
	if enabled {
		value = "0"
	}
	return w.request(ctx, "pause", url.Values{"domain": {domain}, "id": {id}, "val": {value}}, nil)
}

func (w *west) RecordLines(context.Context, string) ([]dnsgo.RecordLine, error) {
	return []dnsgo.RecordLine{{Code: "", Name: "默认"}, {Code: "LTEL", Name: "电信"}, {Code: "LCNC", Name: "联通"},
		{Code: "LMOB", Name: "移动"}, {Code: "LEDU", Name: "教育网"}, {Code: "LSEO", Name: "搜索引擎"},
		{Code: "LFOR", Name: "境外"}}, nil
}

var _ dnsgo.Provider = (*west)(nil)
