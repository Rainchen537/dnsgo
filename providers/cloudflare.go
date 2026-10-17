package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/rainchen537/dnsgo"
)

type cloudflare struct {
	dnsgo.Base
	config  dnsgo.Config
	http    *http.Client
	base    string
	token   string
	email   string
	keyAuth bool
}

type cloudflareRecord struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Type       string          `json:"type"`
	Content    string          `json:"content"`
	TTL        int             `json:"ttl"`
	Proxied    bool            `json:"proxied"`
	Comment    string          `json:"comment"`
	Priority   *uint16         `json:"priority"`
	ModifiedOn string          `json:"modified_on"`
	Data       json.RawMessage `json:"data"`
}

func init() { register("cloudflare", newCloudflare) }

func newCloudflare(config dnsgo.Config) (dnsgo.Provider, error) {
	token := strings.TrimSpace(config.Credentials["apikey"])
	if token == "" {
		token = strings.TrimSpace(config.Credentials["token"])
	}
	if token == "" {
		return nil, &dnsgo.Error{Provider: "cloudflare", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "API token or key is required"}
	}
	keyAuth := config.Credentials["auth"] == "0"
	if keyAuth && strings.TrimSpace(config.Credentials["email"]) == "" {
		return nil, &dnsgo.Error{Provider: "cloudflare", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "email is required for global API key authentication"}
	}
	base := strings.TrimRight(config.Endpoint, "/")
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	return &cloudflare{
		Base: dnsgo.Base{ProviderKind: "cloudflare", Features: dnsgo.Capabilities{
			RecordTypes: []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT", "URI"},
			MinTTL:      60, Remarks: true, Status: true, CreateZone: true, Lines: true, Sort: true,
		}},
		config: config, http: client(config), base: base, token: token,
		email: config.Credentials["email"], keyAuth: keyAuth,
	}, nil
}

func (c *cloudflare) request(ctx context.Context, method, path string, params url.Values, input any, output any, info *struct{ TotalCount, TotalPages int }) error {
	endpoint := c.base + path
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return &dnsgo.Error{Provider: c.Kind(), Operation: method, Code: dnsgo.CodeInvalidInput, Cause: err}
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return &dnsgo.Error{Provider: c.Kind(), Operation: method, Code: dnsgo.CodeInvalidInput, Cause: err}
	}
	if c.keyAuth {
		req.Header.Set("X-Auth-Email", c.email)
		req.Header.Set("X-Auth-Key", c.token)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		code := dnsgo.CodeResultUnknown
		if method == http.MethodGet {
			code = dnsgo.CodeTransport
		}
		return &dnsgo.Error{Provider: c.Kind(), Operation: method, Code: code, Cause: err}
	}
	defer response.Body.Close()
	var envelope struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		ResultInfo struct {
			TotalCount int `json:"total_count"`
			TotalPages int `json:"total_pages"`
		} `json:"result_info"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&envelope); err != nil {
		return &dnsgo.Error{Provider: c.Kind(), Operation: method, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response", Cause: err}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.Success {
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
		e := &dnsgo.Error{Provider: c.Kind(), Operation: method, Code: code}
		if len(envelope.Errors) > 0 {
			e.VendorCode = strconv.Itoa(envelope.Errors[0].Code)
			e.Message = envelope.Errors[0].Message
		}
		return e
	}
	if info != nil {
		info.TotalCount = envelope.ResultInfo.TotalCount
		info.TotalPages = envelope.ResultInfo.TotalPages
	}
	if output != nil {
		if err := json.Unmarshal(envelope.Result, output); err != nil {
			return &dnsgo.Error{Provider: c.Kind(), Operation: method, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result", Cause: err}
		}
	}
	return nil
}

func (c *cloudflare) Check(ctx context.Context) error {
	_, err := c.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (c *cloudflare) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	params := pageParams(query.Page, query.PageSize)
	if query.Keyword != "" {
		params.Set("name", query.Keyword)
	}
	var rows []struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Status      string   `json:"status"`
		NameServers []string `json:"name_servers"`
	}
	var info struct{ TotalCount, TotalPages int }
	if err := c.request(ctx, http.MethodGet, "/zones", params, nil, &rows, &info); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	page := dnsgo.Page[dnsgo.Zone]{Total: info.TotalCount, Items: make([]dnsgo.Zone, 0, len(rows))}
	for _, row := range rows {
		page.Items = append(page.Items, dnsgo.Zone{ID: row.ID, Name: row.Name, Status: row.Status, NameServers: row.NameServers})
	}
	return page, nil
}

func (c *cloudflare) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	accountID := strings.TrimSpace(c.config.Credentials["account_id"])
	if accountID == "" {
		return dnsgo.Zone{}, &dnsgo.Error{Provider: c.Kind(), Operation: "create_zone", Code: dnsgo.CodeInvalidInput, Message: "account_id is required"}
	}
	var row struct{ ID, Name, Status string }
	input := map[string]any{"name": strings.TrimSuffix(name, "."), "account": map[string]string{"id": accountID}, "type": "full"}
	if err := c.request(ctx, http.MethodPost, "/zones", nil, input, &row, nil); err != nil {
		return dnsgo.Zone{}, err
	}
	return dnsgo.Zone{ID: row.ID, Name: row.Name, Status: row.Status}, nil
}

func pageParams(page, size int) url.Values {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(size)}}
}

func (c *cloudflare) zoneID(zone string) string {
	if zone != "" {
		return zone
	}
	return c.config.DomainID
}

func (c *cloudflare) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	zone = c.zoneID(zone)
	params := pageParams(query.Page, query.PageSize)
	var namedName string
	if query.Keyword != "" {
		params.Set("search", query.Keyword)
	}
	if query.Type != "" {
		params.Set("type", query.Type)
	}
	if query.Name != "" {
		name, err := c.fqdn(ctx, zone, query.Name)
		if err != nil {
			return dnsgo.Page[dnsgo.Record]{}, err
		}
		namedName = name
	}
	if query.Line == "1" {
		params.Set("proxied", "true")
	}
	if query.Line == "0" {
		params.Set("proxied", "false")
	}
	allowedSort := map[string]string{"Name": "name", "Type": "type", "LineName": "proxied", "Value": "content"}
	if order := allowedSort[query.SortField]; order != "" {
		params.Set("order", order)
		if query.SortDesc {
			params.Set("direction", "desc")
		} else {
			params.Set("direction", "asc")
		}
	}
	if namedName != "" {
		return c.listNamedRecords(ctx, zone, query, params, namedName)
	}
	if query.Enabled != nil || query.Value != "" {
		return c.listFilteredRecords(ctx, zone, query, params)
	}
	var rows []cloudflareRecord
	var info struct{ TotalCount, TotalPages int }
	path := "/zones/" + url.PathEscape(zone) + "/dns_records"
	if err := c.request(ctx, http.MethodGet, path, params, nil, &rows, &info); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	page := dnsgo.Page[dnsgo.Record]{Total: info.TotalCount, Items: make([]dnsgo.Record, 0, len(rows))}
	for _, row := range rows {
		record := c.record(row)
		record.ZoneID = zone
		if query.Value != "" && record.Value != query.Value {
			continue
		}
		if query.Enabled != nil && (record.Enabled == nil || *record.Enabled != *query.Enabled) {
			continue
		}
		page.Items = append(page.Items, record)
	}
	return page, nil
}

func (c *cloudflare) listFilteredRecords(ctx context.Context, zone string, query dnsgo.RecordQuery, params url.Values) (dnsgo.Page[dnsgo.Record], error) {
	path := "/zones/" + url.PathEscape(zone) + "/dns_records"
	items := make([]dnsgo.Record, 0)
	for page := 1; page <= 100; page++ {
		pageParams := make(url.Values, len(params))
		for key, values := range params {
			pageParams[key] = append([]string(nil), values...)
		}
		pageParams.Set("page", strconv.Itoa(page))
		pageParams.Set("per_page", "100")
		var rows []cloudflareRecord
		var info struct{ TotalCount, TotalPages int }
		if err := c.request(ctx, http.MethodGet, path, pageParams, nil, &rows, &info); err != nil {
			return dnsgo.Page[dnsgo.Record]{}, err
		}
		for _, row := range rows {
			record := c.record(row)
			record.ZoneID = zone
			if query.Value != "" && record.Value != query.Value ||
				query.Enabled != nil && (record.Enabled == nil || *record.Enabled != *query.Enabled) {
				continue
			}
			items = append(items, record)
		}
		if len(rows) < 100 || info.TotalPages > 0 && page >= info.TotalPages {
			break
		}
		if page == 100 {
			return dnsgo.Page[dnsgo.Record]{}, &dnsgo.Error{Provider: c.Kind(), Operation: "list_records",
				Code: dnsgo.CodeResultUnknown, Message: "filtered record query exceeded 100 pages"}
		}
	}
	return pagedRecords(items, query.Page, query.PageSize), nil
}

func pagedRecords(items []dnsgo.Record, page, pageSize int) dnsgo.Page[dnsgo.Record] {
	total := len(items)
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	start, _ := offsetPage(page, pageSize)
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return dnsgo.Page[dnsgo.Record]{Total: total, Items: items[start:end]}
}

func (c *cloudflare) listNamedRecords(ctx context.Context, zone string, query dnsgo.RecordQuery, params url.Values, name string) (dnsgo.Page[dnsgo.Record], error) {
	apex, err := c.fqdn(ctx, zone, "@")
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	names := []string{name, c.pausedName(name, apex)}
	if query.Enabled != nil {
		if *query.Enabled {
			names = names[:1]
		} else {
			names = names[1:]
		}
	}
	path := "/zones/" + url.PathEscape(zone) + "/dns_records"
	items := make([]dnsgo.Record, 0)
	for _, candidate := range names {
		for page := 1; page <= 100; page++ {
			pageParams := make(url.Values, len(params))
			for key, values := range params {
				pageParams[key] = append([]string(nil), values...)
			}
			pageParams.Set("name", candidate)
			pageParams.Set("page", strconv.Itoa(page))
			pageParams.Set("per_page", "100")
			var rows []cloudflareRecord
			var info struct{ TotalCount, TotalPages int }
			if err := c.request(ctx, http.MethodGet, path, pageParams, nil, &rows, &info); err != nil {
				return dnsgo.Page[dnsgo.Record]{}, err
			}
			for _, row := range rows {
				record := c.record(row)
				record.ZoneID = zone
				if query.Value != "" && record.Value != query.Value ||
					query.Enabled != nil && (record.Enabled == nil || *record.Enabled != *query.Enabled) {
					continue
				}
				items = append(items, record)
			}
			if len(rows) < 100 || info.TotalPages > 0 && page >= info.TotalPages {
				break
			}
			if page == 100 {
				return dnsgo.Page[dnsgo.Record]{}, &dnsgo.Error{Provider: c.Kind(), Operation: "list_records",
					Code: dnsgo.CodeResultUnknown, Message: "named record query exceeded 100 pages"}
			}
		}
	}
	if query.SortField != "" {
		sort.SliceStable(items, func(i, j int) bool {
			left, right := "", ""
			switch query.SortField {
			case "Name":
				left, right = items[i].Name, items[j].Name
			case "Type":
				left, right = items[i].Type, items[j].Type
			case "LineName":
				left, right = items[i].Line, items[j].Line
			case "Value":
				left, right = items[i].Value, items[j].Value
			case "UpdateTime":
				left, right = items[i].ModifiedAt, items[j].ModifiedAt
			}
			if query.SortDesc {
				return left > right
			}
			return left < right
		})
	}
	return pagedRecords(items, query.Page, query.PageSize), nil
}

func (c *cloudflare) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	var row cloudflareRecord
	path := "/zones/" + url.PathEscape(c.zoneID(zone)) + "/dns_records/" + url.PathEscape(id)
	if err := c.request(ctx, http.MethodGet, path, nil, nil, &row, nil); err != nil {
		return dnsgo.Record{}, err
	}
	record := c.record(row)
	record.ZoneID = c.zoneID(zone)
	return record, nil
}

func (c *cloudflare) record(row cloudflareRecord) dnsgo.Record {
	name := strings.TrimSuffix(row.Name, ".")
	enabled := true
	if strings.HasPrefix(name, "__root___pause.") {
		name = strings.TrimPrefix(name, "__root___pause.")
		enabled = false
	} else {
		parts := strings.SplitN(name, ".", 2)
		if len(parts) == 2 && strings.HasSuffix(parts[0], "_pause") {
			name = strings.TrimSuffix(parts[0], "_pause") + "." + parts[1]
			enabled = false
		}
	}
	proxied := row.Proxied
	line := "0"
	if proxied {
		line = "1"
	}
	r := dnsgo.Record{ID: row.ID, ZoneID: c.config.DomainID, Name: name, Type: row.Type, Value: row.Content,
		TTL: row.TTL, Priority: row.Priority, Proxied: &proxied, Enabled: &enabled, Line: line,
		Remark: row.Comment, ModifiedAt: row.ModifiedOn, Extra: map[string]any{"raw_name": row.Name}}
	if row.Type == "CAA" && r.Value == "" && len(row.Data) > 0 {
		var data struct {
			Flags int    `json:"flags"`
			Tag   string `json:"tag"`
			Value string `json:"value"`
		}
		if json.Unmarshal(row.Data, &data) == nil && data.Tag != "" {
			r.Value = fmt.Sprintf("%d %s %s", data.Flags, data.Tag, data.Value)
		}
	}
	if row.Type == "SRV" {
		fields := strings.Fields(r.Value)
		if len(fields) == 4 && r.Priority == nil {
			if parsed, err := strconv.ParseUint(fields[0], 10, 16); err == nil {
				priority := uint16(parsed)
				r.Priority = &priority
			}
		}
		if len(fields) == 3 && row.Priority != nil {
			r.Value = fmt.Sprintf("%d %s", *row.Priority, r.Value)
		} else if len(fields) == 0 && len(row.Data) > 0 {
			var data struct {
				Priority int    `json:"priority"`
				Weight   int    `json:"weight"`
				Port     int    `json:"port"`
				Target   string `json:"target"`
			}
			if json.Unmarshal(row.Data, &data) == nil && data.Target != "" {
				r.Value = fmt.Sprintf("%d %d %d %s", data.Priority, data.Weight, data.Port, data.Target)
				if data.Priority >= 0 && data.Priority <= 65535 {
					priority := uint16(data.Priority)
					r.Priority = &priority
				}
			}
		}
	}
	return r
}

func (c *cloudflare) fqdn(ctx context.Context, zone, name string) (string, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	domain := strings.TrimSuffix(c.config.Domain, ".")
	if domain == "" {
		if c.zoneID(zone) == "" {
			return "", &dnsgo.Error{Provider: c.Kind(), Operation: "record_name", Code: dnsgo.CodeInvalidInput,
				Message: "zone ID is required when domain name is not configured"}
		}
		var detail struct {
			Name string `json:"name"`
		}
		if err := c.request(ctx, http.MethodGet, "/zones/"+url.PathEscape(c.zoneID(zone)), nil, nil, &detail, nil); err != nil {
			return "", err
		}
		domain = strings.TrimSuffix(detail.Name, ".")
		if domain == "" {
			return "", &dnsgo.Error{Provider: c.Kind(), Operation: "record_name", Code: dnsgo.CodeResultUnknown,
				Message: "Cloudflare zone response has no name"}
		}
	}
	if name == "@" {
		return domain, nil
	}
	if domain != "" && !strings.EqualFold(name, domain) && !strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(domain)) {
		return name + "." + domain, nil
	}
	return name, nil
}

func (c *cloudflare) payload(ctx context.Context, zone string, record dnsgo.Record) (map[string]any, error) {
	proxied := record.Line == "1"
	if record.Proxied != nil {
		proxied = *record.Proxied
	}
	value := record.Value
	if value == "" && len(record.Values) == 1 {
		value = record.Values[0]
	}
	name, err := c.fqdn(ctx, zone, record.Name)
	if err != nil {
		return nil, err
	}
	if record.Enabled != nil && !*record.Enabled {
		apex, err := c.fqdn(ctx, zone, "@")
		if err != nil {
			return nil, err
		}
		name = c.pausedName(name, apex)
	}
	input := map[string]any{"name": name, "type": record.Type, "content": value,
		"ttl": record.TTL, "proxied": proxied, "comment": record.Remark}
	if record.Priority != nil {
		input["priority"] = *record.Priority
	}
	if record.Type == "CAA" || record.Type == "SRV" {
		data, err := cloudflareStructuredValue(record.Type, value)
		if err != nil {
			return nil, err
		}
		delete(input, "content")
		input["data"] = data
	}
	return input, nil
}

func (c *cloudflare) pausedName(name, apex string) string {
	name = strings.TrimSuffix(name, ".")
	if strings.HasPrefix(name, "__root___pause.") {
		return name
	}
	if strings.EqualFold(name, strings.TrimSuffix(apex, ".")) {
		return "__root___pause." + name
	}
	parts := strings.SplitN(name, ".", 2)
	if !strings.HasSuffix(parts[0], "_pause") {
		parts[0] += "_pause"
	}
	return strings.Join(parts, ".")
}

func cloudflareStructuredValue(kind, value string) (map[string]any, error) {
	fields := strings.Fields(value)
	if kind == "CAA" && len(fields) >= 3 {
		flags, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, err
		}
		return map[string]any{"flags": flags, "tag": fields[1], "value": strings.Trim(strings.Join(fields[2:], " "), "\"")}, nil
	}
	if kind == "SRV" && (len(fields) == 3 || len(fields) == 4) {
		i := 0
		data := map[string]any{}
		if len(fields) == 4 {
			priority, err := strconv.Atoi(fields[0])
			if err != nil {
				return nil, err
			}
			data["priority"] = priority
			i = 1
		}
		weight, err := strconv.Atoi(fields[i])
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(fields[i+1])
		if err != nil {
			return nil, err
		}
		data["weight"] = weight
		data["port"] = port
		data["target"] = fields[i+2]
		return data, nil
	}
	return nil, fmt.Errorf("invalid %s value", kind)
}

func (c *cloudflare) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(c.Kind(), c.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	input, err := c.payload(ctx, zone, record)
	if err != nil {
		return dnsgo.Record{}, &dnsgo.Error{Provider: c.Kind(), Operation: "create_record", Code: dnsgo.CodeInvalidInput, Cause: err}
	}
	var row cloudflareRecord
	path := "/zones/" + url.PathEscape(c.zoneID(zone)) + "/dns_records"
	if err := c.request(ctx, http.MethodPost, path, nil, input, &row, nil); err != nil {
		return dnsgo.Record{}, err
	}
	created := c.record(row)
	created.ZoneID = c.zoneID(zone)
	return created, nil
}

func (c *cloudflare) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(c.Kind(), c.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: c.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	input, err := c.payload(ctx, zone, record)
	if err != nil {
		return dnsgo.Record{}, &dnsgo.Error{Provider: c.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Cause: err}
	}
	var row cloudflareRecord
	path := "/zones/" + url.PathEscape(c.zoneID(zone)) + "/dns_records/" + url.PathEscape(record.ID)
	if err := c.request(ctx, http.MethodPatch, path, nil, input, &row, nil); err != nil {
		return dnsgo.Record{}, err
	}
	updated := c.record(row)
	updated.ZoneID = c.zoneID(zone)
	return updated, nil
}

func (c *cloudflare) DeleteRecord(ctx context.Context, zone, id string) error {
	path := "/zones/" + url.PathEscape(c.zoneID(zone)) + "/dns_records/" + url.PathEscape(id)
	return c.request(ctx, http.MethodDelete, path, nil, nil, nil, nil)
}

func (c *cloudflare) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	record, err := c.GetRecord(ctx, zone, id)
	if err != nil {
		return err
	}
	if record.Enabled != nil && *record.Enabled == enabled {
		return nil
	}
	record.Enabled = &enabled
	_, err = c.UpdateRecord(ctx, zone, record)
	return err
}

func (c *cloudflare) RecordLines(context.Context, string) ([]dnsgo.RecordLine, error) {
	return []dnsgo.RecordLine{{Code: "0", Name: "仅 DNS"}, {Code: "1", Name: "已代理"}}, nil
}
