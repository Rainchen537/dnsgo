package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rainchen537/dnsgo"
)

type spaceship struct {
	dnsgo.Base
	config dnsgo.Config
	http   *http.Client
	base   string
	key    string
	secret string
}

func init() { register("spaceship", newSpaceship) }

func newSpaceship(config dnsgo.Config) (dnsgo.Provider, error) {
	key, secret := config.Credentials["apikey"], config.Credentials["apisecret"]
	if key == "" || secret == "" {
		return nil, &dnsgo.Error{Provider: "spaceship", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "apikey and apisecret are required"}
	}
	base := strings.TrimRight(config.Endpoint, "/")
	if base == "" {
		base = "https://spaceship.dev/api/v1"
	}
	return &spaceship{Base: dnsgo.Base{ProviderKind: "spaceship", Features: dnsgo.Capabilities{
		RecordTypes: []string{"A", "AAAA", "MX", "TXT", "CNAME", "ALIAS", "NS", "PTR", "CAA"}}},
		config: config, http: client(config), base: base, key: key, secret: secret}, nil
}

func (s *spaceship) request(ctx context.Context, method, path string, query url.Values, input, output any) error {
	endpoint := s.base + path
	if len(query) != 0 {
		endpoint += "?" + query.Encode()
	}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return &dnsgo.Error{Provider: s.Kind(), Operation: method, Code: dnsgo.CodeInvalidInput, Cause: err}
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return &dnsgo.Error{Provider: s.Kind(), Operation: method, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	req.Header.Set("X-API-Key", s.key)
	req.Header.Set("X-API-Secret", s.secret)
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := s.http.Do(req)
	if err != nil {
		code := dnsgo.CodeResultUnknown
		if method == http.MethodGet {
			code = dnsgo.CodeTransport
		}
		return &dnsgo.Error{Provider: s.Kind(), Operation: method, Code: code, Message: "request failed"}
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
		var detail struct {
			Detail string `json:"detail"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&detail)
		return &dnsgo.Error{Provider: s.Kind(), Operation: method, Code: code, Message: detail.Detail}
	}
	if output != nil && response.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(output); err != nil {
			return &dnsgo.Error{Provider: s.Kind(), Operation: method, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}

func (s *spaceship) domain(zone string) (string, error) {
	if zone == "" {
		zone = s.config.Domain
	}
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if zone == "" {
		return "", &dnsgo.Error{Provider: s.Kind(), Operation: "domain", Code: dnsgo.CodeInvalidInput, Message: "domain is required"}
	}
	return zone, nil
}

func (s *spaceship) Check(ctx context.Context) error {
	_, err := s.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (s *spaceship) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	page, size := query.Page, query.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	var result struct {
		Total int `json:"total"`
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	params := url.Values{"take": {strconv.Itoa(size)}, "skip": {strconv.Itoa((page - 1) * size)}}
	if err := s.request(ctx, http.MethodGet, "/domains", params, nil, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(result.Items))
	for _, row := range result.Items {
		if query.Keyword == "" || strings.Contains(strings.ToLower(row.Name), strings.ToLower(query.Keyword)) {
			zones = append(zones, dnsgo.Zone{ID: row.Name, Name: row.Name})
		}
	}
	return dnsgo.Page[dnsgo.Zone]{Total: result.Total, Items: zones}, nil
}

type spaceshipItem struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	TTL        int    `json:"ttl,omitempty"`
	Address    string `json:"address,omitempty"`
	Exchange   string `json:"exchange,omitempty"`
	Preference int    `json:"preference,omitempty"`
	CNAME      string `json:"cname,omitempty"`
	Value      string `json:"value,omitempty"`
	Pointer    string `json:"pointer,omitempty"`
	NameServer string `json:"nameserver,omitempty"`
	Flag       int    `json:"flag,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Priority   int    `json:"priority,omitempty"`
	Weight     int    `json:"weight,omitempty"`
	Port       int    `json:"port,omitempty"`
	Target     string `json:"target,omitempty"`
	AliasName  string `json:"aliasName,omitempty"`
}

type spaceshipIdentity struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Priority int    `json:"priority"`
}

func spaceshipID(record dnsgo.Record) string {
	priority := 0
	if record.Priority != nil {
		priority = int(*record.Priority)
	}
	encoded, _ := json.Marshal(spaceshipIdentity{Name: record.Name, Type: record.Type, Value: record.Value, Priority: priority})
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func spaceshipFromItem(domain string, item spaceshipItem) dnsgo.Record {
	value := item.Address
	var priority *uint16
	switch item.Type {
	case "MX":
		value = item.Exchange
		v := uint16(item.Preference)
		priority = &v
	case "CNAME":
		value = item.CNAME
	case "TXT":
		value = item.Value
	case "PTR":
		value = item.Pointer
	case "NS":
		value = item.NameServer
	case "CAA":
		value = strconv.Itoa(item.Flag) + " " + item.Tag + " " + item.Value
	case "SRV":
		value = strconv.Itoa(item.Priority) + " " + strconv.Itoa(item.Weight) + " " + strconv.Itoa(item.Port) + " " + item.Target
	case "ALIAS":
		value = item.AliasName
	}
	enabled := true
	record := dnsgo.Record{ZoneID: domain, Name: item.Name, Type: item.Type, Value: value, TTL: item.TTL,
		Priority: priority, Line: "default", Enabled: &enabled}
	record.ID = spaceshipID(record)
	return record
}

func (s *spaceship) listRecordPage(ctx context.Context, domain string, skip, take int) ([]spaceshipItem, int, error) {
	var result struct {
		Total int             `json:"total"`
		Items []spaceshipItem `json:"items"`
	}
	params := url.Values{"take": {strconv.Itoa(take)}, "skip": {strconv.Itoa(skip)}}
	err := s.request(ctx, http.MethodGet, "/dns/records/"+url.PathEscape(domain), params, nil, &result)
	return result.Items, result.Total, err
}

func (s *spaceship) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	domain, err := s.domain(zone)
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
	filter := query.Name != "" || query.Type != "" || query.Value != "" || query.Keyword != "" || query.Line != "" || query.Enabled != nil
	if !filter {
		if size > 500 {
			size = 500 // Spaceship API take limit.
		}
		items, total, err := s.listRecordPage(ctx, domain, (page-1)*size, size)
		if err != nil {
			return dnsgo.Page[dnsgo.Record]{}, err
		}
		rows := make([]dnsgo.Record, 0, len(items))
		for _, item := range items {
			rows = append(rows, spaceshipFromItem(domain, item))
		}
		return dnsgo.Page[dnsgo.Record]{Total: total, Items: rows}, nil
	}
	matched := []dnsgo.Record{}
	for skip := 0; ; {
		items, total, err := s.listRecordPage(ctx, domain, skip, 100)
		if err != nil {
			return dnsgo.Page[dnsgo.Record]{}, err
		}
		for _, item := range items {
			record := spaceshipFromItem(domain, item)
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
		skip += len(items)
		if len(items) == 0 || skip >= total {
			break
		}
	}
	total := len(matched)
	start, _ := offsetPage(page, size)
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	return dnsgo.Page[dnsgo.Record]{Total: total, Items: matched[start:end]}, nil
}

func (s *spaceship) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return dnsgo.Record{}, &dnsgo.Error{Provider: s.Kind(), Operation: "get_record", Code: dnsgo.CodeInvalidInput, Message: "invalid record ID"}
	}
	var identity spaceshipIdentity
	if err := json.Unmarshal(decoded, &identity); err != nil || identity.Name == "" || identity.Type == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: s.Kind(), Operation: "get_record", Code: dnsgo.CodeInvalidInput, Message: "invalid record ID"}
	}
	page, err := s.ListRecords(ctx, zone, dnsgo.RecordQuery{Name: identity.Name, Type: identity.Type, Page: 1, PageSize: int(^uint(0) >> 1)})
	if err != nil {
		return dnsgo.Record{}, err
	}
	for _, record := range page.Items {
		if record.ID == id {
			return record, nil
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: s.Kind(), Operation: "get_record", Code: dnsgo.CodeNotFound}
}

func (s *spaceship) recordItem(record dnsgo.Record) (map[string]any, error) {
	if record.Name == "" || record.Type == "" {
		return nil, &dnsgo.Error{Provider: s.Kind(), Operation: "record_item", Code: dnsgo.CodeInvalidInput, Message: "record name and type are required"}
	}
	item := map[string]any{"type": record.Type, "name": record.Name}
	switch record.Type {
	case "MX":
		priority := uint16(1)
		if record.Priority != nil {
			priority = *record.Priority
		}
		item["exchange"], item["preference"] = record.Value, priority
	case "TXT":
		item["value"] = record.Value
	case "CNAME":
		item["cname"] = record.Value
	case "ALIAS":
		item["aliasName"] = record.Value
	case "NS":
		item["nameserver"] = record.Value
	case "PTR":
		item["pointer"] = record.Value
	case "CAA":
		parts := strings.SplitN(record.Value, " ", 3)
		if len(parts) != 3 {
			return nil, &dnsgo.Error{Provider: s.Kind(), Operation: "record_item", Code: dnsgo.CodeInvalidInput, Message: "CAA value must be flag tag value"}
		}
		flag, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, &dnsgo.Error{Provider: s.Kind(), Operation: "record_item", Code: dnsgo.CodeInvalidInput, Message: "invalid CAA flag"}
		}
		item["flag"], item["tag"], item["value"] = flag, parts[1], strings.Trim(parts[2], "\"")
	case "SRV":
		parts := strings.SplitN(record.Value, " ", 4)
		if len(parts) != 4 {
			return nil, &dnsgo.Error{Provider: s.Kind(), Operation: "record_item", Code: dnsgo.CodeInvalidInput, Message: "SRV value must be priority weight port target"}
		}
		for i, key := range []string{"priority", "weight", "port"} {
			n, err := strconv.Atoi(parts[i])
			if err != nil {
				return nil, &dnsgo.Error{Provider: s.Kind(), Operation: "record_item", Code: dnsgo.CodeInvalidInput, Message: "invalid SRV value"}
			}
			item[key] = n
		}
		item["target"] = parts[3]
	default:
		item["address"] = record.Value
	}
	return item, nil
}

func (s *spaceship) putRecord(ctx context.Context, zone string, record dnsgo.Record, force bool) (dnsgo.Record, error) {
	domain, err := s.domain(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	item, err := s.recordItem(record)
	if err != nil {
		return dnsgo.Record{}, err
	}
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	item["ttl"] = ttl
	input := map[string]any{"force": force, "items": []any{item}}
	if err := s.request(ctx, http.MethodPut, "/dns/records/"+url.PathEscape(domain), nil, input, nil); err != nil {
		return dnsgo.Record{}, err
	}
	record.ZoneID = domain
	record.ID = spaceshipID(record)
	return record, nil
}

func (s *spaceship) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(s.Kind(), s.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	return s.putRecord(ctx, zone, record, false)
}

func (s *spaceship) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(s.Kind(), s.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: s.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	return s.putRecord(ctx, zone, record, true)
}

func (s *spaceship) DeleteRecord(ctx context.Context, zone, id string) error {
	domain, err := s.domain(zone)
	if err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return &dnsgo.Error{Provider: s.Kind(), Operation: "delete_record", Code: dnsgo.CodeInvalidInput, Message: "invalid record ID"}
	}
	var identity spaceshipIdentity
	if err := json.Unmarshal(decoded, &identity); err != nil || identity.Name == "" || identity.Type == "" {
		return &dnsgo.Error{Provider: s.Kind(), Operation: "delete_record", Code: dnsgo.CodeInvalidInput, Message: "invalid record ID"}
	}
	priority := uint16(identity.Priority)
	record := dnsgo.Record{Name: identity.Name, Type: identity.Type, Value: identity.Value, Priority: &priority}
	item, err := s.recordItem(record)
	if err != nil {
		return err
	}
	return s.request(ctx, http.MethodDelete, "/dns/records/"+url.PathEscape(domain), nil, []any{item}, nil)
}

func (s *spaceship) RecordLines(context.Context, string) ([]dnsgo.RecordLine, error) {
	return []dnsgo.RecordLine{{Code: "default", Name: "默认"}}, nil
}

var _ dnsgo.Provider = (*spaceship)(nil)
