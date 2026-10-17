package providers

import (
	"bytes"
	"context"
	"encoding/base64"
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

type powerDNS struct {
	dnsgo.Base
	config            dnsgo.Config
	http              *http.Client
	base, key, server string
}

type pdnsValue struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type pdnsRRSet struct {
	Name     string      `json:"name"`
	Type     string      `json:"type"`
	TTL      int         `json:"ttl"`
	Records  []pdnsValue `json:"records"`
	Comments []struct {
		Content string `json:"content"`
		Account string `json:"account"`
	} `json:"comments"`
}

type pdnsZone struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Kind        string      `json:"kind"`
	NameServers []string    `json:"nameservers"`
	RRSets      []pdnsRRSet `json:"rrsets"`
}

func init() { register("powerdns", newPowerDNS) }

func newPowerDNS(config dnsgo.Config) (dnsgo.Provider, error) {
	key := config.Credentials["apikey"]
	if key == "" {
		key = config.Credentials["api_key"]
	}
	base := strings.TrimRight(config.Endpoint, "/")
	if base == "" {
		host := config.Credentials["ip"]
		port := config.Credentials["port"]
		if host == "" {
			return nil, &dnsgo.Error{Provider: "powerdns", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "endpoint or ip is required"}
		}
		if port == "" {
			port = "8081"
		}
		base = "http://" + host + ":" + port + "/api/v1"
	}
	if key == "" {
		return nil, &dnsgo.Error{Provider: "powerdns", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "API key is required"}
	}
	server := config.Credentials["server_id"]
	if server == "" {
		server = "localhost"
	}
	return &powerDNS{Base: dnsgo.Base{ProviderKind: "powerdns", Features: dnsgo.Capabilities{
		RecordTypes: []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT", "TLSA"},
		Remarks:     true, Status: true, CreateZone: true,
	}}, config: config, http: client(config), base: base, key: key, server: server}, nil
}

func (p *powerDNS) request(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return &dnsgo.Error{Provider: p.Kind(), Operation: method, Code: dnsgo.CodeInvalidInput, Cause: err}
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, body)
	if err != nil {
		return &dnsgo.Error{Provider: p.Kind(), Operation: method, Code: dnsgo.CodeInvalidInput, Cause: err}
	}
	req.Header.Set("X-API-Key", p.key)
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := p.http.Do(req)
	if err != nil {
		code := dnsgo.CodeResultUnknown
		if method == http.MethodGet {
			code = dnsgo.CodeTransport
		}
		return &dnsgo.Error{Provider: p.Kind(), Operation: method, Code: code, Cause: err}
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
		return &dnsgo.Error{Provider: p.Kind(), Operation: method, Code: code, Message: response.Status}
	}
	if output != nil {
		if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(output); err != nil {
			return &dnsgo.Error{Provider: p.Kind(), Operation: method, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result", Cause: err}
		}
	}
	return nil
}

func (p *powerDNS) serverPath() string { return "/servers/" + url.PathEscape(p.server) + "/zones" }
func (p *powerDNS) zonePath(zone string) string {
	return p.serverPath() + "/" + url.PathEscape(p.zone(zone))
}
func (p *powerDNS) zone(zone string) string {
	if zone == "" {
		zone = p.config.DomainID
	}
	if zone == "" {
		zone = p.config.Domain
	}
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}
	return zone
}

func (p *powerDNS) Check(ctx context.Context) error {
	_, err := p.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (p *powerDNS) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	var rows []pdnsZone
	if err := p.request(ctx, http.MethodGet, p.serverPath(), nil, &rows); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(rows))
	for _, row := range rows {
		if query.Keyword != "" && !strings.Contains(strings.ToLower(row.Name), strings.ToLower(query.Keyword)) {
			continue
		}
		zones = append(zones, dnsgo.Zone{ID: row.ID, Name: strings.TrimSuffix(row.Name, "."), Status: row.Kind, NameServers: row.NameServers})
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

func offsetPage(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	return (page - 1) * size, size
}

func (p *powerDNS) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	name = strings.TrimSuffix(name, ".") + "."
	var row pdnsZone
	input := map[string]any{"name": name, "kind": "Native", "soa_edit_api": "INCREASE"}
	if err := p.request(ctx, http.MethodPost, p.serverPath(), input, &row); err != nil {
		return dnsgo.Zone{}, err
	}
	return dnsgo.Zone{ID: row.ID, Name: strings.TrimSuffix(row.Name, "."), Status: row.Kind, NameServers: row.NameServers}, nil
}

func (p *powerDNS) readZone(ctx context.Context, zone string) (pdnsZone, error) {
	var row pdnsZone
	err := p.request(ctx, http.MethodGet, p.zonePath(zone), nil, &row)
	return row, err
}

func pdnsID(name, kind, content string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(name + "\x00" + kind + "\x00" + content))
}
func pdnsDecodeID(id string) (string, string, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return "", "", "", err
	}
	parts := strings.SplitN(string(raw), "\x00", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid record ID")
	}
	return parts[0], parts[1], parts[2], nil
}

func (p *powerDNS) toRecord(zone string, set pdnsRRSet, value pdnsValue) dnsgo.Record {
	name := strings.TrimSuffix(set.Name, ".")
	content := value.Content
	var priority *uint16
	if set.Type == "MX" {
		parts := strings.SplitN(content, " ", 2)
		if len(parts) == 2 {
			n, err := strconv.ParseUint(parts[0], 10, 16)
			if err == nil {
				x := uint16(n)
				priority = &x
				content = strings.TrimSuffix(parts[1], ".")
			}
		}
	}
	if set.Type == "TXT" {
		content = strings.Trim(content, "\"")
	}
	if set.Type == "CNAME" || set.Type == "NS" {
		content = strings.TrimSuffix(content, ".")
	}
	enabled := !value.Disabled
	remark := ""
	if len(set.Comments) > 0 {
		remark = set.Comments[0].Content
	}
	values := make([]string, 0, len(set.Records))
	for _, member := range set.Records {
		values = append(values, member.Content)
	}
	return dnsgo.Record{ID: pdnsID(set.Name, set.Type, value.Content), ZoneID: zone, Name: name, Type: set.Type, Value: content, Values: values,
		TTL: set.TTL, Priority: priority, Enabled: &enabled, Remark: remark, Extra: map[string]any{"raw_content": value.Content}}
}

func (p *powerDNS) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	row, err := p.readZone(ctx, zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	records := []dnsgo.Record{}
	wantedName := ""
	if query.Name != "" {
		wantedName = strings.TrimSuffix(p.recordName(zone, query.Name), ".")
	}
	for _, set := range row.RRSets {
		for _, value := range set.Records {
			record := p.toRecord(p.zone(zone), set, value)
			if wantedName != "" && !strings.EqualFold(record.Name, wantedName) {
				continue
			}
			if query.Type != "" && !strings.EqualFold(record.Type, query.Type) {
				continue
			}
			if query.Value != "" && record.Value != query.Value {
				continue
			}
			if query.Line != "" && query.Line != "default" && query.Line != "0" {
				continue
			}
			if query.Enabled != nil && (record.Enabled == nil || *record.Enabled != *query.Enabled) {
				continue
			}
			if query.Keyword != "" && !strings.Contains(strings.ToLower(record.Name+" "+record.Value), strings.ToLower(query.Keyword)) {
				continue
			}
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Name < records[j].Name || records[i].Name == records[j].Name && records[i].Type < records[j].Type
	})
	total := len(records)
	start, size := offsetPage(query.Page, query.PageSize)
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	return dnsgo.Page[dnsgo.Record]{Total: total, Items: records[start:end]}, nil
}

func (p *powerDNS) find(ctx context.Context, zone, id string) (pdnsRRSet, pdnsValue, error) {
	name, kind, content, err := pdnsDecodeID(id)
	if err != nil {
		return pdnsRRSet{}, pdnsValue{}, &dnsgo.Error{Provider: p.Kind(), Operation: "find_record", Code: dnsgo.CodeInvalidInput, Cause: err}
	}
	row, err := p.readZone(ctx, zone)
	if err != nil {
		return pdnsRRSet{}, pdnsValue{}, err
	}
	for _, set := range row.RRSets {
		if set.Name == name && set.Type == kind {
			for _, value := range set.Records {
				if value.Content == content {
					return set, value, nil
				}
			}
		}
	}
	return pdnsRRSet{}, pdnsValue{}, &dnsgo.Error{Provider: p.Kind(), Operation: "find_record", Code: dnsgo.CodeNotFound}
}

func (p *powerDNS) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	set, value, err := p.find(ctx, zone, id)
	if err != nil {
		return dnsgo.Record{}, err
	}
	return p.toRecord(p.zone(zone), set, value), nil
}

func (p *powerDNS) recordName(zone, name string) string {
	zone = p.zone(zone)
	name = strings.TrimSuffix(name, ".")
	if name == "@" || name == strings.TrimSuffix(zone, ".") {
		return zone
	}
	if strings.HasSuffix(name, "."+strings.TrimSuffix(zone, ".")) {
		return name + "."
	}
	return name + "." + zone
}

func pdnsRaw(record dnsgo.Record) string {
	value := record.Value
	if value == "" && len(record.Values) == 1 {
		value = record.Values[0]
	}
	switch record.Type {
	case "TXT":
		if !strings.HasPrefix(value, "\"") {
			value = "\"" + value + "\""
		}
	case "CNAME", "NS":
		if !strings.HasSuffix(value, ".") {
			value += "."
		}
	case "MX":
		if !strings.HasSuffix(value, ".") {
			value += "."
		}
		priority := uint16(1)
		if record.Priority != nil {
			priority = *record.Priority
		}
		value = fmt.Sprintf("%d %s", priority, value)
	}
	return value
}

func pdnsChange(set pdnsRRSet) map[string]any {
	change := map[string]any{"name": set.Name, "type": set.Type, "ttl": set.TTL, "changetype": "REPLACE", "records": set.Records}
	if len(set.Records) == 0 {
		change = map[string]any{"name": set.Name, "type": set.Type, "changetype": "DELETE"}
	}
	if len(set.Records) > 0 {
		if len(set.Comments) > 0 {
			change["comments"] = set.Comments
		} else {
			change["comments"] = []any{}
		}
	}
	return change
}

func (p *powerDNS) write(ctx context.Context, zone string, sets ...pdnsRRSet) error {
	changes := make([]map[string]any, 0, len(sets))
	for _, set := range sets {
		changes = append(changes, pdnsChange(set))
	}
	return p.request(ctx, http.MethodPatch, p.zonePath(zone), map[string]any{"rrsets": changes}, nil)
}

func (p *powerDNS) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(p.Kind(), p.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	row, err := p.readZone(ctx, zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	name := p.recordName(zone, record.Name)
	raw := pdnsRaw(record)
	set := pdnsRRSet{Name: name, Type: record.Type, TTL: record.TTL}
	if set.TTL < 1 {
		set.TTL = 600
	}
	for _, candidate := range row.RRSets {
		if candidate.Name == name && candidate.Type == record.Type {
			set = candidate
			break
		}
	}
	for _, existing := range set.Records {
		if existing.Content == raw {
			return dnsgo.Record{}, &dnsgo.Error{Provider: p.Kind(), Operation: "create_record", Code: dnsgo.CodeConflict, Message: "record already exists"}
		}
	}
	disabled := record.Enabled != nil && !*record.Enabled
	set.Records = append(set.Records, pdnsValue{Content: raw, Disabled: disabled})
	if record.Remark != "" {
		set.Comments = []struct {
			Content string `json:"content"`
			Account string `json:"account"`
		}{{Content: record.Remark}}
	}
	if err := p.write(ctx, zone, set); err != nil {
		return dnsgo.Record{}, err
	}
	return p.GetRecord(ctx, zone, pdnsID(name, record.Type, raw))
}

func (p *powerDNS) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(p.Kind(), p.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	old, value, err := p.find(ctx, zone, record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	newName := p.recordName(zone, record.Name)
	newRaw := pdnsRaw(record)
	oldRaw := value.Content
	newSet := old
	if newName != old.Name || record.Type != old.Type {
		row, err := p.readZone(ctx, zone)
		if err != nil {
			return dnsgo.Record{}, err
		}
		newSet = pdnsRRSet{Name: newName, Type: record.Type, TTL: record.TTL}
		for _, candidate := range row.RRSets {
			if candidate.Name == newName && candidate.Type == record.Type {
				newSet = candidate
				break
			}
		}
	}
	filtered := make([]pdnsValue, 0, len(old.Records))
	for _, member := range old.Records {
		if member.Content != value.Content {
			filtered = append(filtered, member)
		}
	}
	old.Records = filtered
	if record.TTL > 0 {
		newSet.TTL = record.TTL
	}
	if record.Enabled != nil {
		value.Disabled = !*record.Enabled
	}
	value.Content = newRaw
	for _, member := range newSet.Records {
		if member.Content == newRaw && !(old.Name == newName && old.Type == record.Type && member.Content == oldRaw) {
			return dnsgo.Record{}, &dnsgo.Error{Provider: p.Kind(), Operation: "update_record", Code: dnsgo.CodeConflict, Message: "target record already exists"}
		}
	}
	if old.Name == newName && old.Type == record.Type {
		newSet.Records = append(filtered, value)
		newSet.Comments = powerDNSComments(record.Remark)
	} else {
		if len(newSet.Records) > 0 {
			existingRemark := ""
			if len(newSet.Comments) > 0 {
				existingRemark = newSet.Comments[0].Content
			}
			if existingRemark != record.Remark {
				return dnsgo.Record{}, &dnsgo.Error{Provider: p.Kind(), Operation: "update_record", Code: dnsgo.CodeConflict,
					Message: "target RRset has a different shared remark"}
			}
		} else {
			newSet.Comments = powerDNSComments(record.Remark)
		}
		newSet.Records = append(newSet.Records, value)
	}
	sets := []pdnsRRSet{newSet}
	if old.Name != newName || old.Type != record.Type {
		sets = []pdnsRRSet{old, newSet}
	}
	if err := p.write(ctx, zone, sets...); err != nil {
		return dnsgo.Record{}, err
	}
	return p.GetRecord(ctx, zone, pdnsID(newName, record.Type, newRaw))
}

func powerDNSComments(remark string) []struct {
	Content string `json:"content"`
	Account string `json:"account"`
} {
	if remark == "" {
		return nil
	}
	return []struct {
		Content string `json:"content"`
		Account string `json:"account"`
	}{{Content: remark}}
}

func (p *powerDNS) DeleteRecord(ctx context.Context, zone, id string) error {
	set, value, err := p.find(ctx, zone, id)
	if err != nil {
		return err
	}
	filtered := make([]pdnsValue, 0, len(set.Records))
	for _, member := range set.Records {
		if member.Content != value.Content {
			filtered = append(filtered, member)
		}
	}
	set.Records = filtered
	return p.write(ctx, zone, set)
}

// SetRecordRemark changes the comment shared by every member of the RRset.
func (p *powerDNS) SetRecordRemark(ctx context.Context, zone, id, remark string) error {
	set, _, err := p.find(ctx, zone, id)
	if err != nil {
		return err
	}
	set.Comments = powerDNSComments(remark)
	return p.write(ctx, zone, set)
}

func (p *powerDNS) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	set, value, err := p.find(ctx, zone, id)
	if err != nil {
		return err
	}
	for index := range set.Records {
		if set.Records[index].Content == value.Content {
			set.Records[index].Disabled = !enabled
			break
		}
	}
	return p.write(ctx, zone, set)
}

func (p *powerDNS) RecordLines(context.Context, string) ([]dnsgo.RecordLine, error) {
	return []dnsgo.RecordLine{{Code: "default", Name: "默认"}}, nil
}
