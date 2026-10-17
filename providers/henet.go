package providers

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/rainchen537/dnsgo"
)

type heNet struct {
	dnsgo.Base
	config   dnsgo.Config
	http     *http.Client
	base     string
	username string
	password string
	loginMu  sync.Mutex
	mu       sync.Mutex
	cookies  map[string]string
	loggedIn bool
}

var (
	heDomainButtonA = regexp.MustCompile(`(?i)onclick="delete_dom\(this\);"[^>]*name="([^"]+)"[^>]*value="(\d+)"`)
	heDomainButtonB = regexp.MustCompile(`(?i)name="([^"]+)"[^>]*value="(\d+)"[^>]*onclick="delete_dom\(this\);"`)
	heDomainLink    = regexp.MustCompile(`(?i)hosted_dns_zoneid=(\d+)[^"']*["'][^>]*>\s*([^<]+)\s*<`)
	heRow           = regexp.MustCompile(`(?is)<tr class="dns_tr" [^>]*>.*?</tr>`)
	heCell          = regexp.MustCompile(`(?is)<td[^>]*>(.*?)</td>`)
	heScript        = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>`)
	heStyle         = regexp.MustCompile(`(?is)<style\b[^>]*>.*?</style>`)
	heTags          = regexp.MustCompile(`(?s)<[^>]*>`)
	heSpace         = regexp.MustCompile(`\s+`)
	heMessage       = regexp.MustCompile(`(?is)<(?:div|span)[^>]*class="[^"]*(?:error|warn|success|message)[^"]*"[^>]*>(.*?)</(?:div|span)>`)
)

func init() { register("henet", newHENet) }

func newHENet(config dnsgo.Config) (dnsgo.Provider, error) {
	username, password := config.Credentials["username"], config.Credentials["password"]
	if username == "" || password == "" {
		return nil, &dnsgo.Error{Provider: "henet", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "username and password are required"}
	}
	if strings.TrimSpace(config.Domain) == "" {
		return nil, &dnsgo.Error{Provider: "henet", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "domain is required"}
	}
	base := strings.TrimRight(config.Endpoint, "/")
	if base == "" {
		base = "https://dns.he.net"
	}
	return &heNet{Base: dnsgo.Base{ProviderKind: "henet", Features: dnsgo.Capabilities{
		MinTTL: 300,
	}}, config: config, http: client(config), base: base, username: username, password: password,
		cookies: make(map[string]string)}, nil
}

func (h *heNet) requestRaw(ctx context.Context, method, path string, values url.Values) (string, error) {
	endpoint := h.base + "/"
	if path != "" {
		endpoint = h.base + "/" + strings.TrimPrefix(path, "/")
	}
	var body io.Reader
	if method == http.MethodPost && values != nil {
		body = strings.NewReader(values.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return "", &dnsgo.Error{Provider: h.Kind(), Operation: method, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Referer", h.base+"/")
	h.mu.Lock()
	for name, value := range h.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	h.mu.Unlock()
	response, err := h.http.Do(req)
	if err != nil {
		code := dnsgo.CodeResultUnknown
		if method == http.MethodGet {
			code = dnsgo.CodeTransport
		}
		return "", &dnsgo.Error{Provider: h.Kind(), Operation: method, Code: code, Message: "request failed"}
	}
	defer response.Body.Close()
	h.mu.Lock()
	for _, cookie := range response.Cookies() {
		h.cookies[cookie.Name] = cookie.Value
	}
	h.mu.Unlock()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		code := dnsgo.CodeProvider
		if response.StatusCode == 401 || response.StatusCode == 403 {
			code = dnsgo.CodeAuthentication
		}
		if ambiguousWriteResponse(method, response.StatusCode) {
			code = dnsgo.CodeResultUnknown
		}
		return "", &dnsgo.Error{Provider: h.Kind(), Operation: method, Code: code, Message: response.Status}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return "", &dnsgo.Error{Provider: h.Kind(), Operation: method, Code: dnsgo.CodeResultUnknown, Message: "response read failed"}
	}
	return string(data), nil
}

func (h *heNet) login(ctx context.Context) (string, error) {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()
	h.mu.Lock()
	loggedIn := h.loggedIn
	h.mu.Unlock()
	if loggedIn {
		return h.requestRaw(ctx, http.MethodGet, "", nil)
	}
	if _, err := h.requestRaw(ctx, http.MethodGet, "", nil); err != nil {
		return "", err
	}
	page, err := h.requestRaw(ctx, http.MethodPost, "", url.Values{"email": {h.username}, "pass": {h.password}})
	if err != nil {
		return "", err
	}
	if strings.Contains(strings.ToLower(page), "incorrect") || strings.Contains(strings.ToLower(page), "invalid") {
		return "", &dnsgo.Error{Provider: h.Kind(), Operation: "login", Code: dnsgo.CodeAuthentication, Message: heExtractMessage(page)}
	}
	if len(heParseDomains(page)) == 0 && !strings.Contains(page, "hosted_dns_zoneid") {
		return "", &dnsgo.Error{Provider: h.Kind(), Operation: "login", Code: dnsgo.CodeAuthentication, Message: "domain list not found after login"}
	}
	h.mu.Lock()
	h.loggedIn = true
	h.mu.Unlock()
	return page, nil
}

func heExpired(page string) bool {
	return strings.Contains(page, `name="email"`) && strings.Contains(page, `name="pass"`) && !strings.Contains(page, "hosted_dns_zoneid")
}

func (h *heNet) request(ctx context.Context, method, path string, values url.Values) (string, error) {
	if _, err := h.login(ctx); err != nil {
		return "", err
	}
	page, err := h.requestRaw(ctx, method, path, values)
	if err != nil {
		return "", err
	}
	if heExpired(page) {
		h.mu.Lock()
		h.loggedIn = false
		h.cookies = make(map[string]string)
		h.mu.Unlock()
		if _, err := h.login(ctx); err != nil {
			return "", err
		}
		return h.requestRaw(ctx, method, path, values)
	}
	return page, nil
}

func heParseDomains(page string) []dnsgo.Zone {
	seen := map[string]bool{}
	zones := []dnsgo.Zone{}
	for _, pattern := range []*regexp.Regexp{heDomainButtonA, heDomainButtonB} {
		for _, match := range pattern.FindAllStringSubmatch(page, -1) {
			if seen[match[2]] {
				continue
			}
			seen[match[2]] = true
			zones = append(zones, dnsgo.Zone{ID: match[2], Name: strings.TrimSpace(html.UnescapeString(match[1]))})
		}
	}
	for _, match := range heDomainLink.FindAllStringSubmatch(page, -1) {
		if seen[match[1]] {
			continue
		}
		seen[match[1]] = true
		zones = append(zones, dnsgo.Zone{ID: match[1], Name: strings.TrimSpace(html.UnescapeString(match[2]))})
	}
	return zones
}

func heExtractMessage(page string) string {
	if match := heMessage.FindStringSubmatch(page); len(match) == 2 {
		return strings.TrimSpace(html.UnescapeString(heTags.ReplaceAllString(match[1], "")))
	}
	return "operation failed"
}

func (h *heNet) Check(ctx context.Context) error {
	_, err := h.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (h *heNet) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	page, err := h.request(ctx, http.MethodGet, "", nil)
	if err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := []dnsgo.Zone{}
	for _, zone := range heParseDomains(page) {
		if query.Keyword == "" || strings.Contains(strings.ToLower(zone.Name), strings.ToLower(query.Keyword)) {
			zones = append(zones, zone)
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

func (h *heNet) zoneID(ctx context.Context, zone string) (string, error) {
	if zone == "" {
		zone = h.config.DomainID
	}
	if zone != "" {
		return zone, nil
	}
	if h.config.Domain == "" {
		return "", &dnsgo.Error{Provider: h.Kind(), Operation: "zone_id", Code: dnsgo.CodeInvalidInput, Message: "domain or numeric zone ID is required"}
	}
	zones, err := h.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: int(^uint(0) >> 1)})
	if err != nil {
		return "", err
	}
	for _, row := range zones.Items {
		if strings.EqualFold(row.Name, h.config.Domain) {
			return row.ID, nil
		}
	}
	return "", &dnsgo.Error{Provider: h.Kind(), Operation: "zone_id", Code: dnsgo.CodeNotFound}
}

func heCleanCell(cell string) string {
	cell = heScript.ReplaceAllString(cell, "")
	cell = heStyle.ReplaceAllString(cell, "")
	cell = heTags.ReplaceAllString(cell, "")
	cell = html.UnescapeString(cell)
	return heSpace.ReplaceAllString(strings.TrimSpace(cell), " ")
}

func (h *heNet) relativeName(full string) string {
	full = strings.TrimSuffix(full, ".")
	domain := strings.TrimSuffix(h.config.Domain, ".")
	if strings.EqualFold(full, domain) {
		return "@"
	}
	if strings.HasSuffix(strings.ToLower(full), "."+strings.ToLower(domain)) {
		return full[:len(full)-len(domain)-1]
	}
	return full
}

func (h *heNet) fullName(name string) string {
	domain := strings.TrimSuffix(h.config.Domain, ".")
	if name == "@" || name == "" || strings.EqualFold(name, domain) {
		return domain
	}
	if strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(domain)) {
		return name
	}
	return name + "." + domain
}

func (h *heNet) parseRecords(page string, zone string) []dnsgo.Record {
	records := []dnsgo.Record{}
	for _, row := range heRow.FindAllString(page, -1) {
		cells := []string{}
		for _, match := range heCell.FindAllStringSubmatch(row, -1) {
			cell := heCleanCell(match[1])
			if cell != "" {
				cells = append(cells, cell)
			}
		}
		if len(cells) < 7 {
			continue
		}
		ttl, _ := strconv.Atoi(cells[4])
		var priority *uint16
		if value, err := strconv.ParseUint(cells[5], 10, 16); err == nil {
			p := uint16(value)
			priority = &p
		}
		enabled := !strings.Contains(strings.ToLower(row), "disabled")
		value := cells[6]
		if strings.EqualFold(cells[3], "TXT") {
			value = strings.Trim(value, "\"")
		}
		records = append(records, dnsgo.Record{ID: cells[1], ZoneID: zone, Name: h.relativeName(cells[2]),
			Type: strings.ToUpper(cells[3]), Value: value, Line: "default", TTL: ttl, Priority: priority, Enabled: &enabled})
	}
	return records
}

func (h *heNet) allRecords(ctx context.Context, zone string) ([]dnsgo.Record, error) {
	params := url.Values{"hosted_dns_zoneid": {zone}, "menu": {"edit_zone"}, "hosted_dns_editzone": {""}}
	page, err := h.request(ctx, http.MethodGet, "index.cgi?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	return h.parseRecords(page, zone), nil
}

func (h *heNet) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	zone, err := h.zoneID(ctx, zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	rows, err := h.allRecords(ctx, zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	matched := []dnsgo.Record{}
	for _, row := range rows {
		if query.Name != "" && !strings.EqualFold(query.Name, row.Name) || query.Type != "" && !strings.EqualFold(query.Type, row.Type) ||
			query.Value != "" && query.Value != row.Value || query.Keyword != "" && !strings.Contains(strings.ToLower(row.Name), strings.ToLower(query.Keyword)) && !strings.Contains(strings.ToLower(row.Value), strings.ToLower(query.Keyword)) ||
			query.Line != "" && query.Line != "default" && query.Line != "0" || query.Enabled != nil && *query.Enabled != *row.Enabled {
			continue
		}
		matched = append(matched, row)
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

func (h *heNet) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	page, err := h.ListRecords(ctx, zone, dnsgo.RecordQuery{Page: 1, PageSize: int(^uint(0) >> 1)})
	if err != nil {
		return dnsgo.Record{}, err
	}
	for _, record := range page.Items {
		if record.ID == id {
			return record, nil
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: h.Kind(), Operation: "get_record", Code: dnsgo.CodeNotFound}
}

func (h *heNet) recordParams(zone string, record dnsgo.Record, create bool) url.Values {
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	priority := ""
	if record.Type == "MX" {
		p := uint16(1)
		if record.Priority != nil {
			p = *record.Priority
		}
		priority = strconv.Itoa(int(p))
	}
	value := record.Value
	if record.Type == "TXT" {
		value = strings.Trim(value, "\"")
	}
	params := url.Values{"account": {""}, "menu": {"edit_zone"}, "Type": {strings.ToUpper(record.Type)},
		"hosted_dns_zoneid": {zone}, "hosted_dns_recordid": {record.ID}, "hosted_dns_editzone": {"1"},
		"Priority": {priority}, "Name": {h.fullName(record.Name)}, "Content": {value}, "TTL": {strconv.Itoa(ttl)}}
	if create {
		params.Set("hosted_dns_recordid", "")
		params.Set("hosted_dns_editrecord", "Submit")
	} else {
		params.Set("hosted_dns_editrecord", "Update")
	}
	return params
}

func (h *heNet) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(h.Kind(), h.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := h.zoneID(ctx, zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	beforeRows, err := h.allRecords(ctx, zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	before := make(map[string]bool, len(beforeRows))
	for _, row := range beforeRows {
		before[row.ID] = true
	}
	page, err := h.request(ctx, http.MethodPost, "index.cgi", h.recordParams(zone, record, true))
	if err != nil {
		return dnsgo.Record{}, err
	}
	if !strings.Contains(strings.ToLower(page), "successfully added new record") {
		return dnsgo.Record{}, &dnsgo.Error{Provider: h.Kind(), Operation: "create_record", Code: dnsgo.CodeProvider, Message: heExtractMessage(page)}
	}
	for _, created := range h.parseRecords(page, zone) {
		if !before[created.ID] && created.Name == record.Name && created.Type == record.Type && created.Value == record.Value {
			return created, nil
		}
	}
	afterRows, err := h.allRecords(ctx, zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	for _, created := range afterRows {
		if !before[created.ID] && created.Name == record.Name && created.Type == record.Type && created.Value == record.Value {
			return created, nil
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: h.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
		Message: "record was created but its ID could not be confirmed"}
}

func (h *heNet) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(h.Kind(), h.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := h.zoneID(ctx, zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: h.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	page, err := h.request(ctx, http.MethodPost, "index.cgi", h.recordParams(zone, record, false))
	if err != nil {
		return dnsgo.Record{}, err
	}
	if !strings.Contains(strings.ToLower(page), "successfully updated record") {
		return dnsgo.Record{}, &dnsgo.Error{Provider: h.Kind(), Operation: "update_record", Code: dnsgo.CodeProvider, Message: heExtractMessage(page)}
	}
	record.ZoneID = zone
	return record, nil
}

func (h *heNet) DeleteRecord(ctx context.Context, zone, id string) error {
	zone, err := h.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	params := url.Values{"menu": {"edit_zone"}, "hosted_dns_zoneid": {zone}, "hosted_dns_recordid": {id},
		"hosted_dns_editzone": {"1"}, "hosted_dns_delrecord": {"1"}, "hosted_dns_delconfirm": {"delete"}}
	page, err := h.request(ctx, http.MethodPost, "index.cgi", params)
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(page), "successfully removed record") {
		return &dnsgo.Error{Provider: h.Kind(), Operation: "delete_record", Code: dnsgo.CodeProvider, Message: heExtractMessage(page)}
	}
	return nil
}

func (h *heNet) RecordLines(context.Context, string) ([]dnsgo.RecordLine, error) {
	return []dnsgo.RecordLine{{Code: "default", Name: "默认"}}, nil
}

func (h *heNet) MinTTL(context.Context, string) (int, error) { return 300, nil }

var _ dnsgo.Provider = (*heNet)(nil)
