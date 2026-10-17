package providers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type aliyunESA struct {
	dnsgo.Base
	config   dnsgo.Config
	http     *http.Client
	endpoint string
	keyID    string
	secret   string
}

type esaRecord struct {
	ID   json.Number `json:"RecordId"`
	Name string      `json:"RecordName"`
	Type string      `json:"RecordType"`
	Data struct {
		Value    string `json:"Value"`
		Flag     int    `json:"Flag"`
		Tag      string `json:"Tag"`
		Priority int    `json:"Priority"`
		Weight   int    `json:"Weight"`
		Port     int    `json:"Port"`
	} `json:"Data"`
	Proxied    bool   `json:"Proxied"`
	TTL        int    `json:"Ttl"`
	Comment    string `json:"Comment"`
	UpdateTime string `json:"UpdateTime"`
}

func init() { register("aliyunesa", newAliyunESA) }

func newAliyunESA(config dnsgo.Config) (dnsgo.Provider, error) {
	id := config.Credentials["AccessKeyId"]
	if id == "" {
		id = config.Credentials["access_key_id"]
	}
	secret := config.Credentials["AccessKeySecret"]
	if secret == "" {
		secret = config.Credentials["access_key_secret"]
	}
	if id == "" || secret == "" {
		return nil, &dnsgo.Error{Provider: "aliyunesa", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "AccessKeyId and AccessKeySecret are required"}
	}
	endpoint := strings.TrimRight(config.Endpoint, "/")
	if endpoint == "" {
		region := config.Credentials["region"]
		if region == "" {
			region = "cn-hangzhou"
		}
		endpoint = "https://esa." + region + ".aliyuncs.com"
	}
	return &aliyunESA{Base: dnsgo.Base{ProviderKind: "aliyunesa", Features: dnsgo.Capabilities{
		MinTTL: 1, Remarks: true, Lines: true,
	}}, config: config, http: client(config), endpoint: endpoint, keyID: id, secret: secret}, nil
}

func (e *aliyunESA) call(ctx context.Context, method, action string, values url.Values, output any) error {
	if values == nil {
		values = url.Values{}
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return &dnsgo.Error{Provider: e.Kind(), Operation: action, Code: dnsgo.CodeTransport, Cause: err}
	}
	for key, value := range map[string]string{
		"Action": action, "Format": "JSON", "Version": "2024-09-10", "AccessKeyId": e.keyID,
		"SignatureMethod": "HMAC-SHA1", "SignatureVersion": "1.0", "SignatureNonce": hex.EncodeToString(nonce),
		"Timestamp": time.Now().UTC().Format(time.RFC3339),
	} {
		values.Set(key, value)
	}
	values.Set("Signature", aliyunSignatureWithMethod(values, e.secret, method))
	endpoint := e.endpoint + "/"
	var body io.Reader
	if method == http.MethodGet {
		endpoint += "?" + values.Encode()
	} else {
		body = strings.NewReader(values.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return &dnsgo.Error{Provider: e.Kind(), Operation: action, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := e.http.Do(req)
	if err != nil {
		code := dnsgo.CodeResultUnknown
		if method == http.MethodGet {
			code = dnsgo.CodeTransport
		}
		// GET places the signature in the URL. Never return an http.Client
		// error containing that URL.
		return &dnsgo.Error{Provider: e.Kind(), Operation: action, Code: code, Message: "request failed"}
	}
	defer response.Body.Close()
	result, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return &dnsgo.Error{Provider: e.Kind(), Operation: action, Code: dnsgo.CodeResultUnknown, Message: "response read failed"}
	}
	var header struct {
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestID string `json:"RequestId"`
	}
	if err := json.Unmarshal(result, &header); err != nil {
		return &dnsgo.Error{Provider: e.Kind(), Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || header.Code != "" {
		code := dnsgo.CodeProvider
		switch response.StatusCode {
		case 401:
			code = dnsgo.CodeAuthentication
		case 403:
			code = dnsgo.CodePermission
		case 404:
			code = dnsgo.CodeNotFound
		case 429:
			code = dnsgo.CodeRateLimited
		}
		if ambiguousWriteResponse(method, response.StatusCode) {
			code = dnsgo.CodeResultUnknown
		}
		return &dnsgo.Error{Provider: e.Kind(), Operation: action, Code: code, VendorCode: header.Code,
			RequestID: header.RequestID, Message: header.Message}
	}
	if output != nil {
		if err := json.Unmarshal(result, output); err != nil {
			return &dnsgo.Error{Provider: e.Kind(), Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}

func (e *aliyunESA) siteID(zone string) (string, error) {
	if zone == "" {
		zone = e.config.DomainID
	}
	if zone == "" {
		return "", &dnsgo.Error{Provider: e.Kind(), Operation: "site_id", Code: dnsgo.CodeInvalidInput, Message: "SiteId is required"}
	}
	return zone, nil
}

func (e *aliyunESA) domain() (string, error) {
	domain := strings.TrimSuffix(e.config.Domain, ".")
	if domain == "" {
		return "", &dnsgo.Error{Provider: e.Kind(), Operation: "domain", Code: dnsgo.CodeInvalidInput, Message: "domain is required for DNS records"}
	}
	return domain, nil
}

func (e *aliyunESA) fqdn(name string) (string, error) {
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

func (e *aliyunESA) Check(ctx context.Context) error {
	_, err := e.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (e *aliyunESA) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	values := aliyunPage(query.Page, query.PageSize)
	values.Set("AccessType", "NS")
	if query.Keyword != "" {
		values.Set("SiteName", query.Keyword)
	}
	var result struct {
		Total int `json:"TotalCount"`
		Sites []struct {
			ID   json.Number `json:"SiteId"`
			Name string      `json:"SiteName"`
		} `json:"Sites"`
	}
	if err := e.call(ctx, http.MethodGet, "ListSites", values, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	page := dnsgo.Page[dnsgo.Zone]{Total: result.Total, Items: make([]dnsgo.Zone, 0, len(result.Sites))}
	for _, row := range result.Sites {
		page.Items = append(page.Items, dnsgo.Zone{ID: row.ID.String(), Name: row.Name})
	}
	return page, nil
}

func (e *aliyunESA) toRecord(zone string, row esaRecord) dnsgo.Record {
	domain := strings.TrimSuffix(e.config.Domain, ".")
	name := row.Name
	if name == domain {
		name = "@"
	} else if domain != "" {
		name = strings.TrimSuffix(name, "."+domain)
	}
	value := row.Data.Value
	kind := row.Type
	var priority *uint16
	switch kind {
	case "CAA":
		value = strconv.Itoa(row.Data.Flag) + " " + row.Data.Tag + " " + row.Data.Value
	case "SRV":
		value = strconv.Itoa(row.Data.Priority) + " " + strconv.Itoa(row.Data.Weight) + " " + strconv.Itoa(row.Data.Port) + " " + row.Data.Value
	case "MX":
		v := uint16(row.Data.Priority)
		priority = &v
	case "A/AAAA":
		if ip := net.ParseIP(value); ip != nil {
			if ip.To4() != nil {
				kind = "A"
			} else {
				kind = "AAAA"
			}
		}
	}
	line := "0"
	if row.Proxied {
		line = "1"
	}
	enabled := true
	return dnsgo.Record{ID: row.ID.String(), ZoneID: zone, Name: name, Type: kind, Value: value, Line: line,
		TTL: row.TTL, Priority: priority, Enabled: &enabled, Remark: row.Comment, ModifiedAt: row.UpdateTime}
}

func (e *aliyunESA) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	zone, err := e.siteID(zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	if _, err := e.domain(); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	values := aliyunPage(query.Page, query.PageSize)
	values.Set("SiteId", zone)
	if query.Name != "" || query.Keyword != "" {
		name := query.Name
		if name == "" {
			name = query.Keyword
		}
		full, err := e.fqdn(name)
		if err != nil {
			return dnsgo.Page[dnsgo.Record]{}, err
		}
		values.Set("RecordName", full)
	}
	if query.Type != "" {
		kind := query.Type
		if kind == "A" || kind == "AAAA" {
			kind = "A/AAAA"
		}
		values.Set("Type", kind)
	}
	if query.Line != "" {
		values.Set("Proxied", strconv.FormatBool(query.Line == "1"))
	}
	var result struct {
		Total   int         `json:"TotalCount"`
		Records []esaRecord `json:"Records"`
	}
	if err := e.call(ctx, http.MethodGet, "ListRecords", values, &result); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	page := dnsgo.Page[dnsgo.Record]{Total: result.Total, Items: make([]dnsgo.Record, 0, len(result.Records))}
	for _, row := range result.Records {
		record := e.toRecord(zone, row)
		if query.Type != "" && query.Type != record.Type || query.Value != "" && query.Value != record.Value ||
			query.Enabled != nil && !*query.Enabled {
			continue
		}
		page.Items = append(page.Items, record)
	}
	return page, nil
}

func (e *aliyunESA) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	zone, err := e.siteID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if _, err := e.domain(); err != nil {
		return dnsgo.Record{}, err
	}
	var result struct {
		Record esaRecord `json:"RecordModel"`
	}
	if err := e.call(ctx, http.MethodGet, "GetRecord", url.Values{"RecordId": {id}}, &result); err != nil {
		return dnsgo.Record{}, err
	}
	return e.toRecord(zone, result.Record), nil
}

func (e *aliyunESA) recordData(record dnsgo.Record) (string, string, error) {
	kind := record.Type
	if kind == "A" || kind == "AAAA" {
		kind = "A/AAAA"
	}
	data := map[string]any{"Value": record.Value}
	switch record.Type {
	case "CAA":
		parts := strings.SplitN(record.Value, " ", 3)
		if len(parts) != 3 {
			return "", "", &dnsgo.Error{Provider: e.Kind(), Operation: "record_data", Code: dnsgo.CodeInvalidInput, Message: "CAA value must be flag tag value"}
		}
		flag, err := strconv.Atoi(parts[0])
		if err != nil {
			return "", "", &dnsgo.Error{Provider: e.Kind(), Operation: "record_data", Code: dnsgo.CodeInvalidInput, Message: "invalid CAA flag"}
		}
		data = map[string]any{"Flag": flag, "Tag": parts[1], "Value": parts[2]}
	case "SRV":
		parts := strings.SplitN(record.Value, " ", 4)
		if len(parts) != 4 {
			return "", "", &dnsgo.Error{Provider: e.Kind(), Operation: "record_data", Code: dnsgo.CodeInvalidInput, Message: "SRV value must be priority weight port value"}
		}
		keys := []string{"Priority", "Weight", "Port"}
		for i, key := range keys {
			n, err := strconv.Atoi(parts[i])
			if err != nil {
				return "", "", &dnsgo.Error{Provider: e.Kind(), Operation: "record_data", Code: dnsgo.CodeInvalidInput, Message: "invalid SRV value"}
			}
			data[key] = n
		}
		data["Value"] = parts[3]
	case "MX":
		priority := uint16(1)
		if record.Priority != nil {
			priority = *record.Priority
		}
		data["Priority"] = priority
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return "", "", &dnsgo.Error{Provider: e.Kind(), Operation: "record_data", Code: dnsgo.CodeInvalidInput, Cause: err}
	}
	return kind, string(encoded), nil
}

func (e *aliyunESA) recordValues(zone string, record dnsgo.Record, create bool) (url.Values, error) {
	kind, data, err := e.recordData(record)
	if err != nil {
		return nil, err
	}
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	proxied := record.Line == "1"
	values := url.Values{"Type": {kind}, "Proxied": {strconv.FormatBool(proxied)}, "Ttl": {strconv.Itoa(ttl)},
		"Data": {data}, "Comment": {record.Remark}}
	if proxied {
		values.Set("BizName", "web")
	}
	if create {
		name, err := e.fqdn(record.Name)
		if err != nil {
			return nil, err
		}
		values.Set("SiteId", zone)
		values.Set("RecordName", name)
	} else {
		values.Set("RecordId", record.ID)
	}
	return values, nil
}

func (e *aliyunESA) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(e.Kind(), e.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := e.siteID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	values, err := e.recordValues(zone, record, true)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var result struct {
		ID json.Number `json:"RecordId"`
	}
	if err := e.call(ctx, http.MethodPost, "CreateRecord", values, &result); err != nil {
		return dnsgo.Record{}, err
	}
	record.ID, record.ZoneID = result.ID.String(), zone
	return record, nil
}

func (e *aliyunESA) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(e.Kind(), e.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := e.siteID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: e.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	values, err := e.recordValues(zone, record, false)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if err := e.call(ctx, http.MethodPost, "UpdateRecord", values, nil); err != nil {
		return dnsgo.Record{}, err
	}
	record.ZoneID = zone
	return record, nil
}

func (e *aliyunESA) DeleteRecord(ctx context.Context, zone, id string) error {
	if _, err := e.siteID(zone); err != nil {
		return err
	}
	if id == "" {
		return &dnsgo.Error{Provider: e.Kind(), Operation: "delete_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	return e.call(ctx, http.MethodPost, "DeleteRecord", url.Values{"RecordId": {id}}, nil)
}

func (e *aliyunESA) RecordLines(context.Context, string) ([]dnsgo.RecordLine, error) {
	return []dnsgo.RecordLine{{Code: "0", Name: "仅 DNS"}, {Code: "1", Name: "已代理"}}, nil
}

func (e *aliyunESA) MinTTL(context.Context, string) (int, error) { return 1, nil }

var _ dnsgo.Provider = (*aliyunESA)(nil)
