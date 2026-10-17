package providers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type aliyun struct {
	dnsgo.Base
	config   dnsgo.Config
	http     *http.Client
	endpoint string
	keyID    string
	secret   string
}

type aliyunRecord struct {
	RecordID        string  `json:"RecordId"`
	DomainName      string  `json:"DomainName"`
	RR              string  `json:"RR"`
	Type            string  `json:"Type"`
	Value           string  `json:"Value"`
	Line            string  `json:"Line"`
	Status          string  `json:"Status"`
	TTL             int     `json:"TTL"`
	Priority        *uint16 `json:"Priority"`
	Weight          *uint16 `json:"Weight"`
	Remark          string  `json:"Remark"`
	UpdateTimestamp int64   `json:"UpdateTimestamp"`
}

func init() { register("aliyun", newAliyun) }

func newAliyun(config dnsgo.Config) (dnsgo.Provider, error) {
	id := config.Credentials["AccessKeyId"]
	if id == "" {
		id = config.Credentials["access_key_id"]
	}
	secret := config.Credentials["AccessKeySecret"]
	if secret == "" {
		secret = config.Credentials["access_key_secret"]
	}
	if id == "" || secret == "" {
		return nil, &dnsgo.Error{Provider: "aliyun", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "AccessKeyId and AccessKeySecret are required"}
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = "https://alidns.aliyuncs.com"
	}
	return &aliyun{Base: dnsgo.Base{ProviderKind: "aliyun", Features: dnsgo.Capabilities{
		RecordTypes: []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT", "REDIRECT_URL", "FORWARD_URL", "URL"},
		MinTTL:      600, Remarks: true, Status: true, Redirect: true, Logs: true, Weight: true, CreateZone: true, Lines: true, Sort: true,
	}}, config: config, http: client(config), endpoint: endpoint, keyID: id, secret: secret}, nil
}

func aliyunEscape(value string) string { return strings.ReplaceAll(url.QueryEscape(value), "+", "%20") }

func aliyunSignatureWithMethod(values url.Values, secret, method string) string {
	canonical := strings.ReplaceAll(values.Encode(), "+", "%20")
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	_, _ = mac.Write([]byte(method + "&%2F&" + aliyunEscape(canonical)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func aliyunSignature(values url.Values, secret string) string {
	return aliyunSignatureWithMethod(values, secret, http.MethodPost)
}

func (a *aliyun) call(ctx context.Context, action string, values url.Values, output any) error {
	if values == nil {
		values = url.Values{}
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return &dnsgo.Error{Provider: a.Kind(), Operation: action, Code: dnsgo.CodeTransport, Cause: err}
	}
	for key, value := range map[string]string{
		"Action": action, "Format": "JSON", "Version": "2015-01-09", "AccessKeyId": a.keyID,
		"SignatureMethod": "HMAC-SHA1", "SignatureVersion": "1.0", "SignatureNonce": hex.EncodeToString(nonce),
		"Timestamp": time.Now().UTC().Format(time.RFC3339),
	} {
		values.Set(key, value)
	}
	values.Set("Signature", aliyunSignature(values, a.secret))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return &dnsgo.Error{Provider: a.Kind(), Operation: action, Code: dnsgo.CodeInvalidInput, Cause: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := a.http.Do(req)
	if err != nil {
		return &dnsgo.Error{Provider: a.Kind(), Operation: action, Code: dnsgo.CodeResultUnknown, Cause: err}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return &dnsgo.Error{Provider: a.Kind(), Operation: action, Code: dnsgo.CodeResultUnknown, Cause: err}
	}
	// The provider uses RequestId rather than RequestID in its JSON response.
	var envelope struct {
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestID string `json:"RequestId"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return &dnsgo.Error{Provider: a.Kind(), Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response", Cause: err}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || envelope.Code != "" {
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
		// AliDNS reports a missing record as InvalidRR.NoExist even when the
		// HTTP status is 400, so callers must use the vendor code for readback.
		if envelope.Code == "InvalidRR.NoExist" || envelope.Code == "InvalidDomainName.NoExist" {
			code = dnsgo.CodeNotFound
		}
		if ambiguousWriteResponse(http.MethodPost, response.StatusCode) {
			code = dnsgo.CodeResultUnknown
		}
		return &dnsgo.Error{Provider: a.Kind(), Operation: action, Code: code, VendorCode: envelope.Code, RequestID: envelope.RequestID, Message: envelope.Message}
	}
	if output != nil {
		if err := json.Unmarshal(body, output); err != nil {
			return &dnsgo.Error{Provider: a.Kind(), Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result", Cause: err}
		}
	}
	return nil
}

func (a *aliyun) Check(ctx context.Context) error {
	_, err := a.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (a *aliyun) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	values := aliyunPage(query.Page, query.PageSize)
	if query.Keyword != "" {
		values.Set("KeyWord", query.Keyword)
	}
	var result struct {
		TotalCount int `json:"TotalCount"`
		Domains    struct {
			Domain []struct {
				ID          string `json:"DomainId"`
				Name        string `json:"DomainName"`
				Count       int    `json:"RecordCount"`
				NameServers struct {
					Server []string `json:"DnsServer"`
				} `json:"DnsServers"`
			} `json:"Domain"`
		} `json:"Domains"`
	}
	if err := a.call(ctx, "DescribeDomains", values, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	page := dnsgo.Page[dnsgo.Zone]{Total: result.TotalCount, Items: make([]dnsgo.Zone, 0, len(result.Domains.Domain))}
	for _, row := range result.Domains.Domain {
		page.Items = append(page.Items, dnsgo.Zone{ID: row.Name, Name: row.Name, RecordCount: row.Count, NameServers: row.NameServers.Server})
	}
	return page, nil
}

func aliyunPage(page, size int) url.Values {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return url.Values{"PageNumber": {strconv.Itoa(page)}, "PageSize": {strconv.Itoa(size)}}
}

func (a *aliyun) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	var result struct {
		ID   string `json:"DomainId"`
		Name string `json:"DomainName"`
	}
	if err := a.call(ctx, "AddDomain", url.Values{"DomainName": {strings.TrimSuffix(name, ".")}}, &result); err != nil {
		return dnsgo.Zone{}, err
	}
	return dnsgo.Zone{ID: result.Name, Name: result.Name}, nil
}

func (a *aliyun) domain(zone string) string {
	if zone != "" {
		return strings.TrimSuffix(zone, ".")
	}
	return strings.TrimSuffix(a.config.Domain, ".")
}

func (a *aliyun) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	zone = a.domain(zone)
	values := aliyunPage(query.Page, query.PageSize)
	values.Set("DomainName", zone)
	if query.Name != "" || query.Type != "" || query.Line != "" || query.Value != "" {
		values.Set("SearchMode", "ADVANCED")
		if query.Name != "" {
			values.Set("RRKeyWord", aliRR(query.Name, zone))
		}
		if query.Value != "" {
			values.Set("ValueKeyWord", query.Value)
		}
		if query.Type != "" {
			values.Set("Type", query.Type)
		}
		if query.Line != "" {
			values.Set("Line", query.Line)
		}
	} else if query.Keyword != "" {
		values.Set("KeyWord", query.Keyword)
	}
	if query.Enabled != nil {
		if *query.Enabled {
			values.Set("Status", "Enable")
		} else {
			values.Set("Status", "Disable")
		}
	}
	allowedSort := map[string]string{"Name": "RR", "Type": "Type", "LineName": "Line", "Value": "Value", "UpdateTime": "UpdateDate"}
	if field := allowedSort[query.SortField]; field != "" {
		values.Set("OrderBy", field)
		if query.SortDesc {
			values.Set("Direction", "DESC")
		} else {
			values.Set("Direction", "ASC")
		}
	}
	var result struct {
		TotalCount    int `json:"TotalCount"`
		DomainRecords struct {
			Record []aliyunRecord `json:"Record"`
		} `json:"DomainRecords"`
	}
	if err := a.call(ctx, "DescribeDomainRecords", values, &result); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	page := dnsgo.Page[dnsgo.Record]{Total: result.TotalCount, Items: make([]dnsgo.Record, 0, len(result.DomainRecords.Record))}
	for _, row := range result.DomainRecords.Record {
		page.Items = append(page.Items, row.record())
	}
	return page, nil
}

func (r aliyunRecord) record() dnsgo.Record {
	name := r.DomainName
	if r.RR != "" && r.RR != "@" {
		name = r.RR + "." + r.DomainName
	}
	enabled := !strings.EqualFold(r.Status, "DISABLE")
	out := dnsgo.Record{ID: r.RecordID, ZoneID: r.DomainName, Name: name, Type: r.Type, Value: r.Value,
		TTL: r.TTL, Priority: r.Priority, Weight: r.Weight, Line: r.Line, Enabled: &enabled, Remark: r.Remark}
	if r.UpdateTimestamp > 0 {
		out.ModifiedAt = time.UnixMilli(r.UpdateTimestamp).UTC().Format(time.RFC3339)
	}
	return out
}

func (a *aliyun) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	var row aliyunRecord
	if err := a.call(ctx, "DescribeDomainRecordInfo", url.Values{"RecordId": {id}}, &row); err != nil {
		return dnsgo.Record{}, err
	}
	if zone != "" && !strings.EqualFold(a.domain(zone), row.DomainName) {
		return dnsgo.Record{}, &dnsgo.Error{Provider: a.Kind(), Operation: "get_record", Code: dnsgo.CodeConflict, Message: "record belongs to a different zone"}
	}
	record := row.record()
	// DescribeDomainRecordInfo omits the load-balancing weight. Read it from
	// the record list so a detail read or a write readback preserves this field.
	if row.Weight == nil && (row.Type == "A" || row.Type == "AAAA" || row.Type == "CNAME") {
		seen := 0
		for page := 1; page <= 10000; page++ {
			listed, err := a.ListRecords(ctx, row.DomainName, dnsgo.RecordQuery{Name: row.RR, Type: row.Type, Page: page, PageSize: 100})
			if err != nil {
				return dnsgo.Record{}, err
			}
			for _, item := range listed.Items {
				if item.ID == id {
					record.Weight = item.Weight
					return record, nil
				}
			}
			seen += len(listed.Items)
			if len(listed.Items) == 0 || listed.Total > 0 && seen >= listed.Total || listed.Total == 0 && len(listed.Items) < 100 {
				break
			}
		}
		return dnsgo.Record{}, &dnsgo.Error{Provider: a.Kind(), Operation: "get_record", Code: dnsgo.CodeResultUnknown,
			Message: "record details and weight listing disagree; read back before retrying"}
	}
	return record, nil
}

func aliRR(name, zone string) string {
	name = strings.TrimSuffix(name, ".")
	if name == "@" || strings.EqualFold(name, zone) {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}

func (a *aliyun) recordParams(zone string, record dnsgo.Record) url.Values {
	line := record.Line
	if line == "" {
		line = "default"
	}
	if converted := map[string]string{"0": "default", "10=1": "unicom", "10=0": "telecom",
		"10=3": "mobile", "10=2": "edu", "3=0": "oversea", "10=22": "btvn",
		"80=0": "search", "7=0": "internal"}[line]; converted != "" {
		line = converted
	}
	value := record.Value
	if value == "" && len(record.Values) == 1 {
		value = record.Values[0]
	}
	ttl := record.TTL
	if ttl == 0 {
		ttl = 600
	}
	recordType := record.Type
	if recordType == "URL" {
		recordType = "REDIRECT_URL"
	}
	values := url.Values{"RR": {aliRR(record.Name, zone)}, "Type": {recordType}, "Value": {value}, "Line": {line}, "TTL": {strconv.Itoa(ttl)}}
	if record.Priority != nil {
		values.Set("Priority", strconv.Itoa(int(*record.Priority)))
	}
	return values
}

func (a *aliyun) validateRecordInput(record dnsgo.Record) error {
	if record.Weight != nil {
		if *record.Weight < 1 || *record.Weight > 100 {
			return &dnsgo.Error{Provider: a.Kind(), Operation: "record", Code: dnsgo.CodeInvalidInput, Message: "weight must be between 1 and 100"}
		}
		if record.Type != "A" && record.Type != "AAAA" && record.Type != "CNAME" {
			return &dnsgo.Error{Provider: a.Kind(), Operation: "record", Code: dnsgo.CodeUnsupported, Message: "weight is only supported for A, AAAA and CNAME records"}
		}
	}
	if record.Name == "" || record.Type == "" || record.Value == "" && len(record.Values) != 1 {
		return &dnsgo.Error{Provider: a.Kind(), Operation: "record", Code: dnsgo.CodeInvalidInput,
			Message: "record name, type and a single value are required"}
	}
	if len(record.Values) > 1 || record.Proxied != nil {
		return &dnsgo.Error{Provider: a.Kind(), Operation: "record", Code: dnsgo.CodeUnsupported,
			Message: "multi-value and proxy fields are unsupported by AliDNS record writes"}
	}
	if record.Value != "" && len(record.Values) == 1 && record.Value != record.Values[0] {
		return &dnsgo.Error{Provider: a.Kind(), Operation: "record", Code: dnsgo.CodeConflict,
			Message: "Value and Values disagree"}
	}
	return nil
}

func (a *aliyun) afterRecordWrite(ctx context.Context, zone string, record dnsgo.Record, before *dnsgo.Record) (dnsgo.Record, error) {
	partial := dnsgo.Record{ID: record.ID, ZoneID: zone, Name: record.Name, Type: record.Type,
		Value: record.Value, TTL: record.TTL, Line: record.Line}
	wrap := func(step string, err error) (dnsgo.Record, error) {
		return partial, &dnsgo.Error{Provider: a.Kind(), Operation: "write_record", Code: dnsgo.CodeResultUnknown,
			Message: "record " + step + " did not complete; read record ID before retrying", Cause: err}
	}
	if record.Enabled != nil && (before == nil && !*record.Enabled || before != nil && (before.Enabled == nil || *before.Enabled != *record.Enabled)) {
		if err := a.SetRecordStatus(ctx, zone, record.ID, *record.Enabled); err != nil {
			return wrap("status update", err)
		}
	}
	if before == nil && record.Remark != "" || before != nil && before.Remark != record.Remark {
		if err := a.SetRecordRemark(ctx, zone, record.ID, record.Remark); err != nil {
			return wrap("remark update", err)
		}
	}
	if record.Weight != nil && (before == nil || before.Weight == nil || *before.Weight != *record.Weight) {
		if err := a.UpdateRecordWeight(ctx, zone, record.ID, int(*record.Weight)); err != nil {
			return wrap("weight update", err)
		}
	}
	result, err := a.GetRecord(ctx, zone, record.ID)
	if err != nil {
		return wrap("readback", err)
	}
	return result, nil
}

func (a *aliyun) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(a.Kind(), a.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	if err := a.validateRecordInput(record); err != nil {
		return dnsgo.Record{}, err
	}
	zone = a.domain(zone)
	values := a.recordParams(zone, record)
	values.Set("DomainName", zone)
	var result struct {
		ID string `json:"RecordId"`
	}
	if err := a.call(ctx, "AddDomainRecord", values, &result); err != nil {
		return dnsgo.Record{}, err
	}
	if result.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: a.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
			Message: "AliDNS returned no record ID; list records before retrying"}
	}
	record.ID = result.ID
	return a.afterRecordWrite(ctx, zone, record, nil)
}

func (a *aliyun) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(a.Kind(), a.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: a.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	if err := a.validateRecordInput(record); err != nil {
		return dnsgo.Record{}, err
	}
	zone = a.domain(zone)
	before, err := a.GetRecord(ctx, zone, record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	values := a.recordParams(zone, record)
	values.Set("RecordId", record.ID)
	if err := a.call(ctx, "UpdateDomainRecord", values, nil); err != nil {
		return dnsgo.Record{}, err
	}
	return a.afterRecordWrite(ctx, zone, record, &before)
}

func (a *aliyun) SetRecordRemark(ctx context.Context, _, id, remark string) error {
	return a.call(ctx, "UpdateDomainRecordRemark", url.Values{"RecordId": {id}, "Remark": {remark}}, nil)
}

func (a *aliyun) DeleteRecord(ctx context.Context, zone, id string) error {
	if _, err := a.GetRecord(ctx, zone, id); err != nil {
		return err
	}
	return a.call(ctx, "DeleteDomainRecord", url.Values{"RecordId": {id}}, nil)
}

func (a *aliyun) SetRecordStatus(ctx context.Context, _, id string, enabled bool) error {
	status := "Disable"
	if enabled {
		status = "Enable"
	}
	return a.call(ctx, "SetDomainRecordStatus", url.Values{"RecordId": {id}, "Status": {status}}, nil)
}

func (a *aliyun) ListRecordLogs(ctx context.Context, zone string, query dnsgo.LogQuery) (dnsgo.Page[dnsgo.RecordLog], error) {
	values := aliyunPage(query.Page, query.PageSize)
	values.Set("DomainName", a.domain(zone))
	values.Set("Lang", "zh")
	if query.Keyword != "" {
		values.Set("KeyWord", query.Keyword)
	}
	if query.Start != "" {
		values.Set("StartDate", query.Start)
	}
	if query.End != "" {
		values.Set("endDate", query.End)
	}
	var result struct {
		TotalCount int `json:"TotalCount"`
		RecordLogs struct {
			RecordLog []struct {
				ActionTimestamp int64  `json:"ActionTimestamp"`
				Action          string `json:"Action"`
				Message         string `json:"Message"`
			} `json:"RecordLog"`
		} `json:"RecordLogs"`
	}
	if err := a.call(ctx, "DescribeRecordLogs", values, &result); err != nil {
		return dnsgo.Page[dnsgo.RecordLog]{}, err
	}
	page := dnsgo.Page[dnsgo.RecordLog]{Total: result.TotalCount, Items: make([]dnsgo.RecordLog, 0, len(result.RecordLogs.RecordLog))}
	for _, row := range result.RecordLogs.RecordLog {
		page.Items = append(page.Items, dnsgo.RecordLog{Action: row.Action, Message: row.Message, CreatedAt: time.UnixMilli(row.ActionTimestamp).UTC().Format(time.RFC3339)})
	}
	return page, nil
}

func (a *aliyun) domainInfo(ctx context.Context, zone string) (struct {
	MinTTL      int `json:"MinTtl"`
	RecordLines struct {
		RecordLine []struct {
			Code string `json:"LineCode"`
			Name string `json:"LineDisplayName"`
		} `json:"RecordLine"`
	} `json:"RecordLines"`
}, error) {
	var result struct {
		MinTTL      int `json:"MinTtl"`
		RecordLines struct {
			RecordLine []struct {
				Code string `json:"LineCode"`
				Name string `json:"LineDisplayName"`
			} `json:"RecordLine"`
		} `json:"RecordLines"`
	}
	err := a.call(ctx, "DescribeDomainInfo", url.Values{"DomainName": {a.domain(zone)}, "NeedDetailAttributes": {"true"}, "Lang": {"zh"}}, &result)
	return result, err
}

func (a *aliyun) RecordLines(ctx context.Context, zone string) ([]dnsgo.RecordLine, error) {
	info, err := a.domainInfo(ctx, zone)
	if err != nil {
		return nil, err
	}
	lines := make([]dnsgo.RecordLine, 0, len(info.RecordLines.RecordLine))
	for _, row := range info.RecordLines.RecordLine {
		lines = append(lines, dnsgo.RecordLine{Code: row.Code, Name: row.Name})
	}
	return lines, nil
}

func (a *aliyun) MinTTL(ctx context.Context, zone string) (int, error) {
	info, err := a.domainInfo(ctx, zone)
	if err != nil {
		return 0, err
	}
	if info.MinTTL < 1 {
		return 0, fmt.Errorf("aliyun returned invalid MinTtl")
	}
	return info.MinTTL, nil
}
