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

	"github.com/rainchen537/dnsgo"
)

// rainbowDNS talks to the reference project's public application API, so a
// DnsGo installation can manage records in an existing Rainbow DNS instance.
type rainbowDNS struct {
	dnsgo.Base
	config dnsgo.Config
	http   *http.Client
	base   string
	uid    string
	key    string
}

type rainbowRecord struct {
	ID         jsonScalar `json:"RecordId"`
	Domain     string     `json:"Domain"`
	Name       string     `json:"Name"`
	Type       string     `json:"Type"`
	Value      string     `json:"Value"`
	Line       jsonScalar `json:"Line"`
	TTL        int        `json:"TTL"`
	MX         *uint16    `json:"MX"`
	Status     jsonScalar `json:"Status"`
	Weight     *uint16    `json:"Weight"`
	Remark     string     `json:"Remark"`
	UpdateTime string     `json:"UpdateTime"`
}

func init() { register("dnsmgr", newRainbowDNS) }

func newRainbowDNS(config dnsgo.Config) (dnsgo.Provider, error) {
	uid, key := config.Credentials["uid"], config.Credentials["key"]
	base := strings.TrimRight(config.Endpoint, "/")
	if base == "" {
		base = strings.TrimRight(config.Credentials["base_url"], "/")
	}
	if uid == "" || key == "" || base == "" {
		return nil, &dnsgo.Error{Provider: "dnsmgr", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "uid, key and endpoint are required"}
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" || parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, &dnsgo.Error{Provider: "dnsmgr", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "invalid endpoint"}
	}
	return &rainbowDNS{Base: dnsgo.Base{ProviderKind: "dnsmgr", Features: dnsgo.Capabilities{
		Remarks: true, Status: true, Redirect: true, Weight: true, Lines: true,
	}}, config: config, http: client(config), base: base, uid: uid, key: key}, nil
}

func (r *rainbowDNS) request(ctx context.Context, path string, params url.Values, output any) error {
	if params == nil {
		params = url.Values{}
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	digest := md5.Sum([]byte(r.uid + timestamp + r.key))
	params.Set("uid", r.uid)
	params.Set("timestamp", timestamp)
	params.Set("sign", hex.EncodeToString(digest[:]))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.base+path, strings.NewReader(params.Encode()))
	if err != nil {
		return &dnsgo.Error{Provider: r.Kind(), Operation: path, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := r.http.Do(req)
	if err != nil {
		return &dnsgo.Error{Provider: r.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown, Message: "request failed"}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return &dnsgo.Error{Provider: r.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown, Message: "response read failed"}
	}
	var envelope struct {
		Code  *int            `json:"code"`
		Msg   string          `json:"msg"`
		Data  json.RawMessage `json:"data"`
		Rows  json.RawMessage `json:"rows"`
		Total int             `json:"total"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return &dnsgo.Error{Provider: r.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response"}
	}
	success := response.StatusCode >= 200 && response.StatusCode < 300 &&
		(envelope.Code != nil && *envelope.Code == 0 || envelope.Code == nil && len(envelope.Rows) > 0)
	if !success {
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
		if ambiguousWriteResponse(http.MethodPost, response.StatusCode) {
			code = dnsgo.CodeResultUnknown
		}
		e := &dnsgo.Error{Provider: r.Kind(), Operation: path, Code: code, Message: envelope.Msg}
		if envelope.Code != nil {
			e.VendorCode = strconv.Itoa(*envelope.Code)
		}
		return e
	}
	if output != nil {
		payload := envelope.Data
		if len(envelope.Rows) > 0 && envelope.Code == nil {
			payload = body
		}
		if len(payload) > 0 && string(payload) != "null" {
			if err := json.Unmarshal(payload, output); err != nil {
				return &dnsgo.Error{Provider: r.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
			}
		}
	}
	return nil
}

func (r *rainbowDNS) zoneID(zone string) (string, error) {
	if zone == "" {
		zone = r.config.DomainID
	}
	if zone == "" {
		return "", &dnsgo.Error{Provider: r.Kind(), Operation: "zone_id", Code: dnsgo.CodeInvalidInput, Message: "domain ID is required"}
	}
	return zone, nil
}

func (r *rainbowDNS) Check(ctx context.Context) error {
	_, err := r.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (r *rainbowDNS) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	offset, size := offsetPage(query.Page, query.PageSize)
	params := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(size)}}
	if query.Keyword != "" {
		params.Set("kw", query.Keyword)
	}
	var result struct {
		Total int `json:"total"`
		Rows  []struct {
			ID    jsonScalar `json:"id"`
			Name  string     `json:"name"`
			Count int        `json:"recordcount"`
		} `json:"rows"`
	}
	if err := r.request(ctx, "/api/domain", params, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(result.Rows))
	for _, row := range result.Rows {
		zones = append(zones, dnsgo.Zone{ID: row.ID.String(), Name: row.Name, RecordCount: row.Count})
	}
	return dnsgo.Page[dnsgo.Zone]{Total: result.Total, Items: zones}, nil
}

func (r *rainbowDNS) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	zone, err := r.zoneID(zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	offset, size := offsetPage(query.Page, query.PageSize)
	params := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(size)}}
	for key, value := range map[string]string{"keyword": query.Keyword, "subdomain": query.Name, "value": query.Value,
		"type": query.Type, "line": query.Line} {
		if value != "" {
			params.Set(key, value)
		}
	}
	if query.Enabled != nil {
		if *query.Enabled {
			params.Set("status", "1")
		} else {
			params.Set("status", "0")
		}
	}
	var result struct {
		Total int             `json:"total"`
		Rows  []rainbowRecord `json:"rows"`
	}
	if err := r.request(ctx, "/api/record/data/"+url.PathEscape(zone), params, &result); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	records := make([]dnsgo.Record, 0, len(result.Rows))
	for _, row := range result.Rows {
		enabled := row.Status.String() == "1"
		records = append(records, dnsgo.Record{ID: row.ID.String(), ZoneID: zone, Name: row.Name, Type: row.Type,
			Value: row.Value, Line: row.Line.String(), TTL: row.TTL, Priority: row.MX, Weight: row.Weight,
			Enabled: &enabled, Remark: row.Remark, ModifiedAt: row.UpdateTime})
	}
	return dnsgo.Page[dnsgo.Record]{Total: result.Total, Items: records}, nil
}

func (r *rainbowDNS) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	seen := 0
	for page := 1; page <= 10000; page++ {
		result, err := r.ListRecords(ctx, zone, dnsgo.RecordQuery{Page: page, PageSize: 100})
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
			return dnsgo.Record{}, &dnsgo.Error{Provider: r.Kind(), Operation: "get_record", Code: dnsgo.CodeResultUnknown,
				Message: "record listing exceeded the page limit"}
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: r.Kind(), Operation: "get_record", Code: dnsgo.CodeNotFound}
}

func (r *rainbowDNS) recordParams(record dnsgo.Record, create bool) url.Values {
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	line := record.Line
	if line == "" {
		line = "default"
	}
	params := url.Values{"name": {record.Name}, "type": {record.Type}, "value": {record.Value},
		"line": {line}, "ttl": {strconv.Itoa(ttl)}}
	if record.Type == "MX" && record.Priority != nil {
		params.Set("mx", strconv.Itoa(int(*record.Priority)))
	}
	if record.Weight != nil {
		params.Set("weight", strconv.Itoa(int(*record.Weight)))
	}
	if record.Remark != "" {
		params.Set("remark", record.Remark)
	}
	if !create {
		params.Set("recordid", record.ID)
	}
	return params
}

func (r *rainbowDNS) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(r.Kind(), r.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := r.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	before := map[string]bool{}
	seen := 0
	for page := 1; page <= 10000; page++ {
		result, err := r.ListRecords(ctx, zone, dnsgo.RecordQuery{Page: page, PageSize: 100})
		if err != nil {
			return dnsgo.Record{}, err
		}
		for _, row := range result.Items {
			before[row.ID] = true
		}
		seen += len(result.Items)
		if !morePages(result.Total, seen, len(result.Items), 100) {
			break
		}
		if page == 10000 {
			return dnsgo.Record{}, &dnsgo.Error{Provider: r.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
				Message: "existing record listing exceeded the page limit"}
		}
	}
	if err := r.request(ctx, "/api/record/add/"+url.PathEscape(zone), r.recordParams(record, true), nil); err != nil {
		return dnsgo.Record{}, err
	}
	seen = 0
	for page := 1; page <= 10000; page++ {
		result, err := r.ListRecords(ctx, zone, dnsgo.RecordQuery{Page: page, PageSize: 100})
		if err != nil {
			return dnsgo.Record{}, &dnsgo.Error{Provider: r.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
				Message: "record created but readback failed", Cause: err}
		}
		for _, created := range result.Items {
			if !before[created.ID] && strings.EqualFold(created.Name, record.Name) && created.Type == record.Type && created.Value == record.Value {
				return applyRequestedStatus(ctx, r, zone, created, record.Enabled, created.Enabled)
			}
		}
		seen += len(result.Items)
		if !morePages(result.Total, seen, len(result.Items), 100) {
			break
		}
		if page == 10000 {
			return dnsgo.Record{}, &dnsgo.Error{Provider: r.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
				Message: "record created but readback exceeded the page limit"}
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: r.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
		Message: "record was created but its ID could not be confirmed"}
}

func (r *rainbowDNS) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(r.Kind(), r.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := r.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: r.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	current, err := r.GetRecord(ctx, zone, record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if err := r.request(ctx, "/api/record/update/"+url.PathEscape(zone), r.recordParams(record, false), nil); err != nil {
		return dnsgo.Record{}, err
	}
	record.ZoneID = zone
	written, err := applyRequestedStatus(ctx, r, zone, record, record.Enabled, current.Enabled)
	if err != nil {
		return written, err
	}
	if current.Remark != "" && record.Remark == "" {
		if err := r.SetRecordRemark(ctx, zone, record.ID, ""); err != nil {
			return written, &dnsgo.Error{Provider: r.Kind(), Operation: "update_record", Code: dnsgo.CodeResultUnknown,
				Message: "record updated but remark clear failed", Cause: err}
		}
	}
	return written, nil
}

func (r *rainbowDNS) SetRecordRemark(ctx context.Context, zone, id, remark string) error {
	zone, err := r.zoneID(zone)
	if err != nil {
		return err
	}
	return r.request(ctx, "/api/record/remark/"+url.PathEscape(zone), url.Values{"recordid": {id}, "remark": {remark}}, nil)
}

func (r *rainbowDNS) DeleteRecord(ctx context.Context, zone, id string) error {
	zone, err := r.zoneID(zone)
	if err != nil {
		return err
	}
	return r.request(ctx, "/api/record/delete/"+url.PathEscape(zone), url.Values{"recordid": {id}}, nil)
}

func (r *rainbowDNS) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	zone, err := r.zoneID(zone)
	if err != nil {
		return err
	}
	status := "0"
	if enabled {
		status = "1"
	}
	return r.request(ctx, "/api/record/status/"+url.PathEscape(zone), url.Values{"recordid": {id}, "status": {status}}, nil)
}

func (r *rainbowDNS) domainInfo(ctx context.Context, zone string, output any) error {
	zone, err := r.zoneID(zone)
	if err != nil {
		return err
	}
	return r.request(ctx, "/api/domain/"+url.PathEscape(zone), url.Values{"loginurl": {"0"}}, output)
}

func (r *rainbowDNS) RecordLines(ctx context.Context, zone string) ([]dnsgo.RecordLine, error) {
	var result struct {
		Lines []struct {
			ID     jsonScalar `json:"id"`
			Name   string     `json:"name"`
			Parent jsonScalar `json:"parent"`
		} `json:"recordLine"`
	}
	if err := r.domainInfo(ctx, zone, &result); err != nil {
		return nil, err
	}
	lines := make([]dnsgo.RecordLine, 0, len(result.Lines))
	for _, row := range result.Lines {
		lines = append(lines, dnsgo.RecordLine{Code: row.ID.String(), Name: row.Name, Parent: row.Parent.String()})
	}
	return lines, nil
}

func (r *rainbowDNS) MinTTL(ctx context.Context, zone string) (int, error) {
	var result struct {
		MinTTL int `json:"minTTL"`
	}
	if err := r.domainInfo(ctx, zone, &result); err != nil {
		return 0, err
	}
	return result.MinTTL, nil
}

var _ dnsgo.Provider = (*rainbowDNS)(nil)
