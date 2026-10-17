package providers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type baoTa struct {
	dnsgo.Base
	config    dnsgo.Config
	http      *http.Client
	base      string
	accountID string
	accessKey string
	secretKey string
}

type btRecord struct {
	ID        json.Number `json:"record_id"`
	Name      string      `json:"record"`
	Type      string      `json:"type"`
	Value     string      `json:"value"`
	Line      json.Number `json:"viewID"`
	TTL       int         `json:"TTL"`
	MX        *uint16     `json:"MX"`
	State     int         `json:"state"`
	Remark    string      `json:"remark"`
	CreatedAt string      `json:"created_at"`
}

func init() { register("bt", newBaoTa) }

func newBaoTa(config dnsgo.Config) (dnsgo.Provider, error) {
	accountID, accessKey, secretKey := config.Credentials["AccountID"], config.Credentials["AccessKey"], config.Credentials["SecretKey"]
	if accountID == "" || accessKey == "" || secretKey == "" {
		return nil, &dnsgo.Error{Provider: "bt", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "AccountID, AccessKey and SecretKey are required"}
	}
	base := strings.TrimRight(config.Endpoint, "/")
	if base == "" {
		base = "https://dmp.bt.cn"
	}
	return &baoTa{Base: dnsgo.Base{ProviderKind: "bt", Features: dnsgo.Capabilities{
		MinTTL: 300, Remarks: true, Status: true, Weight: true, CreateZone: true, Lines: true,
	}}, config: config, http: client(config), base: base, accountID: accountID, accessKey: accessKey, secretKey: secretKey}, nil
}

func (b *baoTa) request(ctx context.Context, path string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return &dnsgo.Error{Provider: b.Kind(), Operation: path, Code: dnsgo.CodeInvalidInput, Cause: err}
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signing := b.accountID + "\n" + timestamp + "\nPOST\n" + path + "\n" + string(body)
	mac := hmac.New(sha256.New, []byte(b.secretKey))
	_, _ = mac.Write([]byte(signing))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.base+path, bytes.NewReader(body))
	if err != nil {
		return &dnsgo.Error{Provider: b.Kind(), Operation: path, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Account-ID", b.accountID)
	req.Header.Set("X-Access-Key", b.accessKey)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", hex.EncodeToString(mac.Sum(nil)))
	response, err := b.http.Do(req)
	if err != nil {
		return &dnsgo.Error{Provider: b.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown, Message: "request failed"}
	}
	defer response.Body.Close()
	var envelope struct {
		Code int             `json:"code"`
		Msg  string          `json:"msg"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&envelope); err != nil {
		return &dnsgo.Error{Provider: b.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || envelope.Code != 0 {
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
		return &dnsgo.Error{Provider: b.Kind(), Operation: path, Code: code, VendorCode: strconv.Itoa(envelope.Code), Message: envelope.Msg}
	}
	if output != nil && len(envelope.Data) > 0 && string(envelope.Data) != "null" {
		if err := json.Unmarshal(envelope.Data, output); err != nil {
			return &dnsgo.Error{Provider: b.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}

func (b *baoTa) zone(zone string) (string, int, error) {
	if zone == "" {
		zone = b.config.DomainID
	}
	if zone == "" {
		return "", 0, &dnsgo.Error{Provider: b.Kind(), Operation: "zone", Code: dnsgo.CodeInvalidInput, Message: "domain ID is required"}
	}
	parts := strings.SplitN(zone, "|", 2)
	if _, err := strconv.ParseUint(parts[0], 10, 64); err != nil {
		return "", 0, &dnsgo.Error{Provider: b.Kind(), Operation: "zone", Code: dnsgo.CodeInvalidInput, Message: "invalid domain ID"}
	}
	typeID := 1
	if len(parts) == 2 {
		n, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", 0, &dnsgo.Error{Provider: b.Kind(), Operation: "zone", Code: dnsgo.CodeInvalidInput, Message: "invalid domain type"}
		}
		typeID = n
	}
	return parts[0], typeID, nil
}

func (b *baoTa) Check(ctx context.Context) error {
	_, err := b.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (b *baoTa) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	page, size := query.Page, query.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	input := map[string]any{"p": page, "rows": size, "keyword": query.Keyword}
	var result struct {
		Total int `json:"total"`
		Rows  []struct {
			ID    json.Number `json:"local_id"`
			Type  int         `json:"domain_type"`
			Name  string      `json:"full_domain"`
			Count int         `json:"record_count"`
		} `json:"data"`
	}
	if err := b.request(ctx, "/api/v1/dns/manage/list_domains", input, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(result.Rows))
	for _, row := range result.Rows {
		zones = append(zones, dnsgo.Zone{ID: row.ID.String() + "|" + strconv.Itoa(row.Type), Name: row.Name, RecordCount: row.Count})
	}
	return dnsgo.Page[dnsgo.Zone]{Total: result.Total, Items: zones}, nil
}

func (b *baoTa) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	var result struct {
		ID   json.Number `json:"domain_id"`
		Name string      `json:"full_domain"`
	}
	if err := b.request(ctx, "/api/v1/dns/manage/add_external_domain", map[string]any{"full_domain": name}, &result); err != nil {
		return dnsgo.Zone{}, err
	}
	return dnsgo.Zone{ID: result.ID.String() + "|1", Name: result.Name}, nil
}

func (b *baoTa) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	id, typeID, err := b.zone(zone)
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
	input := map[string]any{"domain_id": id, "domain_type": typeID, "p": page, "rows": size}
	for _, filter := range []struct{ key, value string }{{"record", query.Name}, {"record", query.Keyword}, {"value", query.Value},
		{"type", query.Type}, {"line", query.Line}} {
		if filter.value != "" {
			input["searchKey"], input["searchValue"] = filter.key, filter.value
			break
		}
	}
	if query.Enabled != nil {
		input["searchKey"] = "state"
		if *query.Enabled {
			input["searchValue"] = "0"
		} else {
			input["searchValue"] = "1"
		}
	}
	var result struct {
		Count int        `json:"count"`
		Rows  []btRecord `json:"data"`
	}
	if err := b.request(ctx, "/api/v1/dns/record/list", input, &result); err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	records := make([]dnsgo.Record, 0, len(result.Rows))
	for _, row := range result.Rows {
		enabled := row.State != 1
		record := dnsgo.Record{ID: row.ID.String(), ZoneID: id + "|" + strconv.Itoa(typeID), Name: row.Name, Type: row.Type,
			Value: row.Value, Line: row.Line.String(), TTL: row.TTL, Enabled: &enabled, Remark: row.Remark,
			ModifiedAt: row.CreatedAt}
		if row.Type == "MX" {
			record.Priority = row.MX
		} else {
			record.Weight = row.MX
		}
		if query.Name != "" && !strings.EqualFold(query.Name, record.Name) || query.Type != "" && query.Type != record.Type ||
			query.Value != "" && query.Value != record.Value || query.Line != "" && query.Line != record.Line ||
			query.Enabled != nil && *query.Enabled != enabled {
			continue
		}
		records = append(records, record)
	}
	return dnsgo.Page[dnsgo.Record]{Total: result.Count, Items: records}, nil
}

func (b *baoTa) GetRecord(ctx context.Context, zone, recordID string) (dnsgo.Record, error) {
	seen := 0
	for page := 1; page <= 10000; page++ {
		result, err := b.ListRecords(ctx, zone, dnsgo.RecordQuery{Page: page, PageSize: 100})
		if err != nil {
			return dnsgo.Record{}, err
		}
		for _, record := range result.Items {
			if record.ID == recordID {
				return record, nil
			}
		}
		seen += len(result.Items)
		if !morePages(result.Total, seen, len(result.Items), 100) {
			break
		}
		if page == 10000 {
			return dnsgo.Record{}, &dnsgo.Error{Provider: b.Kind(), Operation: "get_record", Code: dnsgo.CodeResultUnknown,
				Message: "record listing exceeded the page limit"}
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: b.Kind(), Operation: "get_record", Code: dnsgo.CodeNotFound}
}

func (b *baoTa) recordInput(zone string, typeID int, record dnsgo.Record, create bool) map[string]any {
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	line, _ := strconv.Atoi(record.Line)
	mx := uint16(1)
	if record.Type == "MX" {
		if record.Priority != nil {
			mx = *record.Priority
		}
	} else if record.Weight != nil && *record.Weight > 0 {
		mx = *record.Weight
	}
	input := map[string]any{"domain_id": zone, "domain_type": typeID, "type": record.Type,
		"record": record.Name, "value": record.Value, "ttl": ttl, "view_id": line, "remark": record.Remark, "mx": mx}
	if !create {
		input["record_id"] = record.ID
	}
	return input
}

func (b *baoTa) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(b.Kind(), b.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	id, typeID, err := b.zone(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	// This API returns only a success flag. Snapshot matching IDs so the
	// created record can be identified without guessing among duplicates.
	before := map[string]bool{}
	seen := 0
	for page := 1; page <= 10000; page++ {
		result, err := b.ListRecords(ctx, id+"|"+strconv.Itoa(typeID), dnsgo.RecordQuery{Page: page, PageSize: 100})
		if err != nil {
			return dnsgo.Record{}, err
		}
		for _, existing := range result.Items {
			before[existing.ID] = true
		}
		seen += len(result.Items)
		if !morePages(result.Total, seen, len(result.Items), 100) {
			break
		}
		if page == 10000 {
			return dnsgo.Record{}, &dnsgo.Error{Provider: b.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
				Message: "existing record listing exceeded the page limit"}
		}
	}
	if err := b.request(ctx, "/api/v1/dns/record/create", b.recordInput(id, typeID, record, true), nil); err != nil {
		return dnsgo.Record{}, err
	}
	seen = 0
	for page := 1; page <= 10000; page++ {
		result, err := b.ListRecords(ctx, id+"|"+strconv.Itoa(typeID), dnsgo.RecordQuery{Page: page, PageSize: 100})
		if err != nil {
			return dnsgo.Record{}, &dnsgo.Error{Provider: b.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
				Message: "record created but readback failed", Cause: err}
		}
		for _, created := range result.Items {
			if !before[created.ID] && strings.EqualFold(created.Name, record.Name) && created.Type == record.Type && created.Value == record.Value {
				return applyRequestedStatus(ctx, b, id+"|"+strconv.Itoa(typeID), created, record.Enabled, created.Enabled)
			}
		}
		seen += len(result.Items)
		if !morePages(result.Total, seen, len(result.Items), 100) {
			break
		}
		if page == 10000 {
			return dnsgo.Record{}, &dnsgo.Error{Provider: b.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
				Message: "record created but readback exceeded the page limit"}
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: b.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
		Message: "record was created but its ID could not be confirmed"}
}

func (b *baoTa) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(b.Kind(), b.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	id, typeID, err := b.zone(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: b.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "record ID is required"}
	}
	current, err := b.GetRecord(ctx, id+"|"+strconv.Itoa(typeID), record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	if err := b.request(ctx, "/api/v1/dns/record/update", b.recordInput(id, typeID, record, false), nil); err != nil {
		return dnsgo.Record{}, err
	}
	record.ZoneID = id + "|" + strconv.Itoa(typeID)
	return applyRequestedStatus(ctx, b, record.ZoneID, record, record.Enabled, current.Enabled)
}

func (b *baoTa) DeleteRecord(ctx context.Context, zone, recordID string) error {
	id, typeID, err := b.zone(zone)
	if err != nil {
		return err
	}
	return b.request(ctx, "/api/v1/dns/record/delete", map[string]any{"id": recordID, "domain_id": id, "domain_type": typeID}, nil)
}

func (b *baoTa) SetRecordStatus(ctx context.Context, zone, recordID string, enabled bool) error {
	id, typeID, err := b.zone(zone)
	if err != nil {
		return err
	}
	path := "/api/v1/dns/record/pause"
	if enabled {
		path = "/api/v1/dns/record/start"
	}
	return b.request(ctx, path, map[string]any{"record_id": recordID, "domain_id": id, "domain_type": typeID}, nil)
}

func (b *baoTa) RecordLines(ctx context.Context, zone string) ([]dnsgo.RecordLine, error) {
	var raw json.RawMessage
	if err := b.request(ctx, "/api/v1/dns/record/get_views", map[string]any{}, &raw); err != nil {
		return nil, err
	}
	lines := []dnsgo.RecordLine{}
	var visit func([]byte, string) error
	visit = func(raw []byte, parent string) error {
		var items []struct {
			ID       json.Number     `json:"viewId"`
			Name     string          `json:"name"`
			Free     json.RawMessage `json:"free"`
			Children json.RawMessage `json:"children"`
		}
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		for _, row := range items {
			if string(row.Free) != "true" && string(row.Free) != "1" && string(row.Free) != "\"1\"" {
				continue
			}
			lines = append(lines, dnsgo.RecordLine{Code: row.ID.String(), Name: row.Name, Parent: parent})
			if len(row.Children) > 0 && string(row.Children) != "null" {
				if err := visit(row.Children, row.ID.String()); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(raw, ""); err != nil {
		return nil, err
	}
	return lines, nil
}

func (b *baoTa) MinTTL(context.Context, string) (int, error) { return 300, nil }

var _ dnsgo.Provider = (*baoTa)(nil)
