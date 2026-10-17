package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rainchen537/dnsgo"
)

type goEdge struct {
	dnsgo.Base
	config      dnsgo.Config
	http        *http.Client
	base        string
	keyID, key  string
	userType    string
	clusterID   int64
	userID      int64
	mu          sync.Mutex
	accessToken string
}

type edgeRecord struct {
	ID          jsonScalar `json:"id"`
	Name        string     `json:"name"`
	Type        string     `json:"type"`
	Value       string     `json:"value"`
	TTL         int        `json:"ttl"`
	MX          uint16     `json:"mxPriority"`
	Weight      uint16     `json:"weight"`
	Description string     `json:"description"`
	IsOn        bool       `json:"isOn"`
	CreatedAt   int64      `json:"createdAt"`
	Routes      []struct {
		Code string `json:"code"`
		Name string `json:"name"`
	} `json:"nsRoutes"`
}

func init() { register("goedge", newGoEdge) }

func newGoEdge(config dnsgo.Config) (dnsgo.Provider, error) {
	base := strings.TrimRight(config.Endpoint, "/")
	if base == "" {
		base = strings.TrimRight(config.Credentials["base_url"], "/")
	}
	id, key := config.Credentials["accessKeyId"], config.Credentials["accessKey"]
	userType := strings.ToLower(config.Credentials["type"])
	if userType == "" {
		userType = strings.ToLower(config.Credentials["usertype"])
	}
	if userType == "" {
		userType = "admin"
	}
	cluster, _ := strconv.ParseInt(config.Credentials["nsClusterId"], 10, 64)
	userID, _ := strconv.ParseInt(config.Credentials["userId"], 10, 64)
	if base == "" || id == "" || key == "" || cluster <= 0 || userType != "admin" && userType != "user" {
		return nil, &dnsgo.Error{Provider: "goedge", Operation: "new", Code: dnsgo.CodeInvalidInput,
			Message: "base URL, accessKeyId, accessKey, positive nsClusterId and admin/user type are required"}
	}
	return &goEdge{Base: dnsgo.Base{ProviderKind: "goedge", Features: dnsgo.Capabilities{
		MinTTL: 1, Remarks: true, Status: true, Weight: true, CreateZone: true, Lines: true,
	}}, config: config, http: client(config), base: base, keyID: id, key: key,
		userType: userType, clusterID: cluster, userID: userID}, nil
}

func (e *goEdge) post(ctx context.Context, path string, input, output any, token string) error {
	if input == nil {
		input = struct{}{}
	}
	body, err := json.Marshal(input)
	if err != nil {
		return &dnsgo.Error{Provider: e.Kind(), Operation: path, Code: dnsgo.CodeInvalidInput, Cause: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+path, bytes.NewReader(body))
	if err != nil {
		return &dnsgo.Error{Provider: e.Kind(), Operation: path, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Edge-Access-Token", token)
	}
	response, err := e.http.Do(req)
	if err != nil {
		return &dnsgo.Error{Provider: e.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown, Message: "request failed"}
	}
	defer response.Body.Close()
	var envelope struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&envelope); err != nil {
		return &dnsgo.Error{Provider: e.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response"}
	}
	if response.StatusCode != 200 || envelope.Code != 200 {
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
		return &dnsgo.Error{Provider: e.Kind(), Operation: path, Code: code,
			VendorCode: strconv.Itoa(envelope.Code), Message: envelope.Message}
	}
	if output != nil && len(envelope.Data) > 0 && string(envelope.Data) != "null" {
		if err := json.Unmarshal(envelope.Data, output); err != nil {
			return &dnsgo.Error{Provider: e.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}

func (e *goEdge) token(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.accessToken != "" {
		return e.accessToken, nil
	}
	var result struct {
		Token string `json:"token"`
	}
	input := map[string]string{"type": e.userType, "accessKeyId": e.keyID, "accessKey": e.key}
	if err := e.post(ctx, "/APIAccessTokenService/getAPIAccessToken", input, &result, ""); err != nil {
		return "", err
	}
	if result.Token == "" {
		return "", &dnsgo.Error{Provider: e.Kind(), Operation: "get_access_token", Code: dnsgo.CodeResultUnknown, Message: "empty access token"}
	}
	e.accessToken = result.Token
	return result.Token, nil
}

func (e *goEdge) request(ctx context.Context, path string, input, output any) error {
	token, err := e.token(ctx)
	if err != nil {
		return err
	}
	return e.post(ctx, path, input, output, token)
}

func (e *goEdge) zoneID(zone string) (int64, error) {
	if zone == "" {
		zone = e.config.DomainID
	}
	id, err := strconv.ParseInt(zone, 10, 64)
	if err != nil || id <= 0 {
		return 0, &dnsgo.Error{Provider: e.Kind(), Operation: "zone_id", Code: dnsgo.CodeInvalidInput, Message: "numeric domain ID is required"}
	}
	return id, nil
}

func (e *goEdge) domainQuery(keyword string) map[string]any {
	query := map[string]any{"nsClusterId": e.clusterID}
	if keyword != "" {
		query["keyword"] = keyword
	}
	if e.userType == "admin" && e.userID > 0 {
		query["userId"] = e.userID
	}
	return query
}

func (e *goEdge) Check(ctx context.Context) error {
	var result struct {
		Cluster json.RawMessage `json:"nsCluster"`
	}
	if err := e.request(ctx, "/NSClusterService/findNSCluster", map[string]any{"nsClusterId": e.clusterID}, &result); err != nil {
		return err
	}
	if len(result.Cluster) == 0 || string(result.Cluster) == "null" {
		return &dnsgo.Error{Provider: e.Kind(), Operation: "check", Code: dnsgo.CodeNotFound, Message: "DNS cluster not found"}
	}
	return nil
}

func (e *goEdge) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	base := e.domainQuery(query.Keyword)
	var count struct {
		Count int `json:"count"`
	}
	if err := e.request(ctx, "/NSDomainService/countAllNSDomains", base, &count); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	offset, size := offsetPage(query.Page, query.PageSize)
	base["offset"], base["size"] = offset, size
	var result struct {
		Domains []struct {
			ID   jsonScalar `json:"id"`
			Name string     `json:"name"`
		} `json:"nsDomains"`
	}
	if err := e.request(ctx, "/NSDomainService/listNSDomains", base, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(result.Domains))
	for _, row := range result.Domains {
		zones = append(zones, dnsgo.Zone{ID: row.ID.String(), Name: row.Name})
	}
	return dnsgo.Page[dnsgo.Zone]{Total: count.Count, Items: zones}, nil
}

func (e *goEdge) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	input := e.domainQuery("")
	input["name"] = strings.TrimSuffix(name, ".")
	var result struct {
		ID jsonScalar `json:"nsDomainId"`
	}
	if err := e.request(ctx, "/NSDomainService/createNSDomain", input, &result); err != nil {
		return dnsgo.Zone{}, err
	}
	return dnsgo.Zone{ID: result.ID.String(), Name: name}, nil
}

func edgeRoutes(line string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range strings.Split(line, ",") {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	if len(result) == 0 {
		return []string{"default"}
	}
	return result
}

func (e *goEdge) toRecord(zone string, row edgeRecord) dnsgo.Record {
	lines := []string{}
	for _, route := range row.Routes {
		if route.Code != "" {
			lines = append(lines, route.Code)
		}
	}
	line := strings.Join(lines, ",")
	if line == "" {
		line = "default"
	}
	enabled := row.IsOn
	mx, weight := row.MX, row.Weight
	modified := ""
	if row.CreatedAt != 0 {
		modified = time.Unix(row.CreatedAt, 0).UTC().Format(time.RFC3339)
	}
	return dnsgo.Record{ID: row.ID.String(), ZoneID: zone, Name: row.Name, Type: row.Type,
		Value: row.Value, Line: line, TTL: row.TTL, Priority: &mx, Weight: &weight,
		Enabled: &enabled, Remark: row.Description, ModifiedAt: modified}
}

func (e *goEdge) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	id, err := e.zoneID(zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	all := []dnsgo.Record{}
	for offset := 0; ; {
		input := map[string]any{"nsDomainId": id, "offset": offset, "size": 1000}
		if query.Keyword != "" {
			input["keyword"] = query.Keyword
		}
		if query.Type != "" {
			input["type"] = query.Type
		}
		if query.Line != "" {
			input["nsRouteCode"] = edgeRoutes(query.Line)[0]
		}
		var result struct {
			Records []edgeRecord `json:"nsRecords"`
		}
		if err := e.request(ctx, "/NSRecordService/listNSRecords", input, &result); err != nil {
			return dnsgo.Page[dnsgo.Record]{}, err
		}
		for _, row := range result.Records {
			record := e.toRecord(strconv.FormatInt(id, 10), row)
			if query.Name != "" && !strings.EqualFold(query.Name, record.Name) ||
				query.Value != "" && !strings.Contains(strings.ToLower(record.Value), strings.ToLower(query.Value)) ||
				query.Enabled != nil && *query.Enabled != *record.Enabled {
				continue
			}
			all = append(all, record)
		}
		offset += len(result.Records)
		if len(result.Records) < 1000 {
			break
		}
	}
	total := len(all)
	start, size := offsetPage(query.Page, query.PageSize)
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	return dnsgo.Page[dnsgo.Record]{Total: total, Items: all[start:end]}, nil
}

func (e *goEdge) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	zoneID, err := e.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	recordID, err := strconv.ParseInt(id, 10, 64)
	if err != nil || recordID <= 0 {
		return dnsgo.Record{}, &dnsgo.Error{Provider: e.Kind(), Operation: "get_record", Code: dnsgo.CodeInvalidInput, Message: "numeric record ID is required"}
	}
	var result struct {
		Record edgeRecord `json:"nsRecord"`
	}
	if err := e.request(ctx, "/NSRecordService/findNSRecord", map[string]any{"nsRecordId": recordID}, &result); err != nil {
		return dnsgo.Record{}, err
	}
	if result.Record.ID == "" {
		return dnsgo.Record{}, &dnsgo.Error{Provider: e.Kind(), Operation: "get_record", Code: dnsgo.CodeNotFound}
	}
	return e.toRecord(strconv.FormatInt(zoneID, 10), result.Record), nil
}

func (e *goEdge) recordPayload(zoneID int64, record dnsgo.Record, recordID int64, enabled bool) map[string]any {
	ttl := record.TTL
	if ttl < 1 {
		ttl = 600
	}
	weight, mx := uint16(0), uint16(0)
	if record.Weight != nil {
		weight = *record.Weight
	}
	if record.Type == "MX" && record.Priority != nil {
		mx = *record.Priority
	}
	input := map[string]any{"nsDomainId": zoneID, "name": record.Name, "type": record.Type,
		"value": record.Value, "ttl": ttl, "nsRouteCodes": edgeRoutes(record.Line),
		"weight": weight, "mxPriority": mx, "description": record.Remark}
	if recordID > 0 {
		input["nsRecordId"] = recordID
		input["isOn"] = enabled
	}
	return input
}

func (e *goEdge) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(e.Kind(), e.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	id, err := e.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var result struct {
		ID jsonScalar `json:"nsRecordId"`
	}
	enabled := true
	if record.Enabled != nil {
		enabled = *record.Enabled
	}
	if err := e.request(ctx, "/NSRecordService/createNSRecord", e.recordPayload(id, record, 0, enabled), &result); err != nil {
		return dnsgo.Record{}, err
	}
	record.ID, record.ZoneID = result.ID.String(), strconv.FormatInt(id, 10)
	if record.ID == "" {
		return record, &dnsgo.Error{Provider: e.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
			Message: "record created but provider returned no ID"}
	}
	wanted := record.Enabled
	record.Enabled = &enabled
	return applyRequestedStatus(ctx, e, record.ZoneID, record, wanted, nil)
}

func (e *goEdge) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(e.Kind(), e.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	id, err := e.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	recordID, err := strconv.ParseInt(record.ID, 10, 64)
	if err != nil || recordID <= 0 {
		return dnsgo.Record{}, &dnsgo.Error{Provider: e.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "numeric record ID is required"}
	}
	current, err := e.GetRecord(ctx, zone, record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	enabled := *current.Enabled
	if record.Enabled != nil {
		enabled = *record.Enabled
	}
	if err := e.request(ctx, "/NSRecordService/updateNSRecord", e.recordPayload(id, record, recordID, enabled), nil); err != nil {
		return dnsgo.Record{}, err
	}
	record.ZoneID = strconv.FormatInt(id, 10)
	record.Enabled = &enabled
	return record, nil
}

func (e *goEdge) DeleteRecord(ctx context.Context, zone, id string) error {
	if _, err := e.zoneID(zone); err != nil {
		return err
	}
	recordID, err := strconv.ParseInt(id, 10, 64)
	if err != nil || recordID <= 0 {
		return &dnsgo.Error{Provider: e.Kind(), Operation: "delete_record", Code: dnsgo.CodeInvalidInput, Message: "numeric record ID is required"}
	}
	return e.request(ctx, "/NSRecordService/deleteNSRecord", map[string]any{"nsRecordId": recordID}, nil)
}

func (e *goEdge) updateRecordFields(ctx context.Context, zone, id string, changes map[string]any) error {
	zoneID, err := e.zoneID(zone)
	if err != nil {
		return err
	}
	current, err := e.GetRecord(ctx, zone, id)
	if err != nil {
		return err
	}
	recordID, _ := strconv.ParseInt(id, 10, 64)
	input := e.recordPayload(zoneID, current, recordID, *current.Enabled)
	for key, value := range changes {
		input[key] = value
	}
	return e.request(ctx, "/NSRecordService/updateNSRecord", input, nil)
}

func (e *goEdge) SetRecordRemark(ctx context.Context, zone, id, remark string) error {
	return e.updateRecordFields(ctx, zone, id, map[string]any{"description": remark})
}

func (e *goEdge) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	return e.updateRecordFields(ctx, zone, id, map[string]any{"isOn": enabled})
}

func (e *goEdge) RecordLines(ctx context.Context, zone string) ([]dnsgo.RecordLine, error) {
	paths := []string{"/NSRouteService/findAllDefaultWorldRegionRoutes", "/NSRouteService/findAllDefaultChinaProvinceRoutes",
		"/NSRouteService/findAllDefaultISPRoutes", "/NSRouteService/findAllAgentNSRoutes"}
	if zone != "" || e.config.DomainID != "" {
		paths = append(paths, "/NSRouteService/findAllNSRoutes")
	}
	lines := []dnsgo.RecordLine{{Code: "default", Name: "默认线路"}}
	seen := map[string]bool{"default": true}
	for _, path := range paths {
		var result struct {
			Routes []struct {
				Code   string `json:"code"`
				Name   string `json:"name"`
				Parent string `json:"parent"`
			} `json:"nsRoutes"`
		}
		if err := e.request(ctx, path, map[string]any{}, &result); err != nil {
			return nil, err
		}
		for _, row := range result.Routes {
			if row.Code == "" || seen[row.Code] {
				continue
			}
			seen[row.Code] = true
			name := row.Name
			if name == "" {
				name = row.Code
			}
			lines = append(lines, dnsgo.RecordLine{Code: row.Code, Name: name, Parent: row.Parent})
		}
	}
	for i := range lines {
		if lines[i].Parent != "" {
			continue
		}
		parts := strings.Split(lines[i].Code, ":")
		for len(parts) > 1 {
			parts = parts[:len(parts)-1]
			parent := strings.Join(parts, ":")
			if seen[parent] {
				lines[i].Parent = parent
				break
			}
		}
	}
	return lines, nil
}

func (e *goEdge) MinTTL(context.Context, string) (int, error) { return 1, nil }

var _ dnsgo.Provider = (*goEdge)(nil)
