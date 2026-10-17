package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/internal/qingcloud"
)

type qingCloud struct {
	dnsgo.Base
	config dnsgo.Config
	api    qingcloud.Client
}

type qingValue struct {
	ID     jsonScalar `json:"record_value_id"`
	Value  string     `json:"value"`
	Status int        `json:"status"`
}

type qingGroup struct {
	Weight int         `json:"weight"`
	Data   []qingValue `json:"data"`
}

type qingSet struct {
	ID         jsonScalar  `json:"domain_record_id"`
	DomainName string      `json:"domain_name"`
	ZoneName   string      `json:"zone_name"`
	Type       string      `json:"rd_type"`
	Mode       int         `json:"mode"`
	ViewID     jsonScalar  `json:"view_id"`
	TTL        int         `json:"ttl"`
	CreatedAt  string      `json:"create_time"`
	Groups     []qingGroup `json:"record"`
}

func init() { register("qingcloud", newQingCloud) }

func newQingCloud(config dnsgo.Config) (dnsgo.Provider, error) {
	id := config.Credentials["access_key_id"]
	secret := config.Credentials["secret_access_key"]
	if id == "" || secret == "" {
		return nil, &dnsgo.Error{Provider: "qingcloud", Operation: "new", Code: dnsgo.CodeInvalidInput,
			Message: "access_key_id and secret_access_key are required"}
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = "https://api.routewize.com"
	}
	return &qingCloud{Base: dnsgo.Base{ProviderKind: "qingcloud", Features: dnsgo.Capabilities{
		MinTTL: 60, Status: true, Weight: true, CreateZone: true, Lines: true,
	}}, config: config, api: qingcloud.Client{KeyID: id, Secret: secret, Endpoint: endpoint, HTTP: client(config)}}, nil
}

func (q *qingCloud) zone(zone string) (string, error) {
	if zone == "" {
		zone = q.config.DomainID
	}
	if zone == "" {
		zone = q.config.Domain
	}
	zone = strings.TrimSpace(zone)
	if zone == "" {
		return "", &dnsgo.Error{Provider: q.Kind(), Operation: "zone", Code: dnsgo.CodeInvalidInput, Message: "zone name is required"}
	}
	return zone, nil
}

func (q *qingCloud) fqdn(zone, name string) string {
	zone = strings.TrimSuffix(zone, ".")
	if name == "" || name == "@" || name == zone {
		return zone + "."
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	if strings.HasSuffix(name, "."+zone) {
		return name + "."
	}
	return name + "." + zone + "."
}

func (q *qingCloud) Check(ctx context.Context) error {
	_, err := q.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (q *qingCloud) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	offset, size := offsetPage(query.Page, query.PageSize)
	params := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(size)}}
	if query.Keyword != "" {
		params.Set("zone_name", query.Keyword)
	}
	var result struct {
		Total int `json:"total_count"`
		Zones []struct {
			Name string `json:"zone_name"`
		} `json:"zones"`
	}
	if err := q.api.Call(ctx, http.MethodGet, "/v1/user/zones", params, nil, &result); err != nil {
		return dnsgo.Page[dnsgo.Zone]{}, err
	}
	zones := make([]dnsgo.Zone, 0, len(result.Zones))
	for _, row := range result.Zones {
		zones = append(zones, dnsgo.Zone{ID: row.Name, Name: strings.TrimSuffix(row.Name, ".")})
	}
	return dnsgo.Page[dnsgo.Zone]{Total: result.Total, Items: zones}, nil
}

func (q *qingCloud) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	var result struct {
		Name string `json:"zone_name"`
	}
	if err := q.api.Call(ctx, http.MethodPost, "/v1/zone/", nil, map[string]string{"zone_name": name}, &result); err != nil {
		return dnsgo.Zone{}, err
	}
	if result.Name == "" {
		result.Name = name
	}
	return dnsgo.Zone{ID: result.Name, Name: strings.TrimSuffix(result.Name, ".")}, nil
}

func qingRecordID(setID, valueID string) string { return setID + "_" + valueID }

func qingSplitID(id string) (string, string, error) {
	parts := strings.SplitN(id, "_", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", &dnsgo.Error{Provider: "qingcloud", Operation: "record_id", Code: dnsgo.CodeInvalidInput, Message: "invalid record ID"}
	}
	return parts[0], parts[1], nil
}

func qingRelative(zone, name string) string {
	zone = strings.TrimSuffix(zone, ".")
	name = strings.TrimSuffix(name, ".")
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}

func (q *qingCloud) flatten(zone string, set qingSet) []dnsgo.Record {
	records := []dnsgo.Record{}
	for _, group := range set.Groups {
		for _, value := range group.Data {
			display := value.Value
			var priority *uint16
			if set.Type == "MX" {
				parts := strings.SplitN(display, " ", 2)
				if len(parts) == 2 {
					if n, err := strconv.ParseUint(parts[0], 10, 16); err == nil {
						p := uint16(n)
						priority = &p
						display = parts[1]
					}
				}
			} else if set.Type == "TXT" {
				display = strings.Trim(display, "\"")
			}
			enabled := value.Status == 1
			var weight *uint16
			if group.Weight > 0 {
				w := uint16(group.Weight)
				weight = &w
			}
			records = append(records, dnsgo.Record{ID: qingRecordID(set.ID.String(), value.ID.String()), ZoneID: zone,
				Name: qingRelative(zone, set.DomainName), Type: set.Type, Value: display, Line: set.ViewID.String(),
				TTL: set.TTL, Priority: priority, Weight: weight, Enabled: &enabled, ModifiedAt: set.CreatedAt,
				Extra: map[string]any{"mode": set.Mode}})
		}
	}
	return records
}

func (q *qingCloud) hostInfo(ctx context.Context, zone, host string) ([]qingSet, error) {
	var result struct {
		Records []qingSet `json:"records"`
	}
	params := url.Values{"zone_name": {zone}, "domain_name": {host}}
	err := q.api.Call(ctx, http.MethodGet, "/v1/dns/host_info/", params, nil, &result)
	return result.Records, err
}

func (q *qingCloud) hostNames(ctx context.Context, zone string) ([]string, error) {
	names := []string{}
	for offset := 0; ; {
		params := url.Values{"zone_name": {zone}, "offset": {strconv.Itoa(offset)}, "limit": {"100"}}
		var result struct {
			Total   int `json:"total_count"`
			Domains []struct {
				Name string `json:"domain_name"`
			} `json:"domains"`
		}
		if err := q.api.Call(ctx, http.MethodGet, "/v1/dns/host/", params, nil, &result); err != nil {
			return nil, err
		}
		for _, row := range result.Domains {
			names = append(names, row.Name)
		}
		offset += len(result.Domains)
		if len(result.Domains) == 0 || offset >= result.Total {
			break
		}
	}
	return names, nil
}

func (q *qingCloud) ListHosts(ctx context.Context, zone string, query dnsgo.ZoneQuery) (dnsgo.Page[QingCloudHost], error) {
	zone, err := q.zone(zone)
	if err != nil {
		return dnsgo.Page[QingCloudHost]{}, err
	}
	offset, size := offsetPage(query.Page, query.PageSize)
	if size > 100 {
		size = 100
		offset = (query.Page - 1) * size
		if query.Page < 1 {
			offset = 0
		}
	}
	params := url.Values{"zone_name": {zone}, "offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(size)}}
	if query.Keyword != "" {
		params.Set("search_word", query.Keyword)
	}
	var result struct {
		Total   int `json:"total_count"`
		Domains []struct {
			Name        string `json:"domain_name"`
			Status      string `json:"status"`
			Description string `json:"description"`
			Count       int    `json:"count"`
			CreatedAt   string `json:"create_time"`
		} `json:"domains"`
	}
	if err := q.api.Call(ctx, http.MethodGet, "/v1/dns/host/", params, nil, &result); err != nil {
		return dnsgo.Page[QingCloudHost]{}, err
	}
	page := dnsgo.Page[QingCloudHost]{Total: result.Total, Items: make([]QingCloudHost, 0, len(result.Domains))}
	for _, host := range result.Domains {
		page.Items = append(page.Items, QingCloudHost{ID: host.Name, Name: qingRelative(zone, host.Name),
			Status: host.Status, Remark: host.Description, Count: host.Count, CreatedAt: host.CreatedAt})
	}
	return page, nil
}

func (q *qingCloud) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	zone, err := q.zone(zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	names := []string{}
	if query.Name != "" {
		names = []string{q.fqdn(zone, query.Name)}
	} else {
		names, err = q.hostNames(ctx, zone)
		if err != nil {
			return dnsgo.Page[dnsgo.Record]{}, err
		}
	}
	matched := []dnsgo.Record{}
	for _, name := range names {
		sets, err := q.hostInfo(ctx, zone, name)
		if err != nil {
			return dnsgo.Page[dnsgo.Record]{}, err
		}
		for _, set := range sets {
			for _, record := range q.flatten(zone, set) {
				if query.Name != "" && !strings.EqualFold(record.Name, query.Name) || query.Type != "" && record.Type != query.Type ||
					query.Value != "" && record.Value != query.Value || query.Keyword != "" && !strings.Contains(record.Name, query.Keyword) && !strings.Contains(record.Value, query.Keyword) ||
					query.Line != "" && record.Line != query.Line || query.Enabled != nil && *query.Enabled != *record.Enabled {
					continue
				}
				matched = append(matched, record)
			}
		}
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

func (q *qingCloud) getSet(ctx context.Context, setID string) (qingSet, error) {
	var result struct {
		Data qingSet `json:"data"`
	}
	if err := q.api.Call(ctx, http.MethodGet, "/v1/dr_id/"+url.PathEscape(setID), nil, nil, &result); err != nil {
		return qingSet{}, err
	}
	if result.Data.ID == "" {
		return qingSet{}, &dnsgo.Error{Provider: q.Kind(), Operation: "get_record_set", Code: dnsgo.CodeNotFound}
	}
	return result.Data, nil
}

func (q *qingCloud) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	zone, err := q.zone(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	setID, valueID, err := qingSplitID(id)
	if err != nil {
		return dnsgo.Record{}, err
	}
	set, err := q.getSet(ctx, setID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	for _, record := range q.flatten(zone, set) {
		if record.ID == qingRecordID(setID, valueID) {
			return record, nil
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: q.Kind(), Operation: "get_record", Code: dnsgo.CodeNotFound}
}

func qingMode(record dnsgo.Record, fallback int) int {
	if record.Extra != nil {
		if value, ok := record.Extra["mode"].(int); ok && value > 0 {
			return value
		}
	}
	if fallback > 0 {
		return fallback
	}
	return 1
}

func qingRawValue(record dnsgo.Record) string {
	value := record.Value
	if record.Type == "MX" {
		priority := uint16(1)
		if record.Priority != nil {
			priority = *record.Priority
		}
		value = strconv.Itoa(int(priority)) + " " + value
	} else if record.Type == "TXT" && !strings.HasPrefix(value, "\"") {
		value = strconv.Quote(value)
	}
	return value
}

func qingGroupPayload(groups []qingGroup, targetID, replacement string, weight int, remove bool) ([]map[string]any, bool) {
	result := []map[string]any{}
	found := false
	for _, group := range groups {
		values := []map[string]any{}
		groupWeight := group.Weight
		for _, value := range group.Data {
			if value.ID.String() == targetID {
				found = true
				groupWeight = weight
				if remove {
					continue
				}
				values = append(values, map[string]any{"value": replacement, "status": value.Status})
			} else {
				values = append(values, map[string]any{"value": value.Value, "status": value.Status})
			}
		}
		if len(values) > 0 {
			result = append(result, map[string]any{"weight": groupWeight, "values": values})
		}
	}
	return result, found
}

func (q *qingCloud) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(q.Kind(), q.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := q.zone(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	before := map[string]bool{}
	if sets, err := q.hostInfo(ctx, zone, q.fqdn(zone, record.Name)); err == nil {
		for _, set := range sets {
			for _, existing := range q.flatten(zone, set) {
				before[existing.ID] = true
			}
		}
	}
	line := 0
	if record.Line != "" && record.Line != "default" {
		line, err = strconv.Atoi(record.Line)
		if err != nil {
			return dnsgo.Record{}, &dnsgo.Error{Provider: q.Kind(), Operation: "create_record", Code: dnsgo.CodeInvalidInput, Message: "numeric line ID is required"}
		}
	}
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	mode := qingMode(record, 1)
	if err := qingWeightAllowed(record, mode); err != nil {
		return dnsgo.Record{}, err
	}
	weight := 0
	if (record.Type == "A" || record.Type == "CNAME") && mode == 3 && record.Weight != nil {
		weight = int(*record.Weight)
	}
	values := []string{qingRawValue(record)}
	if len(record.Values) > 0 {
		values = append([]string(nil), record.Values...)
	}
	items := make([]map[string]any, 0, len(values))
	for _, value := range values {
		items = append(items, map[string]any{"value": value, "status": 1})
	}
	encoded, _ := json.Marshal([]map[string]any{{"weight": weight, "values": items}})
	input := map[string]any{"zone_name": zone, "domain_name": record.Name, "view_id": line,
		"type": record.Type, "ttl": ttl, "record": string(encoded), "mode": mode, "auto_merge": 2}
	var result struct {
		SetID jsonScalar `json:"domain_record_id"`
	}
	if err := q.api.Call(ctx, http.MethodPost, "/v1/record/", nil, input, &result); err != nil {
		return dnsgo.Record{}, err
	}
	sets, err := q.hostInfo(ctx, zone, q.fqdn(zone, record.Name))
	if err != nil {
		return dnsgo.Record{ZoneID: zone, Name: record.Name, Type: record.Type,
				Extra: map[string]any{"set_id": result.SetID.String()}}, &dnsgo.Error{Provider: q.Kind(),
				Operation: "create_record", Code: dnsgo.CodeResultUnknown,
				Message: "record was created but readback failed", Cause: err}
	}
	for _, set := range sets {
		if result.SetID != "" && set.ID != result.SetID {
			continue
		}
		for _, created := range q.flatten(zone, set) {
			if !before[created.ID] && created.Type == record.Type && created.Value == record.Value {
				if record.Enabled != nil && !*record.Enabled {
					if err := q.SetRecordStatus(ctx, zone, created.ID, false); err != nil {
						return created, &dnsgo.Error{Provider: q.Kind(), Operation: "create_record",
							Code: dnsgo.CodeResultUnknown, Message: "record created but status update failed", Cause: err}
					}
					created.Enabled = record.Enabled
				}
				return created, nil
			}
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: q.Kind(), Operation: "create_record", Code: dnsgo.CodeResultUnknown,
		Message: "record was created but its value ID could not be confirmed"}
}

func (q *qingCloud) updateSet(ctx context.Context, zone string, set qingSet, name, kind string, ttl, mode, line int, groups []map[string]any) error {
	encoded, err := json.Marshal(groups)
	if err != nil {
		return err
	}
	input := map[string]any{"zone_name": zone, "domain_name": name, "view_id": line,
		"type": kind, "ttl": ttl, "record": string(encoded), "mode": mode}
	return q.api.Call(ctx, http.MethodPost, "/v1/dr_id/"+url.PathEscape(set.ID.String()), nil, input, nil)
}

func (q *qingCloud) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(q.Kind(), q.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zone, err := q.zone(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	setID, valueID, err := qingSplitID(record.ID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	set, err := q.getSet(ctx, setID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	var oldEnabled *bool
	for _, group := range set.Groups {
		for _, value := range group.Data {
			if value.ID.String() == valueID {
				status := value.Status == 1
				oldEnabled = &status
			}
		}
	}
	mode := qingMode(record, set.Mode)
	if err := qingWeightAllowed(record, mode); err != nil {
		return dnsgo.Record{}, err
	}
	weight := 0
	if (record.Type == "A" || record.Type == "CNAME") && mode == 3 && record.Weight != nil {
		weight = int(*record.Weight)
	}
	groups, found := qingGroupPayload(set.Groups, valueID, qingRawValue(record), weight, false)
	if !found {
		return dnsgo.Record{}, &dnsgo.Error{Provider: q.Kind(), Operation: "update_record", Code: dnsgo.CodeNotFound}
	}
	ttl := record.TTL
	if ttl <= 0 {
		ttl = set.TTL
	}
	line := 0
	if record.Line != "" && record.Line != "default" {
		line, err = strconv.Atoi(record.Line)
		if err != nil {
			return dnsgo.Record{}, &dnsgo.Error{Provider: q.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "numeric line ID is required"}
		}
	}
	if err := q.updateSet(ctx, zone, set, record.Name, record.Type, ttl, mode, line, groups); err != nil {
		return dnsgo.Record{}, err
	}
	record.ZoneID = zone
	if record.Enabled != nil && oldEnabled != nil && *record.Enabled != *oldEnabled {
		if err := q.SetRecordStatus(ctx, zone, record.ID, *record.Enabled); err != nil {
			return record, &dnsgo.Error{Provider: q.Kind(), Operation: "update_record",
				Code: dnsgo.CodeResultUnknown, Message: "record updated but status update failed", Cause: err}
		}
	}
	return record, nil
}

func qingWeightAllowed(record dnsgo.Record, mode int) error {
	if record.Weight == nil || (record.Type == "A" || record.Type == "CNAME") && mode == 3 {
		return nil
	}
	return &dnsgo.Error{Provider: "qingcloud", Operation: "write_record", Code: dnsgo.CodeUnsupported,
		Message: "weight requires an A or CNAME record in weighted mode"}
}

func (q *qingCloud) SetRecordRemark(context.Context, string, string, string) error {
	return dnsgo.Unsupported(q.Kind(), "set_record_remark")
}

// SetHostRemark changes the QingCloud host-level description, which affects
// all values under that host. Callers must opt into this broader scope.
func (q *qingCloud) SetHostRemark(ctx context.Context, zone, host, remark string) error {
	zone, err := q.zone(zone)
	if err != nil {
		return err
	}
	if host == "" {
		return &dnsgo.Error{Provider: q.Kind(), Operation: "set_host_remark", Code: dnsgo.CodeInvalidInput,
			Message: "host name is required"}
	}
	return q.api.Call(ctx, http.MethodPost, "/v1/dns/host/", nil,
		map[string]any{"zone_name": zone, "domain_name": q.fqdn(zone, host), "description": remark}, nil)
}

func (q *qingCloud) DeleteHost(ctx context.Context, zone, host string) error {
	zone, err := q.zone(zone)
	if err != nil {
		return err
	}
	if strings.TrimSpace(host) == "" {
		return &dnsgo.Error{Provider: q.Kind(), Operation: "delete_host", Code: dnsgo.CodeInvalidInput,
			Message: "host name is required"}
	}
	fullName := q.fqdn(zone, host)
	zoneName := strings.ToLower(strings.TrimSuffix(zone, "."))
	name := strings.ToLower(strings.TrimSuffix(fullName, "."))
	if name != zoneName && !strings.HasSuffix(name, "."+zoneName) {
		return &dnsgo.Error{Provider: q.Kind(), Operation: "delete_host", Code: dnsgo.CodeConflict,
			Message: "host does not belong to the configured zone"}
	}
	encoded, _ := json.Marshal([]string{fullName})
	return q.api.Call(ctx, http.MethodDelete, "/v1/domain/", nil,
		map[string]string{"zone_name": zone, "domain_names": string(encoded)}, nil)
}

func (q *qingCloud) DeleteRecord(ctx context.Context, zone, id string) error {
	zone, err := q.zone(zone)
	if err != nil {
		return err
	}
	setID, valueID, err := qingSplitID(id)
	if err != nil {
		return err
	}
	set, err := q.getSet(ctx, setID)
	if err != nil {
		return err
	}
	groups, found := qingGroupPayload(set.Groups, valueID, "", 0, true)
	if !found {
		return &dnsgo.Error{Provider: q.Kind(), Operation: "delete_record", Code: dnsgo.CodeNotFound}
	}
	if len(groups) == 0 {
		ids, _ := json.Marshal([]string{setID})
		return q.api.Call(ctx, http.MethodPost, "/v1/change_record_status/", nil,
			map[string]any{"ids": string(ids), "target": "record", "action": "delete"}, nil)
	}
	line, _ := strconv.Atoi(set.ViewID.String())
	return q.updateSet(ctx, zone, set, qingRelative(zone, set.DomainName), set.Type, set.TTL, set.Mode, line, groups)
}

func (q *qingCloud) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	if _, err := q.zone(zone); err != nil {
		return err
	}
	_, valueID, err := qingSplitID(id)
	if err != nil {
		return err
	}
	ids, _ := json.Marshal([]string{valueID})
	action := "stop"
	if enabled {
		action = "enable"
	}
	return q.api.Call(ctx, http.MethodPost, "/v1/change_record_status/", nil,
		map[string]any{"ids": string(ids), "target": "value", "action": action}, nil)
}

func (q *qingCloud) RecordLines(ctx context.Context, zone string) ([]dnsgo.RecordLine, error) {
	zone, err := q.zone(zone)
	if err != nil {
		return nil, err
	}
	var result struct {
		Views []struct {
			ID   jsonScalar `json:"id"`
			Name string     `json:"name"`
		} `json:"zone_views"`
	}
	if err := q.api.Call(ctx, http.MethodGet, "/v1/zone/view/",
		url.Values{"zone_name": {zone}, "type": {"GET_FULL"}}, nil, &result); err != nil {
		return nil, err
	}
	lines := make([]dnsgo.RecordLine, 0, len(result.Views))
	for _, row := range result.Views {
		name := row.Name
		if name == "*" {
			name = "默认"
		}
		lines = append(lines, dnsgo.RecordLine{Code: row.ID.String(), Name: name})
	}
	return lines, nil
}

func (q *qingCloud) MinTTL(context.Context, string) (int, error) { return 60, nil }

var _ dnsgo.Provider = (*qingCloud)(nil)
