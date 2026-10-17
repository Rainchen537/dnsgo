package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/rainchen537/dnsgo"
)

func (a *aliyun) DeleteSubDomainRecords(ctx context.Context, zone, subdomain string) error {
	if a.domain(zone) == "" || subdomain == "" {
		return &dnsgo.Error{Provider: a.Kind(), Operation: "delete_subdomain_records", Code: dnsgo.CodeInvalidInput}
	}
	return a.call(ctx, "DeleteSubDomainRecords", url.Values{"DomainName": {a.domain(zone)}, "RR": {subdomain}}, nil)
}

func (a *aliyun) AliyunDomainInfo(ctx context.Context, zone string) (json.RawMessage, error) {
	var result json.RawMessage
	err := a.call(ctx, "DescribeDomainInfo", url.Values{"DomainName": {a.domain(zone)},
		"NeedDetailAttributes": {"true"}, "Lang": {"zh"}}, &result)
	return result, err
}

func (a *aliyun) ListRecordGroups(ctx context.Context, zone string) ([]RecordGroup, error) {
	var result struct {
		Groups struct {
			Items []json.RawMessage `json:"RecordGroup"`
		} `json:"RecordGroups"`
	}
	if err := a.call(ctx, "DescribeRecordGroups", url.Values{"DomainName": {a.domain(zone)},
		"PageSize": {"100"}, "Lang": {"zh"}}, &result); err != nil {
		return nil, err
	}
	groups := make([]RecordGroup, 0, len(result.Groups.Items))
	for _, raw := range result.Groups.Items {
		var fields struct {
			ID   any    `json:"GroupId"`
			Name string `json:"GroupName"`
		}
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, err
		}
		groups = append(groups, RecordGroup{ID: fmt.Sprint(fields.ID), Name: fields.Name, Extra: raw})
	}
	return groups, nil
}

func (a *aliyun) ChangeRecordGroup(ctx context.Context, zone string, recordIDs []string, groupID string) error {
	if len(recordIDs) == 0 || groupID == "" {
		return &dnsgo.Error{Provider: a.Kind(), Operation: "change_record_group", Code: dnsgo.CodeInvalidInput}
	}
	encoded, err := json.Marshal(recordIDs)
	if err != nil {
		return err
	}
	return a.call(ctx, "ChangeRecordGroup", url.Values{"DomainName": {a.domain(zone)},
		"RecordIdList": {string(encoded)}, "GroupId": {groupID}}, nil)
}

func (a *aliyun) ListWeightedSubdomains(ctx context.Context, zone string, query dnsgo.ZoneQuery) (dnsgo.Page[WeightedSubdomain], error) {
	values := aliyunPage(query.Page, query.PageSize)
	values.Set("DomainName", a.domain(zone))
	if query.Keyword != "" {
		values.Set("Rr", aliRR(query.Keyword, a.domain(zone)))
	}
	var result struct {
		Total int `json:"TotalCount"`
		List  struct {
			Items []json.RawMessage `json:"SlbSubDomain"`
		} `json:"SlbSubDomains"`
	}
	if err := a.call(ctx, "DescribeDNSSLBSubDomains", values, &result); err != nil {
		return dnsgo.Page[WeightedSubdomain]{}, err
	}
	page := dnsgo.Page[WeightedSubdomain]{Total: result.Total, Items: make([]WeightedSubdomain, 0, len(result.List.Items))}
	for _, raw := range result.List.Items {
		var fields struct {
			Name string `json:"SubDomain"`
			Open any    `json:"Open"`
		}
		if err := json.Unmarshal(raw, &fields); err != nil {
			return dnsgo.Page[WeightedSubdomain]{}, err
		}
		page.Items = append(page.Items, WeightedSubdomain{Name: fields.Name,
			Open: fmt.Sprint(fields.Open) == "true" || fmt.Sprint(fields.Open) == "1", Extra: raw})
	}
	return page, nil
}

func (a *aliyun) SetWeightStatus(ctx context.Context, zone, subdomain string, open bool, recordType, line string) error {
	if subdomain == "" {
		return &dnsgo.Error{Provider: a.Kind(), Operation: "set_weight_status", Code: dnsgo.CodeInvalidInput}
	}
	values := url.Values{"DomainName": {a.domain(zone)}, "SubDomain": {subdomain},
		"Open": {strconv.FormatBool(open)}}
	if recordType != "" {
		values.Set("Type", recordType)
	}
	if line != "" {
		values.Set("Line", line)
	}
	return a.call(ctx, "SetDNSSLBStatus", values, nil)
}

func (a *aliyun) UpdateRecordWeight(ctx context.Context, zone, recordID string, weight int) error {
	if recordID == "" || weight < 1 || weight > 100 {
		return &dnsgo.Error{Provider: a.Kind(), Operation: "update_record_weight", Code: dnsgo.CodeInvalidInput}
	}
	return a.call(ctx, "UpdateDNSSLBWeight", url.Values{"RecordId": {recordID},
		"Weight": {strconv.Itoa(weight)}}, nil)
}

var _ AliyunExtras = (*aliyun)(nil)
