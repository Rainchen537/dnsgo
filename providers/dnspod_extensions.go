package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/rainchen537/dnsgo"
)

func (p *dnspod) DNSPodDomainInfo(ctx context.Context, zone string) (json.RawMessage, error) {
	var result struct {
		Info json.RawMessage `json:"DomainInfo"`
	}
	err := p.api.Call(ctx, "DescribeDomain", map[string]any{"Domain": p.domain(zone)}, &result)
	return result.Info, err
}

func (p *dnspod) DNSPodDomainPurview(ctx context.Context, zone string) (json.RawMessage, error) {
	var result struct {
		List json.RawMessage `json:"PurviewList"`
	}
	err := p.api.Call(ctx, "DescribeDomainPurview", map[string]any{"Domain": p.domain(zone)}, &result)
	return result.List, err
}

func (p *dnspod) DNSPodRecordLinesByGrade(ctx context.Context, zone string) ([]dnsgo.RecordLine, error) {
	var result struct {
		Lines []struct {
			ID   any    `json:"LineId"`
			Name string `json:"Name"`
		} `json:"LineList"`
		Groups []struct {
			ID   any    `json:"LineId"`
			Name string `json:"Name"`
		} `json:"LineGroupList"`
	}
	if err := p.api.Call(ctx, "DescribeRecordLineList", map[string]any{"Domain": p.domain(zone), "DomainGrade": ""}, &result); err != nil {
		return nil, err
	}
	lines := make([]dnsgo.RecordLine, 0, len(result.Lines)+len(result.Groups))
	for _, line := range result.Lines {
		lines = append(lines, dnsgo.RecordLine{Code: fmt.Sprint(line.ID), Name: line.Name})
	}
	for _, group := range result.Groups {
		lines = append(lines, dnsgo.RecordLine{Code: fmt.Sprint(group.ID), Name: group.Name})
	}
	return lines, nil
}

func (p *dnspod) DNSPodAccountInfo(ctx context.Context) (json.RawMessage, error) {
	var result struct {
		Info json.RawMessage `json:"UserInfo"`
	}
	err := p.api.Call(ctx, "DescribeUserDetail", map[string]any{}, &result)
	return result.Info, err
}

func (p *dnspod) ListDomainAliases(ctx context.Context, zone string) ([]DomainAlias, error) {
	var result struct {
		List []json.RawMessage `json:"DomainAliasList"`
	}
	if err := p.api.Call(ctx, "DescribeDomainAliasList", map[string]any{"Domain": p.domain(zone)}, &result); err != nil {
		return nil, err
	}
	aliases := make([]DomainAlias, 0, len(result.List))
	for _, raw := range result.List {
		var fields struct {
			ID   any    `json:"Id"`
			Name string `json:"DomainAlias"`
		}
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, err
		}
		aliases = append(aliases, DomainAlias{ID: fmt.Sprint(fields.ID), Name: fields.Name, Extra: raw})
	}
	return aliases, nil
}

func (p *dnspod) AddDomainAlias(ctx context.Context, zone, alias string) error {
	if alias == "" {
		return &dnsgo.Error{Provider: p.Kind(), Operation: "add_domain_alias", Code: dnsgo.CodeInvalidInput}
	}
	return p.api.Call(ctx, "CreateDomainAlias", map[string]any{"Domain": p.domain(zone), "DomainAlias": alias}, nil)
}

func (p *dnspod) DeleteDomainAlias(ctx context.Context, zone, aliasID string) error {
	id, err := strconv.ParseUint(aliasID, 10, 64)
	if err != nil {
		return &dnsgo.Error{Provider: p.Kind(), Operation: "delete_domain_alias", Code: dnsgo.CodeInvalidInput}
	}
	return p.api.Call(ctx, "DeleteDomainAlias", map[string]any{"Domain": p.domain(zone), "DomainAliasId": id}, nil)
}

func (p *dnspod) ListRecordGroups(ctx context.Context, zone string) ([]RecordGroup, error) {
	var result struct {
		List []json.RawMessage `json:"GroupList"`
	}
	if err := p.api.Call(ctx, "DescribeRecordGroupList", map[string]any{"Domain": p.domain(zone)}, &result); err != nil {
		return nil, err
	}
	groups := make([]RecordGroup, 0, len(result.List))
	for _, raw := range result.List {
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

func (p *dnspod) ChangeRecordGroup(ctx context.Context, zone string, recordIDs []string, groupID string) error {
	if len(recordIDs) == 0 {
		return &dnsgo.Error{Provider: p.Kind(), Operation: "change_record_group", Code: dnsgo.CodeInvalidInput}
	}
	id, err := strconv.ParseUint(groupID, 10, 64)
	if err != nil {
		return &dnsgo.Error{Provider: p.Kind(), Operation: "change_record_group", Code: dnsgo.CodeInvalidInput}
	}
	return p.api.Call(ctx, "ModifyRecordToGroup", map[string]any{
		"Domain": p.domain(zone), "GroupId": id, "RecordId": strings.Join(recordIDs, "|"),
	}, nil)
}

var _ DNSPodExtras = (*dnspod)(nil)
