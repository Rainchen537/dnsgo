package providers

import (
	"context"
	"strings"

	"github.com/rainchen537/dnsgo"
)

// validateWriteFields rejects common fields that would otherwise disappear in
// provider-specific request conversion. A provider may still reject a value
// because of account permissions, plan limits or type-specific constraints.
func validateWriteFields(kind string, capabilities dnsgo.Capabilities, record dnsgo.Record) error {
	unsupported := func(field string) error {
		return &dnsgo.Error{Provider: kind, Operation: "write_record", Code: dnsgo.CodeUnsupported,
			Message: field + " is not supported by this provider adapter"}
	}
	if record.Remark != "" && !capabilities.Remarks {
		return unsupported("remark")
	}
	if record.Weight != nil && !capabilities.Weight && kind != "aliyun" {
		return unsupported("weight")
	}
	if record.Weight != nil && *record.Weight == 0 {
		switch kind {
		case "dnsla", "tencenteo", "huoshan", "huawei", "bt":
			return unsupported("zero weight")
		}
	}
	if record.Enabled != nil && !*record.Enabled && !capabilities.Status {
		return unsupported("disabled status")
	}
	if record.Proxied != nil && kind != "cloudflare" {
		return unsupported("proxy setting")
	}
	if len(record.Values) > 1 {
		switch kind {
		case "aws", "huawei", "powerdns", "qingcloud":
		default:
			return unsupported("multiple values")
		}
	}
	if record.Line != "" && record.Line != "default" && record.Line != "0" && !capabilities.Lines {
		return unsupported("line")
	}
	// RRset adapters preserve provider-native members in Values while Value is
	// normalized for the selected logical record (for example quoted TXT).
	rawRRSet := kind == "aws" || kind == "powerdns" || kind == "huawei" || kind == "qingcloud"
	if !rawRRSet && record.Value != "" && len(record.Values) == 1 && strings.TrimSpace(record.Value) != strings.TrimSpace(record.Values[0]) {
		return &dnsgo.Error{Provider: kind, Operation: "write_record", Code: dnsgo.CodeConflict,
			Message: "Value and Values disagree"}
	}
	return nil
}

func applyRequestedStatus(ctx context.Context, provider dnsgo.Provider, zone string, record dnsgo.Record, wanted, before *bool) (dnsgo.Record, error) {
	if wanted == nil || before != nil && *before == *wanted || before == nil && *wanted {
		return record, nil
	}
	if record.ID == "" {
		return record, &dnsgo.Error{Provider: provider.Kind(), Operation: "write_record_status",
			Code: dnsgo.CodeResultUnknown, Message: "record was written without an ID for status update"}
	}
	if err := provider.SetRecordStatus(ctx, zone, record.ID, *wanted); err != nil {
		return record, &dnsgo.Error{Provider: provider.Kind(), Operation: "write_record_status",
			Code: dnsgo.CodeResultUnknown, Message: "record was written but status update failed", Cause: err}
	}
	record.Enabled = wanted
	return record, nil
}
