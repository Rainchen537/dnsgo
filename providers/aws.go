package providers

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/rainchen537/dnsgo"
	"golang.org/x/net/idna"
)

type awsRoute53 struct {
	dnsgo.Base
	config dnsgo.Config
	api    *route53.Client
}

func init() { register("aws", newAWSRoute53) }

func newAWSRoute53(config dnsgo.Config) (dnsgo.Provider, error) {
	id := config.Credentials["AccessKeyId"]
	if id == "" {
		id = config.Credentials["access_key_id"]
	}
	secret := config.Credentials["SecretAccessKey"]
	if secret == "" {
		secret = config.Credentials["secret_access_key"]
	}
	options := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion("us-east-1")}
	if id != "" || secret != "" {
		if id == "" || secret == "" {
			return nil, &dnsgo.Error{Provider: "aws", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "both AWS access key and secret are required"}
		}
		options = append(options, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(id, secret, config.Credentials["SessionToken"])))
	}
	if config.HTTPClient != nil {
		options = append(options, awsconfig.WithHTTPClient(config.HTTPClient))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), options...)
	if err != nil {
		return nil, &dnsgo.Error{Provider: "aws", Operation: "new", Code: dnsgo.CodeInvalidInput, Message: "could not load AWS configuration", Cause: err}
	}
	clientOptions := []func(*route53.Options){}
	if config.Endpoint != "" {
		clientOptions = append(clientOptions, func(o *route53.Options) { o.BaseEndpoint = aws.String(config.Endpoint) })
	}
	return &awsRoute53{Base: dnsgo.Base{ProviderKind: "aws", Features: dnsgo.Capabilities{
		RecordTypes: []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT", "SPF"},
		MinTTL:      60, CreateZone: true,
	}}, config: config, api: route53.NewFromConfig(awsCfg, clientOptions...)}, nil
}

func awsError(operation string, err error) error {
	if err == nil {
		return nil
	}
	code := dnsgo.CodeProvider
	var apiErr smithy.APIError
	apiResponse := errors.As(err, &apiErr)
	vendorCode := ""
	message := "AWS Route 53 request failed"
	if apiResponse {
		vendorCode = apiErr.ErrorCode()
		message = apiErr.ErrorMessage()
		switch vendorCode {
		case "AccessDenied", "AccessDeniedException":
			code = dnsgo.CodePermission
		case "NoSuchHostedZone":
			code = dnsgo.CodeNotFound
		case "InvalidChangeBatch", "PriorRequestNotComplete":
			code = dnsgo.CodeConflict
		case "Throttling", "ThrottlingException":
			code = dnsgo.CodeRateLimited
		}
	}
	if operation == "change_record_sets" || operation == "create_zone" {
		var responseErr *smithyhttp.ResponseError
		ambiguousHTTP := errors.As(err, &responseErr) && responseErr.HTTPResponse() != nil &&
			(responseErr.HTTPStatusCode() == 408 || responseErr.HTTPStatusCode() >= 500)
		if ambiguousHTTP || !apiResponse {
			code = dnsgo.CodeResultUnknown
			message = "AWS write outcome is unknown; inspect the hosted zone before retrying"
		}
	}
	return &dnsgo.Error{Provider: "aws", Operation: operation, Code: code, VendorCode: vendorCode, Message: message}
}

func awsZoneID(zone string) string {
	return strings.TrimPrefix(zone, "/hostedzone/")
}

func (a *awsRoute53) zoneID(zone string) (string, error) {
	if zone == "" {
		zone = a.config.DomainID
	}
	zone = awsZoneID(zone)
	if zone == "" {
		return "", &dnsgo.Error{Provider: a.Kind(), Operation: "zone_id", Code: dnsgo.CodeInvalidInput, Message: "hosted zone ID is required"}
	}
	return zone, nil
}

func (a *awsRoute53) zoneName(ctx context.Context, zoneID string) (string, error) {
	if a.config.Domain != "" {
		return strings.TrimSuffix(a.config.Domain, "."), nil
	}
	result, err := a.api.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: aws.String(zoneID)})
	if err != nil {
		return "", awsError("get_hosted_zone", err)
	}
	if result.HostedZone == nil {
		return "", &dnsgo.Error{Provider: a.Kind(), Operation: "get_hosted_zone", Code: dnsgo.CodeResultUnknown}
	}
	return strings.TrimSuffix(aws.ToString(result.HostedZone.Name), "."), nil
}

func awsDomainASCII(domain string) (string, error) {
	result, err := idna.Lookup.ToASCII(strings.TrimSuffix(domain, "."))
	if err != nil || result == "" {
		return "", &dnsgo.Error{Provider: "aws", Operation: "domain_ascii", Code: dnsgo.CodeInvalidInput, Message: "invalid domain name"}
	}
	return result, nil
}

func awsFQDN(domain, name string) (string, error) {
	domain, err := awsDomainASCII(domain)
	if err != nil {
		return "", err
	}
	if name == "" || name == "@" || strings.EqualFold(strings.TrimSuffix(name, "."), domain) {
		return domain + ".", nil
	}
	if strings.HasSuffix(name, ".") {
		return name, nil
	}
	if strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(domain)) {
		return name + ".", nil
	}
	return name + "." + domain + ".", nil
}

func awsRelative(domain, name string) string {
	name = strings.TrimSuffix(name, ".")
	domain = strings.TrimSuffix(domain, ".")
	if strings.EqualFold(name, domain) {
		return "@"
	}
	suffix := "." + domain
	if strings.HasSuffix(strings.ToLower(name), strings.ToLower(suffix)) {
		return name[:len(name)-len(suffix)]
	}
	return name
}

func (a *awsRoute53) Check(ctx context.Context) error {
	_, err := a.ListZones(ctx, dnsgo.ZoneQuery{Page: 1, PageSize: 1})
	return err
}

func (a *awsRoute53) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	pager := route53.NewListHostedZonesPaginator(a.api, &route53.ListHostedZonesInput{})
	zones := []dnsgo.Zone{}
	for pager.HasMorePages() {
		result, err := pager.NextPage(ctx)
		if err != nil {
			return dnsgo.Page[dnsgo.Zone]{}, awsError("list_zones", err)
		}
		for _, row := range result.HostedZones {
			name := strings.TrimSuffix(aws.ToString(row.Name), ".")
			if query.Keyword == "" || strings.Contains(strings.ToLower(name), strings.ToLower(query.Keyword)) {
				zones = append(zones, dnsgo.Zone{ID: awsZoneID(aws.ToString(row.Id)), Name: name,
					RecordCount: int(aws.ToInt64(row.ResourceRecordSetCount))})
			}
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

func (a *awsRoute53) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	name, err := awsDomainASCII(name)
	if err != nil {
		return dnsgo.Zone{}, err
	}
	result, err := a.api.CreateHostedZone(ctx, &route53.CreateHostedZoneInput{
		Name: aws.String(name), CallerReference: aws.String(fmt.Sprintf("dnsgo-%s-%d", name, time.Now().UnixNano())),
	})
	if err != nil {
		return dnsgo.Zone{}, awsError("create_zone", err)
	}
	if result.HostedZone == nil {
		return dnsgo.Zone{}, &dnsgo.Error{Provider: a.Kind(), Operation: "create_zone", Code: dnsgo.CodeResultUnknown}
	}
	return dnsgo.Zone{ID: awsZoneID(aws.ToString(result.HostedZone.Id)), Name: strings.TrimSuffix(aws.ToString(result.HostedZone.Name), ".")}, nil
}

func awsRecordID(name, kind, raw string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(name + "\x1e" + kind + "\x1e" + raw))
}

func awsDecodeID(id string) (string, string, string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return "", "", "", err
	}
	parts := strings.SplitN(string(decoded), "\x1e", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid record ID")
	}
	return parts[0], parts[1], parts[2], nil
}

func awsParseValue(kind, raw string) (string, *uint16) {
	switch kind {
	case "TXT":
		if len(raw) >= 2 && strings.HasPrefix(raw, "\"") && strings.HasSuffix(raw, "\"") && !strings.Contains(raw[1:len(raw)-1], "\" \"") {
			return strings.ReplaceAll(raw[1:len(raw)-1], `\"`, `"`), nil
		}
	case "MX":
		parts := strings.SplitN(raw, " ", 2)
		if len(parts) == 2 {
			if n, err := strconv.ParseUint(parts[0], 10, 16); err == nil {
				p := uint16(n)
				return strings.TrimSuffix(parts[1], "."), &p
			}
		}
	case "CNAME", "NS", "PTR":
		return strings.TrimSuffix(raw, "."), nil
	case "SRV":
		parts := strings.Fields(raw)
		if len(parts) >= 4 {
			parts[3] = strings.TrimSuffix(parts[3], ".")
			return strings.Join(parts, " "), nil
		}
	}
	return raw, nil
}

func awsFormatValue(kind string, record dnsgo.Record) string {
	value := record.Value
	switch kind {
	case "TXT":
		if !strings.HasPrefix(value, "\"") {
			value = strconv.Quote(value)
		}
	case "MX":
		priority := uint16(1)
		if record.Priority != nil {
			priority = *record.Priority
		}
		value = fmt.Sprintf("%d %s.", priority, strings.TrimSuffix(value, "."))
	case "CNAME", "NS", "PTR":
		value = strings.TrimSuffix(value, ".") + "."
	case "SRV":
		parts := strings.Fields(value)
		if len(parts) >= 4 {
			parts[3] = strings.TrimSuffix(parts[3], ".") + "."
			value = strings.Join(parts, " ")
		}
	}
	return value
}

func awsKind(kind string) types.RRType {
	if kind == "SPF" {
		return types.RRTypeTxt
	}
	return types.RRType(strings.ToUpper(kind))
}

func (a *awsRoute53) listSets(ctx context.Context, zoneID string) ([]types.ResourceRecordSet, error) {
	pager := route53.NewListResourceRecordSetsPaginator(a.api, &route53.ListResourceRecordSetsInput{HostedZoneId: aws.String(zoneID)})
	sets := []types.ResourceRecordSet{}
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, awsError("list_record_sets", err)
		}
		sets = append(sets, page.ResourceRecordSets...)
	}
	return sets, nil
}

func awsSetValues(set types.ResourceRecordSet) []string {
	values := make([]string, 0, len(set.ResourceRecords))
	for _, row := range set.ResourceRecords {
		values = append(values, aws.ToString(row.Value))
	}
	return values
}

func (a *awsRoute53) toRecord(zoneID, domain string, set types.ResourceRecordSet, raw string) dnsgo.Record {
	name := awsRelative(domain, aws.ToString(set.Name))
	kind := string(set.Type)
	value, priority := awsParseValue(kind, raw)
	enabled := true
	return dnsgo.Record{ID: awsRecordID(name, kind, raw), ZoneID: zoneID, Name: name, Type: kind, Value: value,
		Values: awsSetValues(set), TTL: int(aws.ToInt64(set.TTL)), Priority: priority, Line: "default", Enabled: &enabled,
		Extra: map[string]any{"raw_value": raw}}
}

func (a *awsRoute53) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	zoneID, err := a.zoneID(zone)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	domain, err := a.zoneName(ctx, zoneID)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	sets, err := a.listSets(ctx, zoneID)
	if err != nil {
		return dnsgo.Page[dnsgo.Record]{}, err
	}
	records := []dnsgo.Record{}
	for _, set := range sets {
		if set.AliasTarget != nil || set.SetIdentifier != nil || set.Type == types.RRTypeSoa {
			continue
		}
		for _, value := range awsSetValues(set) {
			record := a.toRecord(zoneID, domain, set, value)
			if query.Name != "" && !strings.EqualFold(query.Name, record.Name) || query.Type != "" && query.Type != record.Type ||
				query.Value != "" && query.Value != record.Value || query.Keyword != "" && !strings.Contains(strings.ToLower(record.Name), strings.ToLower(query.Keyword)) && !strings.Contains(strings.ToLower(record.Value), strings.ToLower(query.Keyword)) ||
				query.Line != "" && query.Line != "default" && query.Line != "0" || query.Enabled != nil && !*query.Enabled {
				continue
			}
			records = append(records, record)
		}
	}
	total := len(records)
	start, size := offsetPage(query.Page, query.PageSize)
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	return dnsgo.Page[dnsgo.Record]{Total: total, Items: records[start:end]}, nil
}

func (a *awsRoute53) getSet(ctx context.Context, zoneID, name string, kind types.RRType) (*types.ResourceRecordSet, error) {
	result, err := a.api.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID), StartRecordName: aws.String(name), StartRecordType: kind, MaxItems: aws.Int32(1),
	})
	if err != nil {
		return nil, awsError("get_record_set", err)
	}
	if len(result.ResourceRecordSets) == 0 {
		return nil, nil
	}
	set := result.ResourceRecordSets[0]
	if !strings.EqualFold(strings.TrimSuffix(aws.ToString(set.Name), "."), strings.TrimSuffix(name, ".")) || set.Type != kind {
		return nil, nil
	}
	if set.AliasTarget != nil || set.SetIdentifier != nil {
		return nil, &dnsgo.Error{Provider: a.Kind(), Operation: "get_record_set", Code: dnsgo.CodeConflict,
			Message: "alias or routing-policy record set cannot be edited as a simple record"}
	}
	return &set, nil
}

func (a *awsRoute53) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	zoneID, err := a.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	name, kind, raw, err := awsDecodeID(id)
	if err != nil {
		return dnsgo.Record{}, &dnsgo.Error{Provider: a.Kind(), Operation: "get_record", Code: dnsgo.CodeInvalidInput, Message: "invalid record ID"}
	}
	domain, err := a.zoneName(ctx, zoneID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	fqdn, err := awsFQDN(domain, name)
	if err != nil {
		return dnsgo.Record{}, err
	}
	set, err := a.getSet(ctx, zoneID, fqdn, types.RRType(kind))
	if err != nil {
		return dnsgo.Record{}, err
	}
	if set != nil {
		for _, value := range awsSetValues(*set) {
			if value == raw {
				return a.toRecord(zoneID, domain, *set, raw), nil
			}
		}
	}
	return dnsgo.Record{}, &dnsgo.Error{Provider: a.Kind(), Operation: "get_record", Code: dnsgo.CodeNotFound}
}

func awsWithValues(set types.ResourceRecordSet, values []string) types.ResourceRecordSet {
	set.ResourceRecords = make([]types.ResourceRecord, 0, len(values))
	for _, value := range values {
		set.ResourceRecords = append(set.ResourceRecords, types.ResourceRecord{Value: aws.String(value)})
	}
	return set
}

func (a *awsRoute53) change(ctx context.Context, zoneID string, changes ...types.Change) error {
	_, err := a.api.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID), ChangeBatch: &types.ChangeBatch{Changes: changes},
	})
	return awsError("change_record_sets", err)
}

func (a *awsRoute53) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(a.Kind(), a.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zoneID, err := a.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	domain, err := a.zoneName(ctx, zoneID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	fqdn, err := awsFQDN(domain, record.Name)
	if err != nil {
		return dnsgo.Record{}, err
	}
	kind := awsKind(record.Type)
	raw := awsFormatValue(string(kind), record)
	old, err := a.getSet(ctx, zoneID, fqdn, kind)
	if err != nil {
		return dnsgo.Record{}, err
	}
	values := []string{}
	ttl := record.TTL
	if ttl <= 0 {
		ttl = 600
	}
	if old != nil {
		values = awsSetValues(*old)
		if record.TTL <= 0 {
			ttl = int(aws.ToInt64(old.TTL))
		}
	}
	for _, value := range values {
		if value == raw {
			return dnsgo.Record{}, &dnsgo.Error{Provider: a.Kind(), Operation: "create_record", Code: dnsgo.CodeConflict, Message: "identical record already exists"}
		}
	}
	values = append(values, raw)
	set := types.ResourceRecordSet{Name: aws.String(fqdn), Type: kind, TTL: aws.Int64(int64(ttl))}
	set = awsWithValues(set, values)
	if err := a.change(ctx, zoneID, types.Change{Action: types.ChangeActionUpsert, ResourceRecordSet: &set}); err != nil {
		return dnsgo.Record{}, err
	}
	record.ID = awsRecordID(awsRelative(domain, fqdn), string(kind), raw)
	record.ZoneID, record.Type, record.TTL, record.Values = zoneID, string(kind), ttl, values
	return record, nil
}

func (a *awsRoute53) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := validateWriteFields(a.Kind(), a.Capabilities(), record); err != nil {
		return dnsgo.Record{}, err
	}
	zoneID, err := a.zoneID(zone)
	if err != nil {
		return dnsgo.Record{}, err
	}
	oldName, oldKind, oldRaw, err := awsDecodeID(record.ID)
	if err != nil {
		return dnsgo.Record{}, &dnsgo.Error{Provider: a.Kind(), Operation: "update_record", Code: dnsgo.CodeInvalidInput, Message: "invalid record ID"}
	}
	domain, err := a.zoneName(ctx, zoneID)
	if err != nil {
		return dnsgo.Record{}, err
	}
	oldFQDN, err := awsFQDN(domain, oldName)
	if err != nil {
		return dnsgo.Record{}, err
	}
	newFQDN, err := awsFQDN(domain, record.Name)
	if err != nil {
		return dnsgo.Record{}, err
	}
	newKind := awsKind(record.Type)
	newRaw := awsFormatValue(string(newKind), record)
	oldSet, err := a.getSet(ctx, zoneID, oldFQDN, types.RRType(oldKind))
	if err != nil {
		return dnsgo.Record{}, err
	}
	if oldSet == nil {
		return dnsgo.Record{}, &dnsgo.Error{Provider: a.Kind(), Operation: "update_record", Code: dnsgo.CodeNotFound}
	}
	remaining := []string{}
	found := false
	for _, value := range awsSetValues(*oldSet) {
		if value == oldRaw {
			found = true
		} else {
			remaining = append(remaining, value)
		}
	}
	if !found {
		return dnsgo.Record{}, &dnsgo.Error{Provider: a.Kind(), Operation: "update_record", Code: dnsgo.CodeNotFound}
	}
	newTTL := record.TTL
	if newTTL <= 0 {
		newTTL = int(aws.ToInt64(oldSet.TTL))
	}
	if strings.EqualFold(oldFQDN, newFQDN) && types.RRType(oldKind) == newKind {
		for _, value := range remaining {
			if value == newRaw {
				return dnsgo.Record{}, &dnsgo.Error{Provider: a.Kind(), Operation: "update_record", Code: dnsgo.CodeConflict,
					Message: "identical record already exists"}
			}
		}
		updated := awsWithValues(*oldSet, append(remaining, newRaw))
		updated.TTL = aws.Int64(int64(newTTL))
		if err := a.change(ctx, zoneID, types.Change{Action: types.ChangeActionUpsert, ResourceRecordSet: &updated}); err != nil {
			return dnsgo.Record{}, err
		}
	} else {
		newSet, err := a.getSet(ctx, zoneID, newFQDN, newKind)
		if err != nil {
			return dnsgo.Record{}, err
		}
		newValues := []string{}
		if newSet != nil {
			newValues = awsSetValues(*newSet)
			if record.TTL <= 0 {
				newTTL = int(aws.ToInt64(newSet.TTL))
			}
		}
		for _, value := range newValues {
			if value == newRaw {
				return dnsgo.Record{}, &dnsgo.Error{Provider: a.Kind(), Operation: "update_record", Code: dnsgo.CodeConflict,
					Message: "identical record already exists at destination"}
			}
		}
		changes := []types.Change{}
		if len(remaining) == 0 {
			changes = append(changes, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: oldSet})
		} else {
			updatedOld := awsWithValues(*oldSet, remaining)
			changes = append(changes, types.Change{Action: types.ChangeActionUpsert, ResourceRecordSet: &updatedOld})
		}
		updatedNew := types.ResourceRecordSet{Name: aws.String(newFQDN), Type: newKind, TTL: aws.Int64(int64(newTTL))}
		updatedNew = awsWithValues(updatedNew, append(newValues, newRaw))
		changes = append(changes, types.Change{Action: types.ChangeActionUpsert, ResourceRecordSet: &updatedNew})
		if err := a.change(ctx, zoneID, changes...); err != nil {
			return dnsgo.Record{}, err
		}
	}
	record.ID = awsRecordID(awsRelative(domain, newFQDN), string(newKind), newRaw)
	record.ZoneID, record.Type, record.TTL = zoneID, string(newKind), newTTL
	return record, nil
}

func (a *awsRoute53) DeleteRecord(ctx context.Context, zone, id string) error {
	zoneID, err := a.zoneID(zone)
	if err != nil {
		return err
	}
	name, kind, raw, err := awsDecodeID(id)
	if err != nil {
		return &dnsgo.Error{Provider: a.Kind(), Operation: "delete_record", Code: dnsgo.CodeInvalidInput, Message: "invalid record ID"}
	}
	domain, err := a.zoneName(ctx, zoneID)
	if err != nil {
		return err
	}
	fqdn, err := awsFQDN(domain, name)
	if err != nil {
		return err
	}
	set, err := a.getSet(ctx, zoneID, fqdn, types.RRType(kind))
	if err != nil {
		return err
	}
	if set == nil {
		return &dnsgo.Error{Provider: a.Kind(), Operation: "delete_record", Code: dnsgo.CodeNotFound}
	}
	remaining := []string{}
	found := false
	for _, value := range awsSetValues(*set) {
		if value == raw {
			found = true
		} else {
			remaining = append(remaining, value)
		}
	}
	if !found {
		return &dnsgo.Error{Provider: a.Kind(), Operation: "delete_record", Code: dnsgo.CodeNotFound}
	}
	if len(remaining) == 0 {
		return a.change(ctx, zoneID, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: set})
	}
	updated := awsWithValues(*set, remaining)
	return a.change(ctx, zoneID, types.Change{Action: types.ChangeActionUpsert, ResourceRecordSet: &updated})
}

func (a *awsRoute53) RecordLines(context.Context, string) ([]dnsgo.RecordLine, error) {
	return []dnsgo.RecordLine{{Code: "default", Name: "默认"}}, nil
}

func (a *awsRoute53) MinTTL(context.Context, string) (int, error) { return 60, nil }

var _ dnsgo.Provider = (*awsRoute53)(nil)
