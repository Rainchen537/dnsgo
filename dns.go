// Package dnsgo defines the cloud DNS operations shared by provider adapters.
// It does not discover public IP addresses or schedule DDNS updates.
package dnsgo

import (
	"context"
	"net/http"
	"strings"

	"golang.org/x/net/idna"
)

// Config is supplied by the caller. Credentials are never persisted by the SDK.
// Provider-specific credential names follow each adapter's documentation.
type Config struct {
	Credentials map[string]string
	Domain      string
	DomainID    string
	Endpoint    string
	HTTPClient  *http.Client
}

// Capabilities describe what an adapter exposes. A supported method can still
// fail when the configured account lacks permission or a paid plan is required.
type Capabilities struct {
	RecordTypes []string
	MinTTL      int
	Remarks     bool
	Status      bool
	Redirect    bool
	Logs        bool
	Weight      bool
	CreateZone  bool
	Lines       bool
	Sort        bool
	Batch       bool
}

type Zone struct {
	ID          string
	Name        string
	Status      string
	NameServers []string
	RecordCount int
	Extra       map[string]any
}

// Record represents a single logical record. Values preserves RRset members
// for providers such as Route 53 and PowerDNS; adapters must not drop them when
// changing just one value. Name may be relative or fully qualified according
// to the provider; preserve it when updating and use RecordFQDN for comparison.
// Extra contains provider fields needed for round trips.
type Record struct {
	ID         string
	ZoneID     string
	Name       string
	Type       string
	Value      string
	Values     []string
	TTL        int
	Priority   *uint16
	Weight     *uint16
	Line       string
	Proxied    *bool
	Enabled    *bool
	Remark     string
	ModifiedAt string
	Extra      map[string]any
}

type ZoneQuery struct {
	Keyword  string
	Page     int
	PageSize int
}

// FindZone locates one zone by its exact DNS name. Providers may implement
// ZoneQuery.Keyword as a fuzzy search, so every returned name is checked.
// Unicode and Punycode spellings match the same zone; the returned zone keeps
// the provider's original name and ID for subsequent calls.
func FindZone(ctx context.Context, provider Provider, name string) (Zone, error) {
	if provider == nil {
		return Zone{}, &Error{Operation: "find_zone", Code: CodeInvalidInput, Message: "provider is required"}
	}
	wanted := canonicalZoneName(name)
	if wanted == "" {
		return Zone{}, &Error{Provider: provider.Kind(), Operation: "find_zone", Code: CodeInvalidInput,
			Message: "zone name is required"}
	}
	const pageSize = 20
	seen := 0
	for number := 1; number <= 10000; number++ {
		// A provider may apply a fuzzy search before paging, or filter a page
		// locally while keeping the remote total. Scan unfiltered pages so an
		// empty filtered page cannot hide a later exact match.
		page, err := provider.ListZones(ctx, ZoneQuery{Page: number, PageSize: pageSize})
		if err != nil {
			return Zone{}, err
		}
		for _, zone := range page.Items {
			if canonicalZoneName(zone.Name) == wanted {
				return zone, nil
			}
		}
		seen += len(page.Items)
		if len(page.Items) == 0 || page.Total > 0 && seen >= page.Total || page.Total == 0 && len(page.Items) < pageSize {
			break
		}
		if number == 10000 {
			return Zone{}, &Error{Provider: provider.Kind(), Operation: "find_zone", Code: CodeResultUnknown,
				Message: "zone listing exceeded the page limit"}
		}
	}
	return Zone{}, &Error{Provider: provider.Kind(), Operation: "find_zone", Code: CodeNotFound,
		Message: "zone was not found"}
}

func canonicalZoneName(name string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if ascii, err := idna.Lookup.ToASCII(name); err == nil {
		return strings.ToLower(ascii)
	}
	return name
}

type RecordQuery struct {
	Keyword   string
	Name      string // relative name within the zone; @ selects the zone apex
	Value     string
	Type      string
	Line      string
	Enabled   *bool
	Page      int
	PageSize  int
	SortField string
	SortDesc  bool
}

type SubdomainQuery struct {
	Type     string
	Line     string
	Page     int
	PageSize int
}

// ListSubdomainRecords returns only records whose name is exactly subdomain.
// Provider APIs may treat ListRecords.Name as a fuzzy filter, so this helper
// walks every returned page before applying exact matching and pagination.
// The caller supplies both the provider zone ID and its DNS name because some
// adapters use opaque IDs while returning fully qualified record names.
// Subdomain may be relative, @, or an FQDN within zone.Name.
func ListSubdomainRecords(ctx context.Context, provider Provider, zone Zone, subdomain string, query SubdomainQuery) (Page[Record], error) {
	if provider == nil {
		return Page[Record]{}, &Error{Operation: "list_subdomain_records", Code: CodeInvalidInput,
			Message: "provider is required"}
	}
	zoneID := zone.ID
	if zoneID == "" {
		zoneID = zone.Name
	}
	if zoneID == "" || zone.Name == "" {
		return Page[Record]{}, &Error{Provider: provider.Kind(), Operation: "list_subdomain_records", Code: CodeInvalidInput,
			Message: "zone ID and name are required"}
	}
	wanted := relativeRecordName(zone.Name, subdomain)
	if wanted == "" {
		return Page[Record]{}, &Error{Provider: provider.Kind(), Operation: "list_subdomain_records", Code: CodeInvalidInput,
			Message: "subdomain is required"}
	}
	pageNumber, pageSize := query.Page, query.PageSize
	if pageNumber < 1 {
		pageNumber = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	// Use the common upstream page size; some providers cap larger requests and
	// would otherwise make Total-based completion skip the final page.
	const fetchSize = 20
	fetch := RecordQuery{PageSize: fetchSize}
	matched := make([]Record, 0)
	seen := 0
	for number := 1; number <= 10000; number++ {
		fetch.Page = number
		page, err := provider.ListRecords(ctx, zoneID, fetch)
		if err != nil {
			return Page[Record]{}, err
		}
		for _, record := range page.Items {
			if relativeRecordName(zone.Name, record.Name) != wanted ||
				query.Type != "" && !strings.EqualFold(record.Type, query.Type) ||
				!recordLineMatches(provider.Capabilities().Lines, query.Line, record.Line) {
				continue
			}
			matched = append(matched, record)
		}
		seen += len(page.Items)
		if len(page.Items) == 0 || page.Total > 0 && seen >= page.Total || page.Total == 0 && len(page.Items) < fetchSize {
			break
		}
		if number == 10000 {
			return Page[Record]{}, &Error{Provider: provider.Kind(), Operation: "list_subdomain_records", Code: CodeResultUnknown,
				Message: "record listing exceeded the page limit"}
		}
	}
	total := len(matched)
	start := total
	if pageNumber-1 <= total/pageSize {
		start = (pageNumber - 1) * pageSize
	}
	end := total
	if pageSize <= total-start {
		end = start + pageSize
	}
	return Page[Record]{Total: total, Items: matched[start:end]}, nil
}

func recordLineMatches(selectable bool, requested, actual string) bool {
	if requested == "" || requested == actual {
		return true
	}
	if selectable {
		return false
	}
	isDefault := func(value string) bool { return value == "" || value == "default" || value == "0" }
	return isDefault(requested) && isDefault(actual)
}

func relativeRecordName(zone, name string) string {
	zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return ""
	}
	if name == "@" || name == zone {
		return "@"
	}
	if zone != "" && strings.HasSuffix(name, "."+zone) {
		return strings.TrimSuffix(name, "."+zone)
	}
	return name
}

// RecordFQDN resolves a provider record name against the known zone name.
// It returns a lower-case name without a trailing root dot. Record.Name itself
// remains untouched so that it can be sent back to the originating adapter.
func RecordFQDN(zone Zone, record Record) (string, error) {
	zoneName := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone.Name), "."))
	if zoneName == "" {
		return "", &Error{Operation: "record_fqdn", Code: CodeInvalidInput, Message: "zone name is required"}
	}
	name := relativeRecordName(zoneName, record.Name)
	if name == "" {
		return "", &Error{Operation: "record_fqdn", Code: CodeInvalidInput, Message: "record name is required"}
	}
	if name == "@" {
		return zoneName, nil
	}
	return name + "." + zoneName, nil
}

type LogQuery struct {
	Keyword  string
	Start    string
	End      string
	Page     int
	PageSize int
}

type Page[T any] struct {
	Total int
	Items []T
}

type RecordLine struct {
	Code   string
	Name   string
	Parent string
}

type RecordLog struct {
	ID        string
	RecordID  string
	Action    string
	Message   string
	CreatedAt string
}

// Provider mirrors the full common DNS operation surface in the dnsmgr source.
// Unsupported optional operations return an Error with CodeUnsupported; they
// must never silently report success. Vendor extensions live on concrete types.
type Provider interface {
	Kind() string
	Capabilities() Capabilities
	Check(context.Context) error
	ListZones(context.Context, ZoneQuery) (Page[Zone], error)
	CreateZone(context.Context, string) (Zone, error)
	ListRecords(context.Context, string, RecordQuery) (Page[Record], error)
	GetRecord(context.Context, string, string) (Record, error)
	CreateRecord(context.Context, string, Record) (Record, error)
	UpdateRecord(context.Context, string, Record) (Record, error)
	SetRecordRemark(context.Context, string, string, string) error
	DeleteRecord(context.Context, string, string) error
	SetRecordStatus(context.Context, string, string, bool) error
	ListRecordLogs(context.Context, string, LogQuery) (Page[RecordLog], error)
	RecordLines(context.Context, string) ([]RecordLine, error)
	MinTTL(context.Context, string) (int, error)
}
