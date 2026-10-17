package providers

import (
	"context"
	"encoding/json"

	"github.com/rainchen537/dnsgo"
)

// RecordGroups is implemented by the Aliyun and DNSPod adapters. Applications
// can use a type assertion on a dnsgo.Provider when grouping is available.
type RecordGroups interface {
	ListRecordGroups(context.Context, string) ([]RecordGroup, error)
	ChangeRecordGroup(context.Context, string, []string, string) error
}

// ZoneDetails exposes the provider's detailed domain/zone response when the
// Rainbow DNS source has a real getDomainInfo API. The raw result preserves
// fields that have no common DNS meaning.
type ZoneDetails interface {
	GetZoneDetails(context.Context, string) (json.RawMessage, error)
}

type RecordGroup struct {
	ID    string
	Name  string
	Extra json.RawMessage
}

type AliyunExtras interface {
	RecordGroups
	DeleteSubDomainRecords(context.Context, string, string) error
	AliyunDomainInfo(context.Context, string) (json.RawMessage, error)
	ListWeightedSubdomains(context.Context, string, dnsgo.ZoneQuery) (dnsgo.Page[WeightedSubdomain], error)
	SetWeightStatus(context.Context, string, string, bool, string, string) error
	UpdateRecordWeight(context.Context, string, string, int) error
}

type WeightedSubdomain struct {
	Name  string
	Open  bool
	Extra json.RawMessage
}

type DNSPodExtras interface {
	RecordGroups
	DNSPodDomainInfo(context.Context, string) (json.RawMessage, error)
	DNSPodDomainPurview(context.Context, string) (json.RawMessage, error)
	DNSPodRecordLinesByGrade(context.Context, string) ([]dnsgo.RecordLine, error)
	DNSPodAccountInfo(context.Context) (json.RawMessage, error)
	ListDomainAliases(context.Context, string) ([]DomainAlias, error)
	AddDomainAlias(context.Context, string, string) error
	DeleteDomainAlias(context.Context, string, string) error
}

type DomainAlias struct {
	ID    string
	Name  string
	Extra json.RawMessage
}

// QingCloudHostRemarks changes a description shared by all records of one
// host. It is intentionally separate from per-record remark support.
type QingCloudHostRemarks interface {
	SetHostRemark(context.Context, string, string, string) error
}

type QingCloudHost struct {
	ID        string // fully qualified provider host identifier
	Name      string // relative host name, or @ for the zone apex
	Status    string
	Remark    string
	Count     int
	CreatedAt string
}

// QingCloudHosts exposes the upstream host-level list and delete operations.
// DeleteHost removes the host and all of its records, unlike DeleteRecord.
type QingCloudHosts interface {
	QingCloudHostRemarks
	ListHosts(context.Context, string, dnsgo.ZoneQuery) (dnsgo.Page[QingCloudHost], error)
	DeleteHost(context.Context, string, string) error
}

var _ QingCloudHostRemarks = (*qingCloud)(nil)
var _ QingCloudHosts = (*qingCloud)(nil)
