package dnsgo

import "context"

// Base supplies explicit unsupported responses. Adapters embed it and replace
// only the methods their provider actually supports.
type Base struct {
	ProviderKind string
	Features     Capabilities
}

func (b Base) Kind() string                { return b.ProviderKind }
func (b Base) Capabilities() Capabilities  { return b.Features }
func (b Base) Check(context.Context) error { return Unsupported(b.Kind(), "check") }
func (b Base) ListZones(context.Context, ZoneQuery) (Page[Zone], error) {
	return Page[Zone]{}, Unsupported(b.Kind(), "list_zones")
}
func (b Base) CreateZone(context.Context, string) (Zone, error) {
	return Zone{}, Unsupported(b.Kind(), "create_zone")
}
func (b Base) ListRecords(context.Context, string, RecordQuery) (Page[Record], error) {
	return Page[Record]{}, Unsupported(b.Kind(), "list_records")
}
func (b Base) GetRecord(context.Context, string, string) (Record, error) {
	return Record{}, Unsupported(b.Kind(), "get_record")
}
func (b Base) CreateRecord(context.Context, string, Record) (Record, error) {
	return Record{}, Unsupported(b.Kind(), "create_record")
}
func (b Base) UpdateRecord(context.Context, string, Record) (Record, error) {
	return Record{}, Unsupported(b.Kind(), "update_record")
}
func (b Base) SetRecordRemark(context.Context, string, string, string) error {
	return Unsupported(b.Kind(), "set_record_remark")
}
func (b Base) DeleteRecord(context.Context, string, string) error {
	return Unsupported(b.Kind(), "delete_record")
}
func (b Base) SetRecordStatus(context.Context, string, string, bool) error {
	return Unsupported(b.Kind(), "set_record_status")
}
func (b Base) ListRecordLogs(context.Context, string, LogQuery) (Page[RecordLog], error) {
	return Page[RecordLog]{}, Unsupported(b.Kind(), "list_record_logs")
}
func (b Base) RecordLines(context.Context, string) ([]RecordLine, error) {
	return nil, Unsupported(b.Kind(), "record_lines")
}
func (b Base) MinTTL(context.Context, string) (int, error) {
	return 0, Unsupported(b.Kind(), "min_ttl")
}
