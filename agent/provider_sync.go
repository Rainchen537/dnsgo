package agent

import (
	"context"
	"sync"

	"github.com/rainchen537/dnsgo"
)

// synchronizedProvider protects adapter-local sessions and caches when agent
// loops share the same configured DNS account concurrently.
type synchronizedProvider struct {
	dnsgo.Provider
	mu sync.Mutex
}

func (p *synchronizedProvider) Check(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Provider.Check(ctx)
}
func (p *synchronizedProvider) ListZones(ctx context.Context, query dnsgo.ZoneQuery) (dnsgo.Page[dnsgo.Zone], error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Provider.ListZones(ctx, query)
}
func (p *synchronizedProvider) CreateZone(ctx context.Context, name string) (dnsgo.Zone, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Provider.CreateZone(ctx, name)
}
func (p *synchronizedProvider) ListRecords(ctx context.Context, zone string, query dnsgo.RecordQuery) (dnsgo.Page[dnsgo.Record], error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Provider.ListRecords(ctx, zone, query)
}
func (p *synchronizedProvider) GetRecord(ctx context.Context, zone, id string) (dnsgo.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Provider.GetRecord(ctx, zone, id)
}
func (p *synchronizedProvider) CreateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Provider.CreateRecord(ctx, zone, record)
}
func (p *synchronizedProvider) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Provider.UpdateRecord(ctx, zone, record)
}
func (p *synchronizedProvider) SetRecordRemark(ctx context.Context, zone, id, remark string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Provider.SetRecordRemark(ctx, zone, id, remark)
}
func (p *synchronizedProvider) DeleteRecord(ctx context.Context, zone, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Provider.DeleteRecord(ctx, zone, id)
}
func (p *synchronizedProvider) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Provider.SetRecordStatus(ctx, zone, id, enabled)
}
func (p *synchronizedProvider) ListRecordLogs(ctx context.Context, zone string, query dnsgo.LogQuery) (dnsgo.Page[dnsgo.RecordLog], error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Provider.ListRecordLogs(ctx, zone, query)
}
func (p *synchronizedProvider) RecordLines(ctx context.Context, zone string) ([]dnsgo.RecordLine, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Provider.RecordLines(ctx, zone)
}
func (p *synchronizedProvider) MinTTL(ctx context.Context, zone string) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Provider.MinTTL(ctx, zone)
}

var _ dnsgo.Provider = (*synchronizedProvider)(nil)
