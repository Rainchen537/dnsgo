package automation

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rainchen537/dnsgo"
)

type FailoverMode string

const (
	FailoverPause       FailoverMode = "pause"
	FailoverValue       FailoverMode = "value"
	FailoverConditional FailoverMode = "conditional"
)

type FailoverTask struct {
	Mode          FailoverMode
	ZoneID        string
	RecordID      string
	Name          string
	PrimaryValue  string
	BackupValue   string
	Cycle         int // matches the reference counter threshold
	ProxyOnBackup bool
}

type FailoverState struct {
	BackupActive       bool
	ConditionalEnabled bool
	ErrorCount         int
	RecordID           string
	LastSwitch         time.Time
	InFlight           bool
	PendingMode        FailoverMode
	PendingProvider    string
	PendingZoneID      string
	PendingRecordID    string
	PendingBackup      bool
	PendingEnabled     bool
	PendingName        string
	PendingValue       string
	PendingType        string
	PendingProxyLine   string
	AttemptAt          time.Time
}

type Transition struct {
	Changed  bool
	Action   string
	RecordID string
	At       time.Time
	Probe    ProbeResult
}

func recordTypeForValue(value string) string {
	if ip := net.ParseIP(value); ip != nil {
		if ip.To4() != nil {
			return "A"
		}
		return "AAAA"
	}
	return "CNAME"
}

func failoverRecordID(task FailoverTask, state FailoverState) string {
	if state.RecordID != "" {
		return state.RecordID
	}
	return task.RecordID
}

// EvaluateFailover applies one probe result. As in Rainbow DNS, a cycle of 1
// switches immediately; larger values switch after the error counter has
// reached cycle, so a cycle of 2 requires three matching observations.
func EvaluateFailover(ctx context.Context, provider dnsgo.Provider, task FailoverTask, state FailoverState, probe ProbeResult) (FailoverState, Transition, error) {
	if provider == nil || task.ZoneID == "" || failoverRecordID(task, state) == "" {
		return state, Transition{}, fmt.Errorf("provider, zone ID and record ID are required")
	}
	if task.Mode != FailoverPause && task.Mode != FailoverValue {
		return state, Transition{}, fmt.Errorf("unsupported probe failover mode")
	}
	wantBackup := !probe.Healthy
	if wantBackup == state.BackupActive {
		state.ErrorCount = 0
		return state, Transition{Probe: probe}, nil
	}
	if task.Cycle > 1 && state.ErrorCount < task.Cycle {
		state.ErrorCount++
		return state, Transition{Probe: probe}, nil
	}
	newID, err := applyFailover(ctx, provider, task, state, wantBackup)
	if err != nil {
		if task.Cycle > state.ErrorCount {
			state.ErrorCount = task.Cycle
		}
		return state, Transition{Probe: probe}, err
	}
	state.BackupActive = wantBackup
	state.ErrorCount = 0
	state.RecordID = newID
	state.LastSwitch = time.Now()
	action := "primary"
	if wantBackup {
		action = "backup"
	}
	return state, Transition{Changed: true, Action: action, RecordID: newID, At: state.LastSwitch, Probe: probe}, nil
}

func applyFailover(ctx context.Context, provider dnsgo.Provider, task FailoverTask, state FailoverState, backup bool) (string, error) {
	id := failoverRecordID(task, state)
	if task.Mode == FailoverPause {
		if err := provider.SetRecordStatus(ctx, task.ZoneID, id, !backup); err != nil {
			return "", err
		}
		return id, nil
	}
	value := task.PrimaryValue
	if backup {
		value = task.BackupValue
	}
	if value == "" {
		return "", fmt.Errorf("failover value is empty")
	}
	record, err := provider.GetRecord(ctx, task.ZoneID, id)
	if err != nil {
		return "", err
	}
	if task.Name != "" {
		record.Name = task.Name
	}
	if len(record.Values) > 0 {
		record.Values = append([]string(nil), record.Values...)
		record.Values[0] = value
	}
	record.Value = value
	record.Type = recordTypeForValue(value)
	if task.ProxyOnBackup && provider.Kind() == "cloudflare" {
		record.Line = "0"
		if backup {
			record.Line = "1"
		}
	}
	updated, err := provider.UpdateRecord(ctx, task.ZoneID, record)
	if err != nil {
		return "", err
	}
	if updated.ID == "" {
		return "", &dnsgo.Error{Provider: provider.Kind(), Operation: "failover", Code: dnsgo.CodeResultUnknown,
			Message: "provider update returned no record ID"}
	}
	return updated.ID, nil
}

// EvaluateConditional mirrors the reference task that enables a record when
// the number of healthy sibling checks falls to or below the configured cycle.
func EvaluateConditional(ctx context.Context, provider dnsgo.Provider, task FailoverTask, state FailoverState, healthySiblings int) (FailoverState, Transition, error) {
	if task.Mode != FailoverConditional || provider == nil || task.ZoneID == "" || failoverRecordID(task, state) == "" {
		return state, Transition{}, fmt.Errorf("invalid conditional failover task")
	}
	wantEnabled := healthySiblings <= task.Cycle
	if wantEnabled == state.ConditionalEnabled {
		return state, Transition{}, nil
	}
	id := failoverRecordID(task, state)
	if err := provider.SetRecordStatus(ctx, task.ZoneID, id, wantEnabled); err != nil {
		return state, Transition{}, err
	}
	state.ConditionalEnabled = wantEnabled
	state.LastSwitch = time.Now()
	action := "disable"
	if wantEnabled {
		action = "enable"
	}
	return state, Transition{Changed: true, Action: action, RecordID: id, At: state.LastSwitch}, nil
}
