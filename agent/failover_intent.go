package agent

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/automation"
)

// failoverIntentProvider saves the intended result before the first DNS write.
// EvaluateFailover may read the record before UpdateRecord, so the callback is
// attached to the write methods rather than to the whole evaluation.
type failoverIntentProvider struct {
	dnsgo.Provider
	beforeWrite func() error
}

func (p failoverIntentProvider) SetRecordStatus(ctx context.Context, zone, id string, enabled bool) error {
	if err := p.beforeWrite(); err != nil {
		return err
	}
	return p.Provider.SetRecordStatus(ctx, zone, id, enabled)
}

func (p failoverIntentProvider) UpdateRecord(ctx context.Context, zone string, record dnsgo.Record) (dnsgo.Record, error) {
	if err := p.beforeWrite(); err != nil {
		return dnsgo.Record{}, err
	}
	return p.Provider.UpdateRecord(ctx, zone, record)
}

func pendingFailover(state automation.FailoverState, config FailoverConfig, now time.Time, backup, enabled, cloudflareProxy bool) automation.FailoverState {
	state.InFlight = true
	state.PendingMode = config.Mode
	state.PendingProvider = config.Provider
	state.PendingZoneID = config.ZoneID
	state.PendingRecordID = config.RecordID
	if state.RecordID != "" {
		state.PendingRecordID = state.RecordID
	}
	state.PendingBackup = backup
	state.PendingEnabled = enabled
	state.PendingName = config.Name
	state.AttemptAt = now
	if config.Mode == automation.FailoverValue {
		state.PendingValue = config.PrimaryValue
		if backup {
			state.PendingValue = config.BackupValue
		}
		if ip := net.ParseIP(state.PendingValue); ip != nil {
			state.PendingType = "AAAA"
			if ip.To4() != nil {
				state.PendingType = "A"
			}
		} else {
			state.PendingType = "CNAME"
		}
		if config.ProxyOnBackup && cloudflareProxy {
			state.PendingProxyLine = "0"
			if backup {
				state.PendingProxyLine = "1"
			}
		}
	}
	return state
}

func clearFailoverIntent(state *automation.FailoverState) {
	state.InFlight = false
	state.PendingMode = ""
	state.PendingProvider = ""
	state.PendingZoneID = ""
	state.PendingRecordID = ""
	state.PendingBackup = false
	state.PendingEnabled = false
	state.PendingName = ""
	state.PendingValue = ""
	state.PendingType = ""
	state.PendingProxyLine = ""
	state.AttemptAt = time.Time{}
}

func reconcileFailover(ctx context.Context, provider dnsgo.Provider, config FailoverConfig, state automation.FailoverState, now time.Time) (automation.FailoverState, automation.Transition, error) {
	if !state.InFlight || state.PendingMode != config.Mode || state.PendingProvider != config.Provider || state.PendingZoneID != config.ZoneID {
		return state, automation.Transition{}, &dnsgo.Error{Provider: provider.Kind(), Operation: "reconcile_failover",
			Code: dnsgo.CodeConflict, Message: "failover intent does not match current task configuration"}
	}
	id := state.PendingRecordID
	current, err := provider.GetRecord(ctx, config.ZoneID, id)
	if err != nil {
		return state, automation.Transition{}, err
	}
	confirmed := false
	action := ""
	switch state.PendingMode {
	case automation.FailoverPause:
		confirmed = current.Enabled != nil && *current.Enabled == !state.PendingBackup
		action = "primary"
		if state.PendingBackup {
			action = "backup"
		}
	case automation.FailoverConditional:
		confirmed = current.Enabled != nil && *current.Enabled == state.PendingEnabled
		action = "disable"
		if state.PendingEnabled {
			action = "enable"
		}
	case automation.FailoverValue:
		confirmed = current.Value == state.PendingValue && strings.EqualFold(current.Type, state.PendingType)
		if state.PendingName != "" {
			confirmed = confirmed && strings.EqualFold(strings.TrimSuffix(current.Name, "."), strings.TrimSuffix(state.PendingName, "."))
		}
		if state.PendingProxyLine != "" {
			confirmed = confirmed && current.Line == state.PendingProxyLine
		}
		action = "primary"
		if state.PendingBackup {
			action = "backup"
		}
	}
	if !confirmed {
		return state, automation.Transition{}, &dnsgo.Error{Provider: provider.Kind(), Operation: "reconcile_failover",
			Code: dnsgo.CodeResultUnknown, Message: "DNS record does not confirm the pending failover; inspect it before retrying"}
	}
	if state.PendingMode == automation.FailoverConditional {
		state.ConditionalEnabled = state.PendingEnabled
	} else {
		state.BackupActive = state.PendingBackup
	}
	state.ErrorCount = 0
	state.LastSwitch = state.AttemptAt
	if state.LastSwitch.IsZero() {
		state.LastSwitch = now
	}
	if current.ID != "" {
		state.RecordID = current.ID
	} else {
		state.RecordID = id
	}
	clearFailoverIntent(&state)
	return state, automation.Transition{Changed: true, Action: action, RecordID: state.RecordID,
		At: state.LastSwitch}, nil
}
