package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo/automation"
	"github.com/rainchen537/dnsgo/cert"
	"github.com/rainchen537/dnsgo/deploy"
	"github.com/rainchen537/dnsgo/notify"
)

type FailoverSummary struct {
	ID                 string                  `json:"id"`
	InFlight           bool                    `json:"in_flight"`
	Mode               automation.FailoverMode `json:"mode,omitempty"`
	Provider           string                  `json:"provider,omitempty"`
	ZoneID             string                  `json:"zone_id,omitempty"`
	RecordID           string                  `json:"record_id,omitempty"`
	BackupActive       bool                    `json:"backup_active"`
	ConditionalEnabled bool                    `json:"conditional_enabled"`
	PendingBackup      bool                    `json:"pending_backup"`
	PendingEnabled     bool                    `json:"pending_enabled"`
	PendingValue       string                  `json:"pending_value,omitempty"`
	AttemptAt          time.Time               `json:"attempt_at,omitempty"`
}

func (s *Store) FailoverSummary(ctx context.Context, id string) (FailoverSummary, error) {
	var state automation.FailoverState
	found, err := s.Load(ctx, "failover", id, &state)
	if err != nil {
		return FailoverSummary{}, err
	}
	if !found {
		return FailoverSummary{}, fmt.Errorf("failover %s has no stored state", id)
	}
	recordID := state.PendingRecordID
	if recordID == "" {
		recordID = state.RecordID
	}
	return FailoverSummary{ID: id, InFlight: state.InFlight, Mode: state.PendingMode,
		Provider: state.PendingProvider, ZoneID: state.PendingZoneID, RecordID: recordID,
		BackupActive: state.BackupActive, ConditionalEnabled: state.ConditionalEnabled,
		PendingBackup: state.PendingBackup, PendingEnabled: state.PendingEnabled,
		PendingValue: state.PendingValue, AttemptAt: state.AttemptAt}, nil
}

// ResolveFailover changes a pending intent only after independent DNS readback.
func (s *Store) ResolveFailover(ctx context.Context, id, action, recordID string, now time.Time) error {
	var state automation.FailoverState
	found, err := s.Load(ctx, "failover", id, &state)
	if err != nil {
		return err
	}
	if !found || !state.InFlight {
		return fmt.Errorf("failover %s has no in-flight operation", id)
	}
	if recordID != "" && action != "mark-done" {
		return fmt.Errorf("record ID is allowed only for mark-done")
	}
	switch action {
	case "retry":
		clearFailoverIntent(&state)
		return s.Save(ctx, "failover", id, state)
	case "mark-done":
		if state.PendingMode != automation.FailoverPause && state.PendingMode != automation.FailoverValue &&
			state.PendingMode != automation.FailoverConditional {
			return fmt.Errorf("failover pending mode is invalid")
		}
		transition := "primary"
		if state.PendingMode == automation.FailoverConditional {
			state.ConditionalEnabled = state.PendingEnabled
			transition = "disable"
			if state.PendingEnabled {
				transition = "enable"
			}
		} else {
			state.BackupActive = state.PendingBackup
			if state.PendingBackup {
				transition = "backup"
			}
		}
		if recordID != "" {
			state.RecordID = recordID
		} else if state.RecordID == "" {
			state.RecordID = state.PendingRecordID
		}
		state.ErrorCount = 0
		state.LastSwitch = now
		clearFailoverIntent(&state)
		return s.SaveWithEvent(ctx, "failover", id, state, notify.Event{Kind: notify.Failover,
			Success: transition == "primary" || transition == "disable",
			Title:   "DNS 故障切换（人工确认）：" + id + " → " + transition,
			HTML:    "已核对记录状态"})
	default:
		return fmt.Errorf("unknown failover resolution action %q", action)
	}
}

// CertificateSummary deliberately omits private keys, certificate PEM,
// credentials and raw provider errors.
type CertificateSummary struct {
	ID                 string             `json:"id"`
	Phase              string             `json:"phase"`
	OrderID            string             `json:"order_id,omitempty"`
	Domains            []string           `json:"domains,omitempty"`
	ExpiresAt          time.Time          `json:"expires_at,omitempty"`
	LastAttempt        time.Time          `json:"last_attempt,omitempty"`
	ErrorPresent       bool               `json:"error_present"`
	Deployments        map[string]string  `json:"deployments,omitempty"`
	DeploymentWrites   map[string]bool    `json:"deployment_writes,omitempty"`
	PendingDeployments map[string]string  `json:"pending_deployments,omitempty"`
	ReusableIDs        map[string]string  `json:"reusable_ids,omitempty"`
	PendingDNSCount    int                `json:"pending_dns_count"`
	PendingDNS         []ChallengeSummary `json:"pending_dns,omitempty"`
}

type ChallengeSummary struct {
	Provider string `json:"provider"`
	ZoneID   string `json:"zone_id"`
	RecordID string `json:"record_id,omitempty"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Owned    bool   `json:"owned"`
}

func (s *Store) CertificateSummary(ctx context.Context, id string) (CertificateSummary, error) {
	var state certificateState
	found, err := s.Load(ctx, "certificate", id, &state)
	if err != nil {
		return CertificateSummary{}, err
	}
	if !found {
		return CertificateSummary{}, fmt.Errorf("certificate %s has no stored state", id)
	}
	writes := map[string]bool{}
	pending := map[string]string{}
	for target, result := range state.DeploymentResults {
		writes[target] = result.Written
		if result.Pending && result.Metadata != nil {
			pending[target] = result.Metadata["deploy_record_id"]
		}
	}
	reusable := map[string]string{}
	for target, result := range state.TargetLocations {
		if reusableTargetLocationKey(result.Target) != "" && result.Location != "" {
			reusable[target] = result.Location
		}
	}
	challenges := make([]ChallengeSummary, 0, len(state.Challenges))
	for _, record := range state.Challenges {
		challenges = append(challenges, ChallengeSummary{Provider: record.Provider, ZoneID: record.ZoneID,
			RecordID: record.RecordID, Name: record.Name, Type: record.Type, Owned: record.Owned})
	}
	return CertificateSummary{ID: id, Phase: state.Phase, OrderID: state.Order.ID,
		Domains: append([]string(nil), state.Result.Domains...), ExpiresAt: state.Result.NotAfter,
		LastAttempt: state.LastAttempt, ErrorPresent: state.LastError != "",
		Deployments: state.Deployments, DeploymentWrites: writes, PendingDeployments: pending, ReusableIDs: reusable,
		PendingDNSCount: len(state.Challenges), PendingDNS: challenges}, nil
}

// ResolveCertificate clears an uncertain state only after an operator has
// independently checked the provider. action is "retry", "resume-order",
// "mark-validating", "resume-issued" or "mark-deployed".
func (s *Store) ResolveCertificate(ctx context.Context, id, action string, locationAndTarget ...string) error {
	if len(locationAndTarget) != 0 && (len(locationAndTarget) != 2 || action != "mark-deployed") {
		return fmt.Errorf("location and target are allowed only for mark-deployed")
	}
	var state certificateState
	found, err := s.Load(ctx, "certificate", id, &state)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("certificate %s has no stored state", id)
	}
	switch action {
	case "retry":
		if state.Phase != "issuing" && state.Phase != "unknown_start" && state.Phase != "unknown_challenge" && state.Phase != "unknown_issue" && state.Phase != "unknown_validation" && state.Phase != "rejected" &&
			!strings.HasPrefix(state.Phase, "deploying:") && !strings.HasPrefix(state.Phase, "unknown_deploy:") && !strings.HasPrefix(state.Phase, "pending_deploy:") {
			return fmt.Errorf("certificate phase %s cannot be reset for retry", state.Phase)
		}
		if state.Phase == "unknown_start" || state.Phase == "unknown_challenge" {
			state.Order = cert.CloudOrder{}
			state.Challenges = nil
			state.ChallengeCreatedAt = time.Time{}
		}
		if state.Phase == "unknown_validation" {
			state.Phase = "pending"
			state.LastAttempt = time.Time{}
			state.LastError = ""
			break
		}
		if strings.HasPrefix(state.Phase, "deploying:") || strings.HasPrefix(state.Phase, "unknown_deploy:") || strings.HasPrefix(state.Phase, "pending_deploy:") {
			state.Phase = "issued"
		} else {
			state.Phase = "error"
		}
		state.LastAttempt = time.Time{}
		state.LastError = ""
	case "mark-deployed":
		prefix := "deploying:"
		if strings.HasPrefix(state.Phase, "unknown_deploy:") {
			prefix = "unknown_deploy:"
		} else if strings.HasPrefix(state.Phase, "pending_deploy:") {
			prefix = "pending_deploy:"
		}
		if !strings.HasPrefix(state.Phase, prefix) {
			return fmt.Errorf("certificate has no uncertain deployment")
		}
		if len(state.Result.FullChainPEM) == 0 {
			return fmt.Errorf("certificate material is missing")
		}
		id := strings.TrimPrefix(state.Phase, prefix)
		if state.Deployments == nil {
			state.Deployments = map[string]string{}
		}
		version := state.DeploymentVersions[id]
		if version == "" {
			return fmt.Errorf("deployment attempt has no saved target configuration version")
		}
		state.Deployments[id] = version
		if state.DeploymentResults == nil {
			state.DeploymentResults = map[string]deploy.Result{}
		}
		result := state.DeploymentResults[id]
		if len(locationAndTarget) == 2 {
			if result.Target != "" && result.Target != strings.TrimSpace(locationAndTarget[1]) {
				return fmt.Errorf("deployment target kind does not match stored attempt")
			}
			result.Location = strings.TrimSpace(locationAndTarget[0])
			result.Target = strings.TrimSpace(locationAndTarget[1])
			if result.Location == "" || reusableTargetLocationKey(result.Target) == "" {
				return fmt.Errorf("deployment location and reusable target kind are required")
			}
		}
		result.Written = true
		result.Pending = false
		state.DeploymentResults[id] = result
		if result.Location != "" && reusableTargetLocationKey(result.Target) != "" {
			if state.TargetLocations == nil {
				state.TargetLocations = map[string]deploy.Result{}
			}
			state.TargetLocations[id] = result
		}
		state.Phase = "issued"
		delete(state.DeployErrors, id)
		state.LastError = ""
	case "resume-order":
		if state.Phase != "unknown_start" || state.Order.ID == "" {
			return fmt.Errorf("no stored cloud order can be resumed")
		}
		state.Phase = "pending"
		state.LastAttempt = time.Time{}
		state.LastError = ""
	case "mark-validating":
		if state.Phase != "unknown_validation" || state.Order.ID == "" {
			return fmt.Errorf("no uncertain validation submission can be marked")
		}
		state.Phase = "validating"
		state.LastAttempt = time.Time{}
		state.LastError = ""
	case "resume-issued":
		if state.Phase != "unknown_challenge" || len(state.Result.FullChainPEM) == 0 || len(state.Result.PrivateKeyPEM) == 0 {
			return fmt.Errorf("no issued certificate is waiting for challenge cleanup")
		}
		state.Challenges = nil
		state.Phase = "issued"
		state.LastError = ""
	default:
		return fmt.Errorf("unknown resolution action %q", action)
	}
	return s.Save(ctx, "certificate", id, state)
}

type ScheduleSummary struct {
	ID        string    `json:"id"`
	NextRun   time.Time `json:"next_run"`
	LastRun   time.Time `json:"last_run,omitempty"`
	AttemptAt time.Time `json:"attempt_at,omitempty"`
	RecordID  string    `json:"record_id,omitempty"`
	InFlight  bool      `json:"in_flight"`
	Completed bool      `json:"completed"`
}

func (s *Store) ScheduleSummary(ctx context.Context, id string) (ScheduleSummary, error) {
	var state automation.ScheduleState
	found, err := s.Load(ctx, "schedule", id, &state)
	if err != nil {
		return ScheduleSummary{}, err
	}
	if !found {
		return ScheduleSummary{}, fmt.Errorf("schedule %s has no stored state", id)
	}
	return ScheduleSummary{ID: id, NextRun: state.NextRun, LastRun: state.LastRun,
		AttemptAt: state.AttemptAt, RecordID: state.RecordID, InFlight: state.InFlight,
		Completed: state.Completed}, nil
}

func (s *Store) ResolveSchedule(ctx context.Context, config ScheduleConfig, action, recordID string, now time.Time) error {
	var state automation.ScheduleState
	found, err := s.Load(ctx, "schedule", config.ID, &state)
	if err != nil {
		return err
	}
	if !found || !state.InFlight {
		return fmt.Errorf("schedule %s has no in-flight operation", config.ID)
	}
	switch action {
	case "retry":
		state.InFlight = false
		state.AttemptAt = time.Time{}
		state.IntentKey = ""
	case "mark-done":
		task, err := config.automation()
		if err != nil {
			return err
		}
		if state.IntentKey != "" && state.IntentKey != scheduleIntentKey(task, state) {
			return fmt.Errorf("schedule configuration changed during an in-flight DNS write")
		}
		state, err = automation.CompleteScheduleAfterInspection(task, state, now, recordID)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown schedule resolution action %q", action)
	}
	return s.Save(ctx, "schedule", config.ID, state)
}
