package automation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type ScheduleAction string

const (
	ScheduleEnable ScheduleAction = "enable"
	SchedulePause  ScheduleAction = "pause"
	ScheduleDelete ScheduleAction = "delete"
	ScheduleValue  ScheduleAction = "value"
)

type ScheduleCycle string

const (
	ScheduleOnce    ScheduleCycle = "once"
	ScheduleDaily   ScheduleCycle = "daily"
	ScheduleWeekly  ScheduleCycle = "weekly"
	ScheduleMonthly ScheduleCycle = "monthly"
)

type ScheduleTask struct {
	Action   ScheduleAction
	Cycle    ScheduleCycle
	ZoneID   string
	RecordID string
	Name     string
	Value    string
	Line     string
	TTL      int
	At       time.Time
	Hour     int
	Minute   int
	Weekday  time.Weekday // Sunday=0
	MonthDay int
	Location *time.Location
}

type ScheduleState struct {
	NextRun   time.Time
	LastRun   time.Time
	RecordID  string
	Completed bool
	InFlight  bool
	AttemptAt time.Time
	IntentKey string
}

type ScheduleResult struct {
	Executed bool
	Action   ScheduleAction
	RecordID string
	At       time.Time
	NextRun  time.Time
}

func (t ScheduleTask) location() *time.Location {
	if t.Location != nil {
		return t.Location
	}
	return time.Local
}

func (t ScheduleTask) validate() error {
	if t.ZoneID == "" || t.RecordID == "" {
		return fmt.Errorf("zone ID and record ID are required")
	}
	switch t.Action {
	case ScheduleEnable, SchedulePause, ScheduleDelete, ScheduleValue:
	default:
		return fmt.Errorf("unknown schedule action")
	}
	if t.Action == ScheduleValue && t.Value == "" {
		return fmt.Errorf("scheduled record value is required")
	}
	if t.Hour < 0 || t.Hour > 23 || t.Minute < 0 || t.Minute > 59 {
		return fmt.Errorf("invalid schedule clock time")
	}
	switch t.Cycle {
	case ScheduleOnce:
		if t.At.IsZero() {
			return fmt.Errorf("one-time schedule requires At")
		}
	case ScheduleDaily:
	case ScheduleWeekly:
		if t.Weekday < time.Sunday || t.Weekday > time.Saturday {
			return fmt.Errorf("invalid weekday")
		}
	case ScheduleMonthly:
		if t.MonthDay < 1 || t.MonthDay > 31 {
			return fmt.Errorf("monthly day must be 1 through 31")
		}
	default:
		return fmt.Errorf("unknown schedule cycle")
	}
	return nil
}

// NextAfter returns the first scheduled time strictly after the given time.
// Monthly days absent from a month are skipped, rather than rolling into the
// following month as PHP strtotime can do.
func (t ScheduleTask) NextAfter(after time.Time) (time.Time, error) {
	if err := t.validate(); err != nil {
		return time.Time{}, err
	}
	loc := t.location()
	after = after.In(loc)
	if t.Cycle == ScheduleOnce {
		if t.At.After(after) {
			return t.At, nil
		}
		return time.Time{}, nil
	}
	for day := 0; day < 370; day++ {
		date := after.AddDate(0, 0, day)
		if t.Cycle == ScheduleWeekly && date.Weekday() != t.Weekday {
			continue
		}
		if t.Cycle == ScheduleMonthly && date.Day() != t.MonthDay {
			continue
		}
		candidate := time.Date(date.Year(), date.Month(), date.Day(), t.Hour, t.Minute, 0, 0, loc)
		if candidate.After(after) {
			return candidate, nil
		}
	}
	return time.Time{}, fmt.Errorf("no future schedule time found")
}

// InitSchedule records the first due time; the optional agent persists it.
func InitSchedule(task ScheduleTask, now time.Time) (ScheduleState, error) {
	if task.Cycle == ScheduleOnce {
		if err := task.validate(); err != nil {
			return ScheduleState{}, err
		}
		return ScheduleState{NextRun: task.At}, nil
	}
	next, err := task.NextAfter(now.Add(-time.Nanosecond))
	return ScheduleState{NextRun: next}, err
}

func RunDueSchedule(ctx context.Context, provider dnsgo.Provider, task ScheduleTask, state ScheduleState, now time.Time) (ScheduleState, ScheduleResult, error) {
	if provider == nil {
		return state, ScheduleResult{}, fmt.Errorf("DNS provider is required")
	}
	if err := task.validate(); err != nil {
		return state, ScheduleResult{}, err
	}
	if state.Completed {
		return state, ScheduleResult{}, nil
	}
	if state.NextRun.IsZero() {
		return state, ScheduleResult{}, fmt.Errorf("schedule state has no NextRun; call InitSchedule")
	}
	if now.Before(state.NextRun) {
		return state, ScheduleResult{}, nil
	}
	id := state.RecordID
	if id == "" {
		id = task.RecordID
	}
	switch task.Action {
	case ScheduleEnable:
		if err := provider.SetRecordStatus(ctx, task.ZoneID, id, true); err != nil {
			return state, ScheduleResult{}, err
		}
	case SchedulePause:
		if err := provider.SetRecordStatus(ctx, task.ZoneID, id, false); err != nil {
			return state, ScheduleResult{}, err
		}
	case ScheduleDelete:
		if err := provider.DeleteRecord(ctx, task.ZoneID, id); err != nil {
			return state, ScheduleResult{}, err
		}
	case ScheduleValue:
		record, err := provider.GetRecord(ctx, task.ZoneID, id)
		if err != nil {
			return state, ScheduleResult{}, err
		}
		if task.Name != "" {
			record.Name = task.Name
		}
		if len(record.Values) > 0 {
			record.Values = append([]string(nil), record.Values...)
			record.Values[0] = task.Value
		}
		record.Value = task.Value
		record.Type = recordTypeForValue(task.Value)
		if task.Line != "" {
			record.Line = task.Line
		}
		if task.TTL > 0 {
			record.TTL = task.TTL
		}
		updated, err := provider.UpdateRecord(ctx, task.ZoneID, record)
		if err != nil {
			return state, ScheduleResult{}, err
		}
		if updated.ID == "" {
			return state, ScheduleResult{}, &dnsgo.Error{Provider: provider.Kind(), Operation: "schedule", Code: dnsgo.CodeResultUnknown,
				Message: "provider update returned no record ID"}
		}
		id = updated.ID
	}
	return completeSchedule(task, state, now, id)
}

func completeSchedule(task ScheduleTask, state ScheduleState, now time.Time, id string) (ScheduleState, ScheduleResult, error) {
	state.LastRun = now
	state.RecordID = id
	state.InFlight = false
	state.AttemptAt = time.Time{}
	state.IntentKey = ""
	if task.Cycle == ScheduleOnce || task.Action == ScheduleDelete {
		state.Completed = true
		state.NextRun = time.Time{}
	} else {
		next, err := task.NextAfter(now)
		if err != nil {
			return state, ScheduleResult{Executed: true, Action: task.Action, RecordID: id, At: now}, err
		}
		state.NextRun = next
	}
	return state, ScheduleResult{Executed: true, Action: task.Action, RecordID: id, At: now, NextRun: state.NextRun}, nil
}

// ReconcileDueSchedule checks whether an interrupted operation reached its
// desired state before the resident agent attempts another write.
func ReconcileDueSchedule(ctx context.Context, provider dnsgo.Provider, task ScheduleTask, state ScheduleState, now time.Time) (ScheduleState, bool, error) {
	if !state.InFlight {
		return state, false, nil
	}
	id := state.RecordID
	if id == "" {
		id = task.RecordID
	}
	record, err := provider.GetRecord(ctx, task.ZoneID, id)
	if err != nil {
		if task.Action == ScheduleDelete && dnsgo.IsCode(err, dnsgo.CodeNotFound) {
			finished, _, finishErr := completeSchedule(task, state, now, id)
			return finished, true, finishErr
		}
		return state, false, &dnsgo.Error{Provider: provider.Kind(), Operation: "schedule_reconcile",
			Code: dnsgo.CodeResultUnknown, Message: "record outcome is unknown; inspect provider state before retrying", Cause: err}
	}
	switch task.Action {
	case ScheduleEnable, SchedulePause:
		wanted := task.Action == ScheduleEnable
		if record.Enabled == nil {
			return state, false, &dnsgo.Error{Provider: provider.Kind(), Operation: "schedule_reconcile",
				Code: dnsgo.CodeResultUnknown, Message: "provider did not return record status"}
		}
		if *record.Enabled != wanted {
			return state, false, nil
		}
	case ScheduleDelete:
		return state, false, nil // record still exists; caller decides whether to retry
	case ScheduleValue:
		if record.Value != task.Value || !strings.EqualFold(record.Type, recordTypeForValue(task.Value)) ||
			task.Line != "" && record.Line != task.Line || task.TTL > 0 && record.TTL != task.TTL {
			return state, false, nil
		}
		if task.Name != "" && !strings.EqualFold(strings.Trim(record.Name, "."), strings.Trim(task.Name, ".")) {
			return state, false, &dnsgo.Error{Provider: provider.Kind(), Operation: "schedule_reconcile",
				Code: dnsgo.CodeResultUnknown, Message: "record name differs from scheduled target"}
		}
	}
	if record.ID != "" {
		id = record.ID
	}
	finished, _, finishErr := completeSchedule(task, state, now, id)
	return finished, true, finishErr
}

// CompleteScheduleAfterInspection advances an interrupted task only after the
// operator has independently confirmed the intended DNS state.
func CompleteScheduleAfterInspection(task ScheduleTask, state ScheduleState, now time.Time, recordID string) (ScheduleState, error) {
	if !state.InFlight {
		return state, fmt.Errorf("schedule has no in-flight operation")
	}
	if err := task.validate(); err != nil {
		return state, err
	}
	if recordID == "" {
		recordID = state.RecordID
	}
	if recordID == "" {
		recordID = task.RecordID
	}
	finished, _, err := completeSchedule(task, state, now, recordID)
	return finished, err
}
