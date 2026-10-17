package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/rainchen537/dnsgo/automation"
)

// scheduleIntentKey freezes the task parameters that determine a pending DNS
// write. If the YAML changes during recovery, the agent waits for inspection.
func scheduleIntentKey(task automation.ScheduleTask, state automation.ScheduleState) string {
	recordID := state.RecordID
	if recordID == "" {
		recordID = task.RecordID
	}
	location := ""
	if task.Location != nil {
		location = task.Location.String()
	}
	content, _ := json.Marshal(struct {
		Action   automation.ScheduleAction
		Cycle    automation.ScheduleCycle
		ZoneID   string
		RecordID string
		Name     string
		Value    string
		Line     string
		TTL      int
		At       time.Time
		Hour     int
		Minute   int
		Weekday  time.Weekday
		MonthDay int
		Timezone string
	}{task.Action, task.Cycle, task.ZoneID, recordID, task.Name, task.Value, task.Line, task.TTL,
		task.At, task.Hour, task.Minute, task.Weekday, task.MonthDay, location})
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
