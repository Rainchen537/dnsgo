// Package agent provides the optional DnsGo resident task runner. Importing
// this package is unnecessary for applications that only use the SDK.
package agent

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"github.com/rainchen537/dnsgo/notify"

	_ "modernc.org/sqlite"
)

// Store keeps task state and certificate key material in a local SQLite file.
// The containing directory and database must be accessible only by the owner.
type Store struct {
	db   *sql.DB
	path string
}

func OpenStore(path string) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("SQLite path must be absolute")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return nil, err
	}
	if info, err := os.Stat(parent); err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("SQLite directory must have owner-only permissions")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("SQLite file must be regular with owner-only permissions")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, query := range []string{
		"PRAGMA busy_timeout = 5000", "PRAGMA journal_mode = WAL", "PRAGMA synchronous = FULL",
		`CREATE TABLE IF NOT EXISTS task_state (
			kind TEXT NOT NULL, id TEXT NOT NULL, data BLOB NOT NULL,
			updated_at TEXT NOT NULL, PRIMARY KEY (kind, id)
		)`,
	} {
		if _, err := db.Exec(query); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return &Store{db: db, path: path}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// AcquireRunnerLock prevents two local agent processes from executing the
// same task database concurrently. It also guards manual state resolution.
func (s *Store) AcquireRunnerLock() (func() error, error) {
	path := s.path + ".lock"
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("agent lock file must be regular with owner-only permissions")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	lock := flock.New(path)
	locked, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, fmt.Errorf("another DnsGo agent is already using this database")
	}
	return lock.Unlock, nil
}

func (s *Store) Load(ctx context.Context, kind, id string, result any) (bool, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT data FROM task_state WHERE kind=? AND id=?", kind, id).Scan(&raw)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return false, fmt.Errorf("invalid stored %s state for %s: %w", kind, id, err)
	}
	return true, nil
}

func (s *Store) Save(ctx context.Context, kind, id string, state any) error {
	if kind == "" || id == "" {
		return fmt.Errorf("state kind and ID are required")
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO task_state(kind,id,data,updated_at) VALUES(?,?,?,?)
		ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at`,
		kind, id, data, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) Delete(ctx context.Context, kind, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM task_state WHERE kind=? AND id=?", kind, id)
	return err
}

// SaveWithEvent atomically persists the completed task transition and its
// notification. Delivery can be retried after a process restart.
func (s *Store) SaveWithEvent(ctx context.Context, kind, id string, state any, event notify.Event) error {
	return s.SaveManyWithEvent(ctx, kind, map[string]any{id: state}, event)
}

func (s *Store) SaveManyWithEvent(ctx context.Context, kind string, states map[string]any, event notify.Event) error {
	eventJSON, err := json.Marshal(PendingEvent{Event: event, Delivered: map[string]bool{}})
	if err != nil {
		return err
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for id, state := range states {
		if kind == "" || id == "" {
			return fmt.Errorf("state kind and ID are required")
		}
		stateJSON, err := json.Marshal(state)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO task_state(kind,id,data,updated_at) VALUES(?,?,?,?)
			ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at`, kind, id, stateJSON, now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO task_state(kind,id,data,updated_at) VALUES(?,?,?,?)",
		"outbox", hex.EncodeToString(random), eventJSON, now); err != nil {
		return err
	}
	return tx.Commit()
}

type PendingEvent struct {
	ID        string          `json:"-"`
	Event     notify.Event    `json:"event"`
	Delivered map[string]bool `json:"delivered,omitempty"`
}

func (s *Store) PendingEvents(ctx context.Context) ([]PendingEvent, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,data FROM task_state WHERE kind='outbox' ORDER BY updated_at LIMIT 100")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []PendingEvent
	for rows.Next() {
		var item PendingEvent
		var data []byte
		if err := rows.Scan(&item.ID, &data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &item); err != nil {
			return nil, err
		}
		// Early agent checkpoints stored the Event directly, before channel
		// receipts were tracked. Read those rows without losing the message.
		if item.Event.Kind == "" {
			if err := json.Unmarshal(data, &item.Event); err != nil {
				return nil, err
			}
		}
		if item.Delivered == nil {
			item.Delivered = map[string]bool{}
		}
		events = append(events, item)
	}
	return events, rows.Err()
}

func (s *Store) SavePendingEvent(ctx context.Context, item PendingEvent) error {
	return s.Save(ctx, "outbox", item.ID, item)
}
