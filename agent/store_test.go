package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestStorePrivatePermissionsAndSingleRunner(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "state.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Save(context.Background(), "schedule", "one", map[string]string{"state": "ready"}); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(candidate)
		if os.IsNotExist(err) {
			continue // SQLite may checkpoint and remove WAL sidecars.
		}
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0077 != 0 {
			t.Fatalf("%s is accessible outside its owner: %o", candidate, info.Mode().Perm())
		}
	}
	unlock, err := store.AcquireRunnerLock()
	if err != nil {
		t.Fatal(err)
	}
	lockInfo, err := os.Stat(path + ".lock")
	if err != nil || lockInfo.Mode().Perm()&0077 != 0 {
		t.Fatalf("agent lock file permissions are not owner-only: %v", err)
	}
	if _, err := store.AcquireRunnerLock(); err == nil {
		t.Fatal("second runner acquired the same database lock")
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	unlock, err = store.AcquireRunnerLock()
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
}
