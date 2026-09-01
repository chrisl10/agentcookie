package protocol

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReservationDoesNotAdvanceUntilCommit(t *testing.T) {
	store := NewMemorySequenceStore(nil)
	tracker, err := NewTrackerFromStore(store)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := tracker.Reserve("source", 10)
	if !ok || tracker.seen["source"] != 0 || store.SaveCount != 0 {
		t.Fatal("reserve advanced replay state before external side effect")
	}
	if err := r.Commit(); err != nil {
		t.Fatal(err)
	}
	if tracker.Last("source") != 10 || store.SaveCount != 1 {
		t.Fatal("commit did not durably advance replay state")
	}
}

func TestRequiredReplayStateInitializationIsCreateOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "replay-state.json")
	if err := InitializeRequiredSequenceState(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode: info=%v err=%v", info, err)
	}
	parentInfo, err := os.Stat(filepath.Dir(path))
	if err != nil || parentInfo.Mode().Perm() != 0o700 {
		t.Fatalf("parent mode: info=%v err=%v", parentInfo, err)
	}
	store := NewRequiredFileSequenceStore(path)
	tracker, err := NewTrackerFromStore(store)
	if err != nil {
		t.Fatal(err)
	}
	if !tracker.Accept("source", 10) {
		t.Fatal("initial accept failed")
	}
	if err := InitializeRequiredSequenceState(path); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewTrackerFromStore(store)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Last("source") != 10 {
		t.Fatal("initializer reset existing replay state")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTrackerFromStore(store); err == nil {
		t.Fatal("required store accepted missing replay state")
	}
}
