package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
)

// SequenceStore is the persistence backend a SequenceTracker reads at
// startup and writes to on every accepted envelope. The default
// implementation is fileSequenceStore at ~/.agentcookie/sequence.json
// (mode 0600). Tests inject MemorySequenceStore or a path under
// t.TempDir() to keep the on-disk file out of the user's home.
type SequenceStore interface {
	// Load returns the persisted map of source-hostname to highest
	// accepted sequence. A missing file is not an error; Load returns
	// an empty map and nil. A present-but-corrupt file IS an error,
	// surfaced so the sink can refuse to start.
	Load() (map[string]int64, error)
	// Save writes state atomically (write-tmp-then-rename) at mode 0600.
	Save(state map[string]int64) error
}

// fileSequenceStore writes JSON to a path on disk. Atomic via
// CreateTemp + Rename, mirroring internal/state/state.go.Writer.Save.
type fileSequenceStore struct {
	path            string
	requireExisting bool
}

// NewFileSequenceStore returns a SequenceStore backed by path. The
// parent directory is created (mode 0700) on the first Save when
// missing. path is typically filepath.Join(home, ".agentcookie",
// "sequence.json").
func NewFileSequenceStore(path string) SequenceStore {
	return &fileSequenceStore{path: path}
}

// NewRequiredFileSequenceStore returns a store that rejects a missing state
// file. Hardened sinks use this after provisioning an explicit empty JSON
// object before pairing, so deletion or rollback never silently resets replay
// protection.
func NewRequiredFileSequenceStore(path string) SequenceStore {
	return &fileSequenceStore{path: path, requireExisting: true}
}

// InitializeRequiredSequenceState creates a valid empty replay file exactly
// once. It never truncates or resets an existing file. Pairing calls this
// before persisting the sink key so a paired sink can never start without
// initialized replay defense.
func InitializeRequiredSequenceState(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("replay state path must be absolute")
	}
	dir := filepath.Dir(path)
	if err := ensurePrivateReplayParent(dir); err != nil {
		return err
	}
	if _, err := readPrivateReplayFile(path); err == nil {
		_, loadErr := NewRequiredFileSequenceStore(path).Load()
		return loadErr
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat replay state %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create replay state %s: %w", path, err)
	}
	cleanup := func() { _ = os.Remove(path) }
	if _, err := f.WriteString("{}\n"); err != nil {
		f.Close()
		cleanup()
		return fmt.Errorf("initialize replay state: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		cleanup()
		return fmt.Errorf("fsync replay state: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close replay state: %w", err)
	}
	if _, err := readPrivateReplayFile(path); err != nil {
		cleanup()
		return fmt.Errorf("validate initialized replay state: %w", err)
	}
	parent, err := os.Open(dir)
	if err != nil {
		cleanup()
		return fmt.Errorf("open replay parent for fsync: %w", err)
	}
	if err := parent.Sync(); err != nil {
		parent.Close()
		cleanup()
		return fmt.Errorf("fsync replay parent: %w", err)
	}
	return parent.Close()
}

// DefaultSequencePath is the canonical on-disk location of the
// persistent replay-defense state.
func DefaultSequencePath(home string) string {
	return filepath.Join(home, ".agentcookie", "sequence.json")
}

func (s *fileSequenceStore) Load() (map[string]int64, error) {
	var data []byte
	var err error
	if s.requireExisting {
		data, err = readPrivateReplayFile(s.path)
	} else {
		data, err = os.ReadFile(s.path)
	}
	if err != nil {
		if os.IsNotExist(err) {
			if s.requireExisting {
				return nil, fmt.Errorf("required replay state is missing: %s", s.path)
			}
			return map[string]int64{}, nil
		}
		return nil, fmt.Errorf("read sequence state %s: %w", s.path, err)
	}
	// Empty file is treated as fresh state (no high-water marks yet).
	if len(data) == 0 {
		if s.requireExisting {
			return nil, fmt.Errorf("required replay state is empty: %s", s.path)
		}
		return map[string]int64{}, nil
	}
	state := map[string]int64{}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse sequence state %s: %w (delete this file to reset replay-defense state)", s.path, err)
	}
	return state, nil
}

func (s *fileSequenceStore) Save(state map[string]int64) error {
	dir := filepath.Dir(s.path)
	if s.requireExisting {
		if _, err := readPrivateReplayFile(s.path); err != nil {
			return fmt.Errorf("validate required replay state before save: %w", err)
		}
	} else if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ensure sequence dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-sequence-*.json")
	if err != nil {
		return fmt.Errorf("create tmp sequence file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Best-effort chmod on the tmp file before write; final rename
	// preserves these bits on the destination.
	if err := os.Chmod(tmpName, 0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("chmod tmp sequence file: %w", err)
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(state); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("encode sequence state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("fsync tmp sequence file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close tmp sequence file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename sequence file into place: %w", err)
	}
	if s.requireExisting {
		if _, err := readPrivateReplayFile(s.path); err != nil {
			return fmt.Errorf("validate required replay state after save: %w", err)
		}
	}
	parent, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open sequence parent for fsync: %w", err)
	}
	if err := parent.Sync(); err != nil {
		parent.Close()
		return fmt.Errorf("fsync sequence parent: %w", err)
	}
	if err := parent.Close(); err != nil {
		return fmt.Errorf("close sequence parent: %w", err)
	}
	return nil
}

// MemorySequenceStore is an in-memory SequenceStore for tests. Captures
// every Save so test assertions can verify write-through behavior.
type MemorySequenceStore struct {
	State     map[string]int64
	SaveCount int
	// FailLoad, when non-nil, is returned from Load. Lets tests
	// exercise the sink-refuse-to-start path without writing a
	// corrupt file to disk.
	FailLoad error
	// FailSave, when non-nil, is returned from every Save call. Lets
	// tests exercise the write-through failure path.
	FailSave error
}

// NewMemorySequenceStore returns a MemorySequenceStore seeded with the
// given state. Pass nil for an empty store.
func NewMemorySequenceStore(seed map[string]int64) *MemorySequenceStore {
	st := map[string]int64{}
	maps.Copy(st, seed)
	return &MemorySequenceStore{State: st}
}

func (m *MemorySequenceStore) Load() (map[string]int64, error) {
	if m.FailLoad != nil {
		return nil, m.FailLoad
	}
	out := map[string]int64{}
	maps.Copy(out, m.State)
	return out, nil
}

func (m *MemorySequenceStore) Save(state map[string]int64) error {
	if m.FailSave != nil {
		return m.FailSave
	}
	m.SaveCount++
	cp := map[string]int64{}
	maps.Copy(cp, state)
	m.State = cp
	return nil
}
