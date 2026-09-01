//go:build darwin || linux

package protocol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequiredReplayStateRejectsUnsafeFilesystemObjects(t *testing.T) {
	t.Run("parent mode", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := InitializeRequiredSequenceState(filepath.Join(parent, "state.json")); err == nil || !strings.Contains(err.Error(), "mode 0700") {
			t.Fatalf("unsafe parent mode error = %v", err)
		}
	})

	t.Run("parent symlink", func(t *testing.T) {
		root := t.TempDir()
		realParent := filepath.Join(root, "real")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedParent := filepath.Join(root, "linked")
		if err := os.Symlink(realParent, linkedParent); err != nil {
			t.Fatal(err)
		}
		if err := InitializeRequiredSequenceState(filepath.Join(linkedParent, "state.json")); err == nil || !strings.Contains(err.Error(), "real directory") {
			t.Fatalf("symlink parent error = %v", err)
		}
	})

	t.Run("file mode", func(t *testing.T) {
		path := newUnsafeReplayState(t, 0o640)
		if _, err := NewRequiredFileSequenceStore(path).Load(); err == nil || !strings.Contains(err.Error(), "mode 0600") {
			t.Fatalf("unsafe file mode error = %v", err)
		}
	})

	t.Run("file symlink", func(t *testing.T) {
		parent := secureReplayParent(t)
		target := filepath.Join(parent, "target.json")
		if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "state.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRequiredFileSequenceStore(link).Load(); err == nil {
			t.Fatal("required store followed a replay-state symlink")
		}
	})

	t.Run("non regular file", func(t *testing.T) {
		parent := secureReplayParent(t)
		path := filepath.Join(parent, "state.json")
		if err := os.Mkdir(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRequiredFileSequenceStore(path).Load(); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("non-regular file error = %v", err)
		}
	})

	t.Run("hard link", func(t *testing.T) {
		path := newUnsafeReplayState(t, 0o600)
		if err := os.Link(path, path+".second-link"); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRequiredFileSequenceStore(path).Load(); err == nil || !strings.Contains(err.Error(), "exactly one hard link") {
			t.Fatalf("hard-link error = %v", err)
		}
	})

	t.Run("ownership", func(t *testing.T) {
		path := newUnsafeReplayState(t, 0o600)
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		wrongUID := uint32(os.Geteuid() + 1)
		if err := validatePrivateReplayOwner(path, info, wrongUID); err == nil || !strings.Contains(err.Error(), "owned by uid") {
			t.Fatalf("ownership error = %v", err)
		}
	})

	t.Run("save revalidates", func(t *testing.T) {
		parent := secureReplayParent(t)
		path := filepath.Join(parent, "state.json")
		if err := InitializeRequiredSequenceState(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := NewRequiredFileSequenceStore(path).Save(map[string]int64{"source": 1}); err == nil {
			t.Fatal("required store saved through an unsafe replay-state file")
		}
	})
}

func secureReplayParent(t *testing.T) string {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return parent
}

func newUnsafeReplayState(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(secureReplayParent(t), "state.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
