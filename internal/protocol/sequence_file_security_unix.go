//go:build darwin || linux

package protocol

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func ensurePrivateReplayParent(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ensure replay state dir %s: %w", dir, err)
	}
	return validatePrivateReplayParent(dir)
}

func validatePrivateReplayParent(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("lstat replay state parent %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("replay state parent must be a real directory: %s", dir)
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("replay state parent must have mode 0700: %s has %04o", dir, info.Mode().Perm())
	}
	return validatePrivateReplayOwner(dir, info, uint32(os.Geteuid()))
}

func readPrivateReplayFile(path string) ([]byte, error) {
	if err := validatePrivateReplayParent(filepath.Dir(path)); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open replay state without symlink traversal %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("open replay state %s: invalid file descriptor", path)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("fstat replay state %s: %w", path, err)
	}
	if err := validatePrivateReplayFileInfo(path, info); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read replay state %s: %w", path, err)
	}
	return data, nil
}

func validatePrivateReplayFileInfo(path string, info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("replay state must be a regular file: %s", path)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("replay state must have mode 0600: %s has %04o", path, info.Mode().Perm())
	}
	if err := validatePrivateReplayOwner(path, info, uint32(os.Geteuid())); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("replay state ownership metadata is unavailable: %s", path)
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("replay state must have exactly one hard link: %s has %d", path, stat.Nlink)
	}
	return nil
}

func validatePrivateReplayOwner(path string, info os.FileInfo, expectedUID uint32) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("replay state ownership metadata is unavailable: %s", path)
	}
	if stat.Uid != expectedUID {
		return fmt.Errorf("replay state path must be owned by uid %d: %s is owned by uid %d", expectedUID, path, stat.Uid)
	}
	return nil
}
