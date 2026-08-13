//go:build linux

package config

// IsDarwin reports whether the current build target is macOS.
func IsDarwin() bool { return false }

// IsLinux reports whether the current build target is Linux.
func IsLinux() bool { return true }
