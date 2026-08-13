//go:build darwin

package config

// IsDarwin reports whether the current build target is macOS.
func IsDarwin() bool { return true }

// IsLinux reports whether the current build target is Linux.
func IsLinux() bool { return false }
