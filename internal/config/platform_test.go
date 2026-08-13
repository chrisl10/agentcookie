package config

import (
	"runtime"
	"testing"
)

func TestIsDarwin(t *testing.T) {
	got := IsDarwin()
	want := runtime.GOOS == "darwin"
	if got != want {
		t.Errorf("IsDarwin() = %v, want %v (GOOS=%s)", got, want, runtime.GOOS)
	}
}

func TestIsLinux(t *testing.T) {
	got := IsLinux()
	want := runtime.GOOS == "linux"
	if got != want {
		t.Errorf("IsLinux() = %v, want %v (GOOS=%s)", got, want, runtime.GOOS)
	}
}
