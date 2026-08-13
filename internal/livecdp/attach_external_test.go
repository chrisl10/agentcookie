package livecdp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/mvanhorn/agentcookie/internal/chrome"
)

func TestWaitForCDPEndpoint_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/json/version" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Browser": "test"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	err := waitForCDPEndpoint(context.Background(), srv.URL, 2*time.Second)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestWaitForCDPEndpoint_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := waitForCDPEndpoint(ctx, srv.URL, 300*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestWaitForCDPEndpoint_Unreachable(t *testing.T) {
	err := waitForCDPEndpoint(context.Background(), "http://127.0.0.1:59999", 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected connection error")
	}
}

func TestAttachAndInject_EmptyCookies(t *testing.T) {
	n, err := AttachAndInject(context.Background(), "http://127.0.0.1:59999", nil)
	if err != nil {
		t.Fatalf("empty cookies should succeed without connecting: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 contexts, got %d", n)
	}
}

// TestAttachAndInject_LiveChrome exercises attaching to a real Chrome.
// Gated behind AGENTCOOKIE_LIVE_CDP_TEST.
func TestAttachAndInject_LiveChrome(t *testing.T) {
	if os.Getenv("AGENTCOOKIE_LIVE_CDP_TEST") == "" {
		t.Skip("set AGENTCOOKIE_LIVE_CDP_TEST=1 to run live attach test")
	}

	cookies := []chrome.Cookie{
		{HostKey: "example.com", Name: "test_attach", Value: "attached", Path: "/", IsSecure: 0, SameSite: 1},
	}

	n, err := AttachAndInject(context.Background(), DefaultCDPEndpoint, cookies)
	if err != nil {
		t.Fatalf("AttachAndInject: %v", err)
	}
	t.Logf("injected into %d contexts", n)
}
