package livecdp

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/mvanhorn/agentcookie/internal/chrome"
)

// DefaultCDPEndpoint is the default Chrome DevTools Protocol endpoint for
// attach-mode injection. Grok Bot and similar agent runtimes launch Chrome
// with --remote-debugging-port=9223 on loopback, so this is the canonical
// attach address for Linux sink injection.
const DefaultCDPEndpoint = "http://127.0.0.1:9223"

// AttachAndInject connects to an already-running Chrome instance at the given
// CDP endpoint and injects cookies into all browser contexts. This is the
// Linux sink's primary injection path: no Keychain, no Chrome SQLite rewrite,
// just live CDP injection into a Chrome that was launched by the agent runtime.
//
// Returns the number of contexts injected and any error. An unreachable
// endpoint returns an error (the caller should advise starting Chrome with
// --remote-debugging-port).
func AttachAndInject(ctx context.Context, endpoint string, cookies []chrome.Cookie) (int, error) {
	if endpoint == "" {
		endpoint = DefaultCDPEndpoint
	}
	if len(cookies) == 0 {
		return 0, nil
	}

	if err := waitForCDPEndpoint(ctx, endpoint, 5*time.Second); err != nil {
		return 0, fmt.Errorf("livecdp: cannot reach CDP endpoint %s: %w (start Chrome with --remote-debugging-port=9223)", endpoint, err)
	}

	allocCtx, allocCancel := chromedp.NewRemoteAllocator(ctx, endpoint+"/json/version")
	defer allocCancel()

	browserCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	return InjectAllContexts(browserCtx, cookies)
}

// AttachSyncer creates a Syncer bound to an already-running Chrome at the
// given CDP endpoint. Unlike LaunchOwnedChrome, this does NOT spawn a new
// Chrome process - it attaches to one the agent runtime (e.g., Grok Bot)
// already started. The Syncer polls for new browser contexts and injects
// cookies into each.
func AttachSyncer(ctx context.Context, endpoint string, provider CookieProvider, log func(string, ...any)) (*Syncer, context.CancelFunc, error) {
	if endpoint == "" {
		endpoint = DefaultCDPEndpoint
	}

	if err := waitForCDPEndpoint(ctx, endpoint, 10*time.Second); err != nil {
		return nil, nil, fmt.Errorf("livecdp: cannot reach CDP endpoint %s: %w (start Chrome with --remote-debugging-port=9223)", endpoint, err)
	}

	allocCtx, allocCancel := chromedp.NewRemoteAllocator(ctx, endpoint+"/json/version")
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)

	cleanup := func() {
		browserCancel()
		allocCancel()
	}

	syncer := NewSyncer(browserCtx, provider, log)
	return syncer, cleanup, nil
}

// waitForCDPEndpoint polls the CDP /json/version endpoint until it responds
// 200 or the timeout elapses. Unlike waitForCDP in launch.go, this is for
// attaching to an existing Chrome (not one we just spawned).
func waitForCDPEndpoint(ctx context.Context, endpoint string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	var lastErr error

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		resp, err := client.Get(endpoint + "/json/version")
		if err != nil {
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		lastErr = fmt.Errorf("CDP endpoint returned %d", resp.StatusCode)
		time.Sleep(200 * time.Millisecond)
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("CDP endpoint %s not reachable within %s", endpoint, timeout)
}
