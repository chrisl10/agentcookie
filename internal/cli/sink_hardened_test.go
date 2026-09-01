package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mvanhorn/agentcookie/internal/chrome"
	"github.com/mvanhorn/agentcookie/internal/config"
	"github.com/mvanhorn/agentcookie/internal/pairing"
	"github.com/mvanhorn/agentcookie/internal/protocol"
	"github.com/mvanhorn/agentcookie/internal/state"
)

func TestPairingCodesAreStdinOnly(t *testing.T) {
	if flag := pairCmd.Flags().Lookup("code"); flag != nil {
		t.Fatal("pair command still accepts the legacy --code argv flag")
	}
	pairStdinFlag := pairCmd.Flags().Lookup("code-stdin")
	if pairStdinFlag == nil {
		t.Fatal("pair command does not accept --code-stdin")
	}
	if flag := wizardInstallCmd.Flags().Lookup("code"); flag != nil {
		t.Fatal("wizard install still accepts the legacy --code argv flag")
	}
	wizardStdinFlag := wizardInstallCmd.Flags().Lookup("code-stdin")
	if wizardStdinFlag == nil {
		t.Fatal("wizard install does not accept --code-stdin")
	}
	if err := pairStdinFlag.Value.Set("true"); err != nil || !pairCodeStdin {
		t.Fatalf("pair --code-stdin was not accepted: enabled=%v err=%v", pairCodeStdin, err)
	}
	if err := pairStdinFlag.Value.Set("false"); err != nil {
		t.Fatalf("reset pair --code-stdin: %v", err)
	}
	if err := wizardStdinFlag.Value.Set("true"); err != nil || !wizardCodeStdin {
		t.Fatalf("wizard --code-stdin was not accepted: enabled=%v err=%v", wizardCodeStdin, err)
	}
	if err := wizardStdinFlag.Value.Set("false"); err != nil {
		t.Fatalf("reset wizard --code-stdin: %v", err)
	}

	code, err := readPairingCode(strings.NewReader("ABCD-EFGH-IJKL\n"))
	if err != nil {
		t.Fatalf("read pairing code from stdin: %v", err)
	}
	if code != "ABCD-EFGH-IJKL" {
		t.Fatal("stdin pairing code did not match")
	}
	listenUsage := wizardInstallCmd.Flags().Lookup("listen").Usage
	if strings.Contains(listenUsage, "0.0.0.0") || !strings.Contains(listenUsage, "Tailscale") || !strings.Contains(listenUsage, "wildcard") {
		t.Fatalf("wizard listener help does not describe safe tailnet detection/wildcard refusal: %q", listenUsage)
	}
}

func TestWizardPairingMetadataNeverPersistsOrForwardsSentinelCode(t *testing.T) {
	const sentinel = "SENT-INEL-CODE"
	testRoot := t.TempDir()
	infoPath := filepath.Join(testRoot, ".agentcookie", "pairing.json")
	oldConfigDir := common.ConfigDir
	oldPeer := wizardPeer
	common.ConfigDir = filepath.Join(testRoot, "config")
	wizardPeer = "sink.test"
	t.Cleanup(func() {
		common.ConfigDir = oldConfigDir
		wizardPeer = oldPeer
	})

	var statusOutput bytes.Buffer
	var secretOutput bytes.Buffer
	var persistedDuringPairing []byte
	runner := func(_ context.Context, _, _ string, statusWriter, secretWriter io.Writer) (*pairing.HandshakeResult, error) {
		body, err := os.ReadFile(infoPath)
		if err != nil {
			return nil, fmt.Errorf("read pairing metadata during handshake: %w", err)
		}
		persistedDuringPairing = body
		fmt.Fprintln(secretWriter, "agentcookie one-time pairing code:", sentinel)
		fmt.Fprintln(statusWriter, "safe pairing status")
		return &pairing.HandshakeResult{
			Key:         bytes.Repeat([]byte{0x42}, 32),
			Fingerprint: "safe-fingerprint",
			RemotePeer:  "sink.test",
		}, nil
	}

	result, err := beginSourcePairingWithRunner(context.Background(), "127.0.0.1:9998", "source.test", &statusOutput, &secretOutput, infoPath, runner)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(secretOutput.String(), sentinel) {
		t.Fatal("owner-attended secret writer did not receive sentinel")
	}
	var metadata map[string]string
	if err := json.Unmarshal(persistedDuringPairing, &metadata); err != nil {
		t.Fatalf("decode nonsecret pairing metadata: %v", err)
	}
	if _, exists := metadata["code"]; exists {
		t.Fatal("pairing.json retained a pairing-code field")
	}
	if metadata["peer"] == "" || metadata["pair_url"] == "" || metadata["status"] == "" {
		t.Fatalf("pairing.json omitted required nonsecret metadata: %#v", metadata)
	}
	for label, candidate := range map[string]string{
		"pairing.json": string(persistedDuringPairing),
		"status/log":   statusOutput.String(),
		"result":       fmt.Sprintf("%+v", result),
	} {
		if strings.Contains(candidate, sentinel) {
			t.Fatalf("%s leaked sentinel pairing code", label)
		}
	}
	if _, err := os.Stat(infoPath); !os.IsNotExist(err) {
		t.Fatalf("pairing metadata artifact survived pairing: %v", err)
	}
	if err := filepath.WalkDir(testRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(body, []byte(sentinel)) {
			return fmt.Errorf("artifact persisted sentinel pairing code: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type cliSecretWriterFunc func([]byte) (int, error)

func (write cliSecretWriterFunc) Write(data []byte) (int, error) {
	return write(data)
}

func TestWizardPairingSecretWriteFailureRemovesMetadataAndClosesListener(t *testing.T) {
	testRoot := t.TempDir()
	infoPath := filepath.Join(testRoot, ".agentcookie", "pairing.json")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()

	var statusOutput bytes.Buffer
	result, err := beginSourcePairing(
		context.Background(),
		addr,
		"source.test",
		&statusOutput,
		cliSecretWriterFunc(func([]byte) (int, error) {
			return 0, errors.New("injected controlling-terminal failure")
		}),
		infoPath,
	)
	if err == nil || result != nil {
		t.Fatalf("secret delivery failure did not fail closed: result=%v err=%v", result != nil, err)
	}
	if statusOutput.Len() != 0 {
		t.Fatal("status/log output was emitted after secret delivery failed")
	}
	if _, err := os.Stat(infoPath); !os.IsNotExist(err) {
		t.Fatalf("pairing.json survived secret delivery failure: %v", err)
	}
	conn, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if dialErr == nil {
		conn.Close()
		t.Fatal("pair listener remained reachable after secret delivery failed")
	}
	if err := filepath.WalkDir(testRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			return fmt.Errorf("secret delivery failure retained artifact: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func hardenedTestDeps(t *testing.T) (*config.SinkConfig, *protocol.SequenceTracker, *state.Writer, *state.SinkState, *sync.Mutex, *protocol.BlocklistMatcher) {
	t.Helper()
	cfg := &config.SinkConfig{HardenedLiveCDP: true, LiveCDP: config.LiveCDPRef{Enabled: true}}
	tracker, err := protocol.NewTrackerFromStore(protocol.NewMemorySequenceStore(nil))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, tracker, state.NewWriter(filepath.Join(t.TempDir(), "sink-state.json")), &state.SinkState{Role: "sink"}, &sync.Mutex{}, protocol.NewBlocklistMatcher(nil)
}

func TestHardenedSyncInjectFailureDoesNotAdvanceOrClaimSuccess(t *testing.T) {
	cfg, tracker, writer, sinkState, mu, matcher := hardenedTestDeps(t)
	old := liveCDPInject
	liveCDPInject = func(context.Context, string, []chrome.Cookie) (int, error) {
		return 0, errors.New("cookie .secret.example SID rejected")
	}
	t.Cleanup(func() { liveCDPInject = old })
	rec := httptest.NewRecorder()
	handleHardenedLiveCDPSync(rec, httptest.NewRequest("POST", "/sync", nil), cfg,
		&protocol.SyncEnvelope{SourceHostname: "source", Sequence: 1},
		[]chrome.Cookie{{HostKey: ".secret.example", Name: "SID", Value: "sensitive"}}, 0, matcher, tracker, writer, sinkState, mu)
	if rec.Code != 503 || tracker.Last("source") != 0 || sinkState.TotalWrites != 0 {
		t.Fatalf("failure must be non-2xx with no replay/status advance: code=%d last=%d writes=%d", rec.Code, tracker.Last("source"), sinkState.TotalWrites)
	}
	if body := rec.Body.String(); body != "live CDP injection failed\n" {
		t.Fatalf("response leaked details: %q", body)
	}
}

func TestHardenedSyncZeroContextsIsFailure(t *testing.T) {
	cfg, tracker, writer, sinkState, mu, matcher := hardenedTestDeps(t)
	old := liveCDPInject
	liveCDPInject = func(context.Context, string, []chrome.Cookie) (int, error) { return 0, nil }
	t.Cleanup(func() { liveCDPInject = old })
	rec := httptest.NewRecorder()
	handleHardenedLiveCDPSync(rec, httptest.NewRequest("POST", "/sync", nil), cfg,
		&protocol.SyncEnvelope{SourceHostname: "source", Sequence: 1},
		[]chrome.Cookie{{HostKey: ".example.com", Name: "session", Value: "sensitive"}}, 0, matcher, tracker, writer, sinkState, mu)
	if rec.Code != 503 || tracker.Last("source") != 0 || sinkState.TotalWrites != 0 {
		t.Fatalf("zero contexts must fail without replay/status advance: code=%d last=%d writes=%d", rec.Code, tracker.Last("source"), sinkState.TotalWrites)
	}
}

func TestHardenedSyncDurableCommitFailureDoesNotAckOrClaimSuccess(t *testing.T) {
	cfg, _, writer, sinkState, mu, matcher := hardenedTestDeps(t)
	store := protocol.NewMemorySequenceStore(nil)
	store.FailSave = errors.New("simulated durable write failure")
	tracker, err := protocol.NewTrackerFromStore(store)
	if err != nil {
		t.Fatal(err)
	}
	old := liveCDPInject
	liveCDPInject = func(context.Context, string, []chrome.Cookie) (int, error) { return 1, nil }
	t.Cleanup(func() { liveCDPInject = old })
	rec := httptest.NewRecorder()
	handleHardenedLiveCDPSync(rec, httptest.NewRequest("POST", "/sync", nil), cfg,
		&protocol.SyncEnvelope{SourceHostname: "source", Sequence: 1},
		[]chrome.Cookie{{HostKey: ".example.com", Name: "session", Value: "sensitive"}}, 0, matcher, tracker, writer, sinkState, mu)
	if rec.Code != 507 || tracker.Last("source") != 0 || sinkState.TotalWrites != 0 {
		t.Fatalf("commit failure must fail without replay/status advance: code=%d last=%d writes=%d", rec.Code, tracker.Last("source"), sinkState.TotalWrites)
	}
}

func TestHardenedSyncInjectThenDurableCommitThenAck(t *testing.T) {
	cfg, tracker, writer, sinkState, mu, matcher := hardenedTestDeps(t)
	old := liveCDPInject
	liveCDPInject = func(context.Context, string, []chrome.Cookie) (int, error) { return 2, nil }
	t.Cleanup(func() { liveCDPInject = old })
	rec := httptest.NewRecorder()
	handleHardenedLiveCDPSync(rec, httptest.NewRequest("POST", "/sync", nil), cfg,
		&protocol.SyncEnvelope{SourceHostname: "source", Sequence: 2},
		[]chrome.Cookie{{HostKey: ".example.com", Name: "session", Value: "sensitive"}}, 0, matcher, tracker, writer, sinkState, mu)
	if rec.Code != 200 || tracker.Last("source") != 2 || sinkState.TotalWrites != 1 || sinkState.LastWriteMode != "livecdp-hardened" {
		t.Fatalf("success contract failed: code=%d last=%d state=%+v", rec.Code, tracker.Last("source"), sinkState)
	}
}

func TestHardenedSyncRejectsStorageAndSecretsBeforeInjection(t *testing.T) {
	cfg, tracker, writer, sinkState, mu, matcher := hardenedTestDeps(t)
	called := false
	old := liveCDPInject
	liveCDPInject = func(context.Context, string, []chrome.Cookie) (int, error) { called = true; return 1, nil }
	t.Cleanup(func() { liveCDPInject = old })
	rec := httptest.NewRecorder()
	handleHardenedLiveCDPSync(rec, httptest.NewRequest("POST", "/sync", nil), cfg,
		&protocol.SyncEnvelope{SourceHostname: "source", Sequence: 3, LocalStorageTarball: []byte("forbidden"), Secrets: map[string]map[string]string{"x": {"TOKEN": "forbidden"}}},
		[]chrome.Cookie{{HostKey: ".example.com", Name: "session", Value: "sensitive"}}, 0, matcher, tracker, writer, sinkState, mu)
	if rec.Code != 422 || called || tracker.Last("source") != 0 || sinkState.TotalWrites != 0 || sinkState.TotalRejects != 0 || sinkState.LastError != "" {
		t.Fatalf("forbidden payload reached a side effect: code=%d called=%v last=%d state=%+v", rec.Code, called, tracker.Last("source"), sinkState)
	}
}
