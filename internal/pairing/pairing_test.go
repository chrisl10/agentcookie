package pairing

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewCodeIsCanonical(t *testing.T) {
	c, err := NewCode()
	if err != nil {
		t.Fatal(err)
	}
	s := string(c)
	// 12 chars + 2 hyphens = 14
	if len(s) != CodeLength+2 {
		t.Fatalf("expected %d chars including hyphens, got %d (%q)", CodeLength+2, len(s), s)
	}
	if s[4] != '-' || s[9] != '-' {
		t.Errorf("expected hyphens at index 4 and 9, got %q", s)
	}
}

func TestCodeNormalize(t *testing.T) {
	cases := map[string]string{
		"abcd-efgh-ijkl":   "ABCD-EFGH-IJKL",
		"ABCDEFGHIJKL":     "ABCD-EFGH-IJKL",
		"abcdefghijkl":     "ABCD-EFGH-IJKL",
		"ab cd-ef gh-ijkl": "ABCD-EFGH-IJKL",
	}
	for in, want := range cases {
		got := Code(in).Normalize().String()
		if got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCodeEqualConstantTime(t *testing.T) {
	a := Code("ABCD-EFGH-IJKL")
	if !a.Equal(Code("abcd-efgh-ijkl")) {
		t.Error("case-insensitive equal failed")
	}
	if a.Equal(Code("ZZZZ-ZZZZ-ZZZZ")) {
		t.Error("different codes reported equal")
	}
}

func TestDeriveKeySymmetric(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 32)
	code := Code("ABCD-EFGH-IJKL")
	k1, fp1, err := DeriveKey(secret, code)
	if err != nil {
		t.Fatal(err)
	}
	k2, fp2, err := DeriveKey(secret, code)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("identical inputs produced different keys")
	}
	if fp1 != fp2 {
		t.Errorf("fingerprints differ: %s vs %s", fp1, fp2)
	}
	if len(k1) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(k1))
	}
}

func TestDeriveKeyDiffersOnDifferentCode(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 32)
	k1, _, _ := DeriveKey(secret, Code("ABCD-EFGH-IJKL"))
	k2, _, _ := DeriveKey(secret, Code("ZZZZ-ZZZZ-ZZZZ"))
	if bytes.Equal(k1, k2) {
		t.Error("different codes must produce different derived keys (MITM defense)")
	}
}

func TestDeriveKeyDiffersOnDifferentSecret(t *testing.T) {
	code := Code("ABCD-EFGH-IJKL")
	k1, _, _ := DeriveKey(bytes.Repeat([]byte{0x01}, 32), code)
	k2, _, _ := DeriveKey(bytes.Repeat([]byte{0x02}, 32), code)
	if bytes.Equal(k1, k2) {
		t.Error("different shared secrets must produce different keys")
	}
}

// TestRunSourceTimesOut proves the source-side listener does not hang forever
// when no sink connects.
func TestRunSourceTimesOut(t *testing.T) {
	// Override the timeout via a context.
	addr := freeAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := RunSource(ctx, addr, "laptop.test", io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestRunSourcePrintsStdinOnlyPairingCommand(t *testing.T) {
	addr := freeAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	var output bytes.Buffer
	var secretOutput bytes.Buffer
	_, _ = RunSource(ctx, addr, "laptop.test", &output, &secretOutput)
	text := output.String()
	if strings.Contains(text, " --code ") {
		t.Fatalf("pairing output put the one-time code in argv: %s", text)
	}
	if !strings.Contains(text, "--code-stdin") || !strings.Contains(text, "read -rsp") {
		t.Fatalf("pairing output omitted the stdin-only command: %s", text)
	}
	secretFields := strings.Fields(secretOutput.String())
	if len(secretFields) == 0 {
		t.Fatal("owner-attended secret writer did not receive the pairing code")
	}
	code := secretFields[len(secretFields)-1]
	if strings.Contains(text, code) {
		t.Fatal("status output leaked the one-time code")
	}
}

func TestRunSourceSentinelAppearsOnlyOnOwnerSecretWriter(t *testing.T) {
	const sentinel = "SENT-INEL-CODE"
	addr := freeAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var statusOutput bytes.Buffer
	var secretOutput bytes.Buffer
	type sourceResult struct {
		result *HandshakeResult
		err    error
	}
	resultCh := make(chan sourceResult, 1)
	go func() {
		result, err := runSourceWithCode(ctx, addr, "laptop.test", Code(sentinel), &statusOutput, &secretOutput)
		resultCh <- sourceResult{result: result, err: err}
	}()
	waitForListen(t, addr)

	sinkResult, err := RunSink(ctx, "http://"+addr+"/pair", Code(sentinel), "sink.test")
	if err != nil {
		t.Fatalf("sink pairing: %v", err)
	}
	source := <-resultCh
	if source.err != nil {
		t.Fatalf("source pairing: %v", source.err)
	}
	if !strings.Contains(secretOutput.String(), sentinel) {
		t.Fatal("sentinel was not delivered to the owner-attended secret writer")
	}
	for label, candidate := range map[string]string{
		"status":        statusOutput.String(),
		"source result": fmt.Sprintf("%+v", source.result),
		"sink result":   fmt.Sprintf("%+v", sinkResult),
	} {
		if strings.Contains(candidate, sentinel) {
			t.Fatalf("%s leaked sentinel pairing code", label)
		}
	}
}

type secretWriterFunc func([]byte) (int, error)

func (write secretWriterFunc) Write(data []byte) (int, error) {
	return write(data)
}

func TestRunSourceSecretWriteFailureClosesListenerWithoutLeak(t *testing.T) {
	const sentinel = "SENT-INEL-CODE"
	tests := map[string]io.Writer{
		"error": secretWriterFunc(func([]byte) (int, error) {
			return 0, errors.New("injected terminal write failure")
		}),
		"short write": secretWriterFunc(func(data []byte) (int, error) {
			return len(data) - 1, nil
		}),
	}
	for name, secretWriter := range tests {
		t.Run(name, func(t *testing.T) {
			addr := freeAddr(t)
			var statusOutput bytes.Buffer
			result, err := runSourceWithCode(context.Background(), addr, "source.test", Code(sentinel), &statusOutput, secretWriter)
			if err == nil || result != nil {
				t.Fatalf("secret write failure did not fail closed: result=%v err=%v", result != nil, err)
			}
			if strings.Contains(err.Error(), sentinel) || strings.Contains(statusOutput.String(), sentinel) {
				t.Fatal("secret write failure leaked the pairing code")
			}
			if statusOutput.Len() != 0 {
				t.Fatal("status output was emitted after secret delivery failed")
			}
			conn, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if dialErr == nil {
				conn.Close()
				t.Fatal("pair listener remained reachable after secret delivery failed")
			}
		})
	}
}

// TestRunSourceRejectsBadCode exercises the source's auth path: spin up the
// listener, post a request with the wrong code, expect 401 and no derived key.
func TestRunSourceRejectsBadCode(t *testing.T) {
	addr := freeAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Go(func() {
		// Source-side error not checked: we cancel the ctx below, which
		// returns context.Canceled. The signal we care about is that the
		// sink call returns the right rejection.
		_, _ = RunSource(ctx, addr, "laptop.test", io.Discard, io.Discard)
	})

	waitForListen(t, addr)

	// Post with a known-wrong code.
	curve := ecdh.X25519()
	priv, _ := curve.GenerateKey(rand.Reader)
	_, err := RunSink(ctx, "http://"+addr+"/pair", Code("WRON-GCOD-EXXX"), "macmini.test")
	if err == nil {
		t.Error("sink should fail with wrong code")
	}
	if !strings.Contains(err.Error(), "invalid pairing code") {
		t.Errorf("expected 'invalid pairing code', got: %v", err)
	}
	_ = priv
	cancel()
	wg.Wait()
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitForListen(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener never came up on %s", addr)
}
