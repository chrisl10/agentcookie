package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mvanhorn/agentcookie/internal/config"
	"github.com/mvanhorn/agentcookie/internal/keystore"
	"github.com/mvanhorn/agentcookie/internal/pairing"
	"github.com/mvanhorn/agentcookie/internal/protocol"
	"github.com/mvanhorn/agentcookie/internal/tsclient"
)

var (
	pairRole       string
	pairListenAddr string
	pairLocalName  string
	pairPeerURL    string
	pairCodeStdin  bool
	pairPeerHost   string
)

var pairCmd = &cobra.Command{
	Use:   "pair",
	Short: "Pair source and sink machines with a one-time code over X25519 + HKDF",
	Long: `Run on the source machine first:

  agentcookie pair --as source

That prints a one-time pairing code and the source hostname + URL. Within
ten minutes, run on the sink machine:

  read -rsp 'Pairing code: ' AGENTCOOKIE_PAIR_CODE; printf '\n'
  printf '%s\n' "$AGENTCOOKIE_PAIR_CODE" | agentcookie pair --as sink \\
    --peer <source-hostname> --pair-url http://<source-hostname>:9998/pair \\
    --code-stdin
  unset AGENTCOOKIE_PAIR_CODE

Both sides derive a 32-byte symmetric key from an X25519 exchange salted
with the pairing code (HKDF-SHA256, info "agentcookie-pair-v1"). The
derived key is written to ~/.config/agentcookie/keys/<peer>.json with
mode 0600. macOS Keychain storage is a planned follow-up.

After pairing, 'agentcookie source --once' and 'agentcookie sink' look up
the key by the peer hostname configured in source.yaml / sink.yaml rather
than reading 'security.shared_secret' from those files.`,
	RunE: runPair,
}

func init() {
	pairCmd.Flags().StringVar(&pairRole, "as", "", "role: source | sink (required)")
	// v0.12 S1: --listen no longer defaults to 0.0.0.0:9998. Empty
	// triggers tailnet auto-detection; an explicit value is validated
	// against the same tailnet-or-loopback policy. The detection-failed
	// path fails loud rather than falling through to every interface.
	pairCmd.Flags().StringVar(&pairListenAddr, "listen", "", "[source] address to listen on for the sink handshake (default: this machine's Tailscale 100.x:9998)")
	pairCmd.Flags().StringVar(&pairLocalName, "local-name", "", "hostname identifier announced to the peer (defaults to os.Hostname)")
	pairCmd.Flags().StringVar(&pairPeerURL, "pair-url", "", "[sink] full URL of the source's /pair endpoint")
	pairCmd.Flags().BoolVar(&pairCodeStdin, "code-stdin", false, "[sink] read the required pairing code from stdin")
	pairCmd.Flags().StringVar(&pairPeerHost, "peer", "", "[sink] source machine's hostname (also used as filename for the derived key)")
}

func runPair(cmd *cobra.Command, args []string) error {
	if pairLocalName == "" {
		pairLocalName = pairing.LocalHostname()
	}
	switch strings.ToLower(pairRole) {
	case "source":
		return runPairAsSource(cmd.Context())
	case "sink":
		return runPairAsSink(cmd.Context(), cmd.InOrStdin())
	default:
		return fmt.Errorf("--as is required and must be 'source' or 'sink'")
	}
}

func runPairAsSource(ctx context.Context) error {
	// v0.12 S1: resolve and validate the pair listener address before
	// binding. Empty -> auto-detect tailnet 100.x; explicit -> must be
	// tailnet or loopback. 0.0.0.0 is refused.
	listenAddr := pairListenAddr
	if listenAddr == "" {
		ip, err := tsclient.RequireTailnetIP(ctx)
		if err != nil {
			return fmt.Errorf("detect Tailscale 100.x address for pair listener: %w", err)
		}
		listenAddr = fmt.Sprintf("%s:9998", ip)
	} else if err := validateListenAddr(listenAddr); err != nil {
		return fmt.Errorf("pair listen %q: %w", listenAddr, err)
	}
	secretTTY, err := openPairingSecretTTY()
	if err != nil {
		return err
	}
	defer secretTTY.Close()
	res, err := pairing.RunSource(ctx, listenAddr, pairLocalName, os.Stderr, secretTTY)
	if err != nil {
		return err
	}
	pk := &keystore.PeerKey{
		Peer:        res.RemotePeer,
		Key:         res.Key,
		PairedAt:    res.PairedAt,
		Fingerprint: res.Fingerprint,
		ProtocolVer: pairing.ProtocolVersion,
	}
	if err := keystore.Save(common.ConfigDir, pk); err != nil {
		return fmt.Errorf("save key: %w", err)
	}
	fmt.Fprintf(os.Stderr, "\nagentcookie pair: paired with sink %q (fingerprint %s)\n", res.RemotePeer, res.Fingerprint)
	fmt.Fprintf(os.Stderr, "  key saved to %s/keys/%s.json (mode 0600)\n", common.ConfigDir, res.RemotePeer)
	return nil
}

func runPairAsSink(ctx context.Context, input io.Reader) error {
	if pairPeerURL == "" {
		return fmt.Errorf("--pair-url is required when --as sink")
	}
	if !pairCodeStdin {
		return fmt.Errorf("--code-stdin is required when --as sink; pairing codes in process arguments are not supported")
	}
	pairCode, err := readPairingCode(input)
	if err != nil {
		return err
	}
	defer func() { pairCode = "" }()
	if pairPeerHost == "" {
		return fmt.Errorf("--peer is required when --as sink (the source machine's hostname)")
	}
	res, err := pairing.RunSink(ctx, pairPeerURL, pairCode, pairLocalName)
	if err != nil {
		return err
	}
	pk := &keystore.PeerKey{
		Peer:        pairPeerHost,
		Key:         res.Key,
		PairedAt:    res.PairedAt,
		Fingerprint: res.Fingerprint,
		ProtocolVer: pairing.ProtocolVersion,
	}
	sinkCfg, cfgErr := config.LoadSink(common.ConfigDir)
	if cfgErr != nil {
		return fmt.Errorf("load sink config before saving pair key: %w", cfgErr)
	}
	if sinkCfg.HardenedLiveCDP {
		if err := protocol.InitializeRequiredSequenceState(sinkCfg.ReplayStatePath); err != nil {
			return fmt.Errorf("initialize hardened replay state before saving pair key: %w", err)
		}
	}
	if err := keystore.Save(common.ConfigDir, pk); err != nil {
		return fmt.Errorf("save key: %w", err)
	}
	fmt.Fprintf(os.Stderr, "agentcookie pair: paired with source %q (fingerprint %s)\n", pairPeerHost, res.Fingerprint)
	fmt.Fprintf(os.Stderr, "  key saved to %s/keys/%s.json (mode 0600)\n", common.ConfigDir, pairPeerHost)
	return nil
}

func openPairingSecretTTY() (*os.File, error) {
	secretTTY, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open controlling terminal for owner-attended pairing code: %w", err)
	}
	return secretTTY, nil
}

func readPairingCode(input io.Reader) (pairing.Code, error) {
	value, err := bufio.NewReader(io.LimitReader(input, 257)).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read pairing code from stdin")
	}
	code := strings.TrimSpace(value)
	if len(code) > 128 {
		return "", fmt.Errorf("pairing code from stdin is too long")
	}
	if len(code) < 8 {
		return "", fmt.Errorf("pairing code from stdin is too short")
	}
	for _, character := range code {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' {
			return "", fmt.Errorf("pairing code from stdin has invalid characters")
		}
	}
	return pairing.Code(code), nil
}
