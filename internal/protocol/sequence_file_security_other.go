//go:build !darwin && !linux

package protocol

import "fmt"

func ensurePrivateReplayParent(string) error {
	return fmt.Errorf("required replay state is supported only on Darwin and Linux")
}

func readPrivateReplayFile(string) ([]byte, error) {
	return nil, fmt.Errorf("required replay state is supported only on Darwin and Linux")
}
