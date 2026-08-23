package server

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProbeExecutionToolPathIdentityBindsExactBytes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("router executable identity contract is Linux-only")
	}
	path := filepath.Join(t.TempDir(), "nft")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 'nftables v1.1.0'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := probeExecutionToolPathIdentity(context.Background(), executionToolNFT, path)
	if err != nil || !validExecutionToolIdentity(first, executionToolNFT) {
		t.Fatalf("identity=%+v error=%v", first, err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 'nftables v1.1.1'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	second, err := probeExecutionToolPathIdentity(context.Background(), executionToolNFT, path)
	if err != nil || second.ContentSHA256 == first.ContentSHA256 || second.Version == first.Version {
		t.Fatalf("replacement identity=%+v first=%+v error=%v", second, first, err)
	}
}

func TestExactKernelToolRunnerUsesCapturedAbsolutePath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("router executable identity contract is Linux-only")
	}
	path := filepath.Join(t.TempDir(), "nft")
	if err := os.WriteFile(path, []byte("#!/bin/sh\ncat >/dev/null\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := probeExecutionToolPathIdentity(context.Background(), executionToolNFT, path)
	if err == nil {
		t.Fatal("fixture unexpectedly reported a version")
	}
	// The runner validates the already captured identity shape; use fixed version text while keeping
	// the exact resolved path and digest from a separate version-capable capture.
	if err := os.WriteFile(path, []byte("#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'nftables v1.1.0'; else cat >/dev/null; fi\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := probeExecutionToolPathIdentity(context.Background(), executionToolNFT, path)
	if err != nil {
		t.Fatal(err)
	}
	runner := exactKernelToolRunner{nft: identity}
	if _, err := runner.Run(context.Background(), "table inet x {}", executionToolNFT, "-f", "-"); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), "bad", executionToolIP, "rule", "add"); err == nil {
		t.Fatal("foreign tool or stdin crossed the pinned runner")
	}
}

func TestBusyBoxIPIdentityAndRunnerUseExplicitApplet(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("router executable identity contract is Linux-only")
	}
	path := filepath.Join(t.TempDir(), "busybox")
	script := `#!/bin/sh
[ "$1" = ip ] || exit 9
shift
case "$*" in
  "-o link show dev lo") echo "1: lo: <LOOPBACK,UP> mtu 65536" ;;
  "rule show") echo "100: from all lookup main" ;;
  *) exit 8 ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := probeExecutionToolPathIdentity(context.Background(), executionToolIP, path)
	if err != nil || identity.Version != executionBusyBoxIPVersion ||
		!validExecutionToolIdentity(identity, executionToolIP) {
		t.Fatalf("BusyBox ip identity=%+v error=%v", identity, err)
	}
	output, err := (exactKernelToolRunner{ip: identity}).Run(
		context.Background(), "", executionToolIP, "rule", "show",
	)
	if err != nil || !strings.Contains(output, "lookup main") {
		t.Fatalf("BusyBox ip runner output=%q error=%v", output, err)
	}
}

func TestExactKernelToolRunnerRetainsBoundedStderrForAbsentClassification(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("router executable identity contract is Linux-only")
	}
	path := filepath.Join(t.TempDir(), "busybox")
	script := `#!/bin/sh
[ "$1" = ip ] || exit 9
shift
if [ "$*" = "-o link show dev lo" ]; then
  echo "1: lo: <LOOPBACK,UP> mtu 65536"
  exit 0
fi
echo "RTNETLINK answers: No such process" >&2
exit 2
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := probeExecutionToolPathIdentity(context.Background(), executionToolIP, path)
	if err != nil {
		t.Fatal(err)
	}
	command := "ip rule del fwmark 0x1"
	_, err = (exactKernelToolRunner{ip: identity}).Run(
		context.Background(), "", executionToolIP, "rule", "del", "fwmark", "0x1",
	)
	if err == nil || !strings.Contains(err.Error(), "No such process") ||
		!exactKernelAlreadyAbsent(command, err) {
		t.Fatalf("stderr classification error = %v", err)
	}
}
