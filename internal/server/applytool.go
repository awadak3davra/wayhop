package server

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const executionToolProbeTimeout = 5 * time.Second

const executionBusyBoxIPVersion = "BusyBox ip applet"

// executionShellProbeVersion is the identity text for an interpreter that has no version flag. The
// file's SHA-256 is the identity that matters; this only records how it was proven to work.
const executionShellProbeVersion = "POSIX shell (echo probe)"

// executionMulticallHosts are the multicall binaries a router's tool symlinks resolve to. Such a
// binary dispatches on argv[0], so invoking it by its RESOLVED path — which is what identity
// verification requires — needs the applet name passed as argv[1] instead.
//
// Entware does this for the whole iptables family: /opt/sbin/iptables and /opt/sbin/ip6tables are
// both symlinks to xtables-multi, and calling that path directly answers "ERROR: No valid subcommand
// given". BusyBox does the same for ip. Naming the hosts once keeps the probe, the argv runner and
// the rendered shell preamble from each inventing their own rule.
var executionMulticallHosts = map[string]bool{"busybox": true, "xtables-multi": true}

// executionMulticallApplet returns the applet argument a resolved path needs, or "" when the binary
// is called directly.
func executionMulticallApplet(resolvedPath, tool string) string {
	if executionMulticallHosts[filepath.Base(resolvedPath)] {
		return tool
	}
	return ""
}

// probeExecutionToolIdentity captures the exact executable used by the strict kernel plane. The
// digest is checked again after the version process exits so a path replacement cannot pair H1
// bytes with H2 output. Only nft/ip are part of the 0.5.5 production contract.
func probeExecutionToolIdentity(ctx context.Context, tool string) (ExecutionToolIdentityV1, error) {
	if ctx == nil {
		return ExecutionToolIdentityV1{Tool: tool}, errExecutionCaptureUnavailable
	}
	located, err := exec.LookPath(tool)
	if err != nil {
		return ExecutionToolIdentityV1{Tool: tool}, errExecutionCaptureUnavailable
	}
	return probeExecutionToolPathIdentity(ctx, tool, located)
}

func probeExecutionToolPathIdentity(
	ctx context.Context,
	tool string,
	located string,
) (ExecutionToolIdentityV1, error) {
	identity := ExecutionToolIdentityV1{Tool: tool}
	if ctx == nil || located == "" {
		return identity, errExecutionCaptureUnavailable
	}
	resolved, err := filepath.EvalSymlinks(located)
	if err != nil {
		return identity, errExecutionCaptureUnavailable
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil || !validExecutionRouterPath(filepath.ToSlash(resolved)) {
		return identity, errExecutionCaptureUnavailable
	}
	// Router paths are slash-based. filepath.Abs on Linux already uses '/', while ToSlash keeps the
	// test helper deterministic on non-router hosts without granting Windows production support.
	resolved = filepath.ToSlash(resolved)
	var args []string
	busyBoxIP := false
	// probeEcho proves a tool runs without asking it for a version it does not have. The SHA-256 of
	// the exact file is the real identity in that case; this only establishes that the binary is the
	// working interpreter/applet host it claims to be.
	probeEcho := ""
	switch tool {
	case executionToolNFT:
		args = []string{"--version"}
	case executionToolIpset, executionToolIptables, executionToolIp6tables:
		args = []string{"--version"}
		if applet := executionMulticallApplet(resolved, tool); applet != "" {
			args = append([]string{applet}, args...)
		}
	case executionToolDnsmasq:
		args = []string{"--version"}
	case executionToolShell:
		// KeeneticOS ships BusyBox ash, which has no --version. Prove it executes a command and
		// returns its output; the file digest carries the identity. /opt/usr/bin/sh is itself a
		// BusyBox symlink there, so the applet rule applies to the interpreter too — without it the
		// probe runs `busybox -c …` and BusyBox answers "-c: applet not found".
		probeEcho = "wayhop-shell-probe"
		args = []string{"-c", "echo " + probeEcho}
		if applet := executionMulticallApplet(resolved, tool); applet != "" {
			args = append([]string{applet}, args...)
		}
	case executionToolIP:
		// OpenWrt commonly exposes /sbin/ip as a symlink to the BusyBox multicall binary. The
		// resolved executable does not accept iproute2's -Version, and invoking it by resolved path
		// requires the applet name as argv[1]. Prove that exact binary carries a working ip applet
		// with a bounded read-only loopback query; its SHA-256 is the actual version identity.
		busyBoxIP = filepath.Base(resolved) == "busybox"
		if busyBoxIP {
			args = []string{"ip", "-o", "link", "show", "dev", "lo"}
		} else {
			args = []string{"-Version"}
		}
	default:
		return identity, errExecutionCaptureUnavailable
	}
	before, err := os.Stat(resolved)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&0o111 == 0 {
		return identity, errExecutionCaptureUnavailable
	}
	probeCtx, cancel := context.WithTimeout(ctx, executionToolProbeTimeout)
	defer cancel()
	digest, err := sha256FileContext(probeCtx, resolved)
	if err != nil {
		return identity, errExecutionCaptureUnavailable
	}
	var stdout, stderr cappedHostOutput
	cmd := exec.CommandContext(probeCtx, resolved, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = applyHostCommandWaitDelay
	runErr := cmd.Run()
	version := strings.TrimSpace(stdout.String() + "\n" + stderr.String())
	if busyBoxIP {
		if !strings.Contains(stdout.String(), " lo:") {
			return identity, errExecutionCaptureUnavailable
		}
		version = executionBusyBoxIPVersion
	}
	if probeEcho != "" {
		if strings.TrimSpace(stdout.String()) != probeEcho {
			return identity, errExecutionCaptureUnavailable
		}
		version = executionShellProbeVersion
	}
	// Reduce every version banner to its first line. validExecutionIdentityText rejects control
	// characters, so ANY multi-line banner would fail identity validation outright — and tools
	// genuinely produce them: ipset prints a kernel/userspace protocol-skew warning on stderr
	// alongside the version on stdout, and dnsmasq follows its version with ~400 bytes of warranty
	// text, past the 256-byte cap. Observed as a Keenetic capture failing at desired_host with no
	// indication of which tool was at fault.
	//
	// This is a no-op for the two tools that predate it: `nft --version` and `ip -Version` are each
	// a single line. The digest was always the identity; the banner is human evidence, and its first
	// line is the part that identifies anything.
	version, _, _ = strings.Cut(version, "\n")
	version = strings.TrimSpace(version)
	after, statErr := os.Stat(resolved)
	digestAfter, digestErr := sha256FileContext(probeCtx, resolved)
	if runErr != nil || errors.Is(runErr, exec.ErrWaitDelay) || probeCtx.Err() != nil ||
		stdout.Truncated() || stderr.Truncated() || statErr != nil || digestErr != nil ||
		!sameHostFile(before, after) || digestAfter != digest ||
		!validExecutionIdentityText(version, executionMaxToolVersionBytes) {
		return identity, errExecutionCaptureUnavailable
	}
	identity.ResolvedPath = resolved
	identity.ContentSHA256 = digest
	identity.Version = version
	identity.Runnable = true
	return identity, nil
}
