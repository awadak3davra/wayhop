package server

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// applykeeneticpbrexec.go executes the artifact applykeeneticpbr.go rendered.
//
// It is the ipset-plane twin of applykernel.go and keeps the same envelope, because that envelope is
// the safety property rather than a style: every binary is invoked by the absolute path whose digest
// the ledger authenticated, commands are bounded in time and output, and stderr is retained because
// BusyBox reports an idempotent delete miss only there — mistaking that for a fatal error would roll
// back a plane that had in fact applied.

const (
	exactKeeneticKernelCommandTimeout = 30 * time.Second
	exactKeeneticKernelOutputLimit    = 1 << 20
)

type exactKeeneticKernelRunner struct {
	tools executionKernelIpsetArtifactV1
}

// identityFor returns the authenticated identity a tool name must run as. An unknown name has no
// identity and therefore cannot be executed at all, which is what keeps the set of runnable binaries
// closed to the four the artifact declares.
func (runner exactKeeneticKernelRunner) identityFor(name string) (ExecutionToolIdentityV1, bool) {
	switch name {
	case executionToolIpset:
		return runner.tools.IpsetTool, true
	case executionToolIptables:
		return runner.tools.IptablesTool, true
	case executionToolIp6tables:
		return runner.tools.IP6Tool, true
	case executionToolShell:
		return runner.tools.ShellTool, true
	case executionToolDnsmasq:
		return runner.tools.DnsmasqTool, true
	}
	return ExecutionToolIdentityV1{}, false
}

func (runner exactKeeneticKernelRunner) Run(
	ctx context.Context,
	stdin string,
	name string,
	args ...string,
) (string, error) {
	identity, known := runner.identityFor(name)
	if !known || !validExecutionToolIdentity(identity, name) {
		return "", errExactKernelArtifact
	}
	// Same multicall rule the probe and the shell preamble use: ipset is a real binary, but on
	// Entware iptables/ip6tables resolve to xtables-multi, which needs its applet as argv[1].
	if applet := executionMulticallApplet(identity.ResolvedPath, name); applet != "" {
		args = append([]string{applet}, args...)
	}
	runCtx, cancel := context.WithTimeout(ctx, exactKeeneticKernelCommandTimeout)
	defer cancel()
	output := newApplyHostCommandOutput(exactKeeneticKernelOutputLimit, cancel)
	cmd := exec.CommandContext(runCtx, identity.ResolvedPath, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	cmd.Stdout = applyHostCommandWriter{output: output, retain: true}
	cmd.Stderr = applyHostCommandWriter{output: output, retain: true}
	cmd.WaitDelay = applyHostCommandWaitDelay
	err := cmd.Run()
	if output.exceededLimit() || errors.Is(err, exec.ErrWaitDelay) || runCtx.Err() != nil {
		return "", errExactKernelArtifact
	}
	if err != nil {
		return output.stdoutString(), fmt.Errorf("%w: %s", err, output.stdoutString())
	}
	return output.stdoutString(), nil
}

type exactKeeneticKernelAdapter struct {
	runner exactKeeneticKernelRunner
}

func newExactKeeneticKernelAdapter(artifact executionKernelIpsetArtifactV1) (*exactKeeneticKernelAdapter, error) {
	if !validExecutionKernelIpsetArtifact(artifact) {
		return nil, errExactKernelArtifact
	}
	return &exactKeeneticKernelAdapter{runner: exactKeeneticKernelRunner{tools: artifact}}, nil
}

// apply installs the plane in the only order that is safe to interrupt: sets first, rules second.
//
// A set that exists but is referenced by no rule marks nothing, so a failure between the two steps
// leaves the router exactly as it was. The reverse order would install a rule referencing a set that
// does not exist yet — iptables refuses that outright on some builds and, worse, `ipset` names are
// resolved at rule-insert time, so a half-applied plane could match nothing while reporting success.
func (adapter *exactKeeneticKernelAdapter) apply(
	ctx context.Context,
	artifact executionKernelIpsetArtifactV1,
) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if !validExecutionKernelIpsetArtifact(artifact) {
		return errExactKernelArtifact
	}
	// `-!` is ipset's "ignore errors that mean the object already exists", which is what makes the
	// restore stream idempotent across a re-apply and across the netfilter.d hook re-running it.
	if _, err := adapter.runner.Run(ctx, string(artifact.Restore), executionToolIpset, "restore", "-!"); err != nil {
		return fmt.Errorf("%w: ipset restore: %v", errExactProductionKernelApply, err)
	}
	// The program is fed on stdin rather than passed as `-c <text>`: a plan with many zones renders
	// past a comfortable argv length, and stdin has no such limit.
	if _, err := adapter.runner.Run(ctx, string(artifact.Script), executionToolShell, "-s"); err != nil {
		return fmt.Errorf("%w: policy script: %v", errExactProductionKernelApply, err)
	}
	return nil
}

// teardown removes the plane in the mirror order: rules first, then the sets they referenced. A set
// destroyed while a rule still references it is refused by the kernel, so the reverse would leave
// both behind.
func (adapter *exactKeeneticKernelAdapter) teardown(
	ctx context.Context,
	artifact executionKernelIpsetArtifactV1,
) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if !validExecutionKernelIpsetArtifact(artifact) {
		return errExactKernelArtifact
	}
	// The hook comes off first. A teardown that removed the rules while leaving it in place would be
	// undone by NDM's next firewall rebuild, which would re-install a plane the ledger no longer
	// owns — the one leak that survives an otherwise clean removal.
	hookErr := removeKeeneticPBRHook()
	if _, err := adapter.runner.Run(ctx, string(artifact.Teardown), executionToolShell, "-s"); err != nil {
		return fmt.Errorf("%w: teardown script: %v", errExactProductionKernelApply, err)
	}
	if hookErr != nil {
		return fmt.Errorf("%w: netfilter.d hook: %v", errExactProductionKernelApply, hookErr)
	}
	return nil
}

// postcheck proves the plane is actually in the kernel rather than merely reported as applied.
//
// Every set the plan owns must exist, AND a mangle rule must read it. `ipset list -n` names the sets
// without dumping members, which matters when a set holds thousands of entries; the two `-S` dumps
// are likewise cheap enough for every supervision tick.
//
// Existence alone was the whole check, and it is only half the plane: a set nothing marks against
// routes nothing. Measured on a live router by deleting one MARK rule — the TeamViewer list
// stopped being policy-routed, `/api/pbr/status` still said verified:true and the panel still said
// "The router is verified to be running this configuration". The rule came back within ~30s, but
// from the NDM firewall hook re-asserting the plane, not from this supervision noticing anything.
func (adapter *exactKeeneticKernelAdapter) postcheck(
	ctx context.Context,
	artifact executionKernelIpsetArtifactV1,
) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if !validExecutionKernelIpsetArtifact(artifact) {
		return errExactKernelArtifact
	}
	out, err := adapter.runner.Run(ctx, "", executionToolIpset, "list", "-n")
	if err != nil {
		return fmt.Errorf("%w: ipset list: %v", errExactProductionKernelApply, err)
	}
	present := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if name := strings.TrimSpace(line); name != "" {
			present[name] = true
		}
	}
	for _, name := range artifact.SetNames {
		if !present[name] {
			return fmt.Errorf("%w: set %q is missing", errExactProductionKernelApply, name)
		}
	}
	v4Rules, err := adapter.runner.Run(ctx, "", executionToolIptables, "-t", "mangle", "-S")
	if err != nil {
		return fmt.Errorf("%w: iptables -S: %v", errExactProductionKernelApply, err)
	}
	// A missing ip6tables is a router shape, not drift: ask, and judge the v6 sets only if answered.
	v6Rules, v6Err := adapter.runner.Run(ctx, "", executionToolIp6tables, "-t", "mangle", "-S")
	if missing := unreferencedSets(artifact.SetNames, v4Rules, v6Rules, v6Err == nil); len(missing) > 0 {
		return fmt.Errorf("%w: set %q exists but no mangle rule reads it",
			errExactProductionKernelApply, missing[0])
	}
	return nil
}

// unreferencedSets names the owned sets that exist but no mangle rule reads.
//
// A set without its MARK rule routes NOTHING while looking perfectly healthy: `ipset list -n` shows
// it, the members are all there, and the traffic that was supposed to take the tunnel goes out the
// provider instead. Demonstrated on a live Keenetic by deleting one rule — the list stopped
// being marked, and every WayHop verdict still read "verified to be running this configuration",
// because the only thing verified was that the sets existed.
//
// Families are told apart by the renderer's own "_4"/"_6" suffix (render_ipset.go builds both names
// from one zone). v6Known is false when ip6tables could not be asked at all: a router without that
// tool is not drifting, so its v6 sets are left unjudged rather than reported missing — inventing
// drift here would reinstall the plane every supervision tick forever.
func unreferencedSets(setNames []string, v4Rules, v6Rules string, v6Known bool) []string {
	var out []string
	for _, name := range setNames {
		if strings.HasSuffix(name, "_6") {
			if !v6Known {
				continue
			}
			if !strings.Contains(v6Rules, name) {
				out = append(out, name)
			}
			continue
		}
		if !strings.Contains(v4Rules, name) {
			out = append(out, name)
		}
	}
	return out
}
