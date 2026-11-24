package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"wayhop/internal/pbr"
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
// closed to the tools the artifact declares.
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
	case executionToolIP:
		return runner.tools.IPTool, true
	}
	return ExecutionToolIdentityV1{}, false
}

func (runner exactKeeneticKernelRunner) Run(
	ctx context.Context,
	stdin string,
	name string,
	args ...string,
) (string, error) {
	return runner.runLimit(ctx, exactKeeneticKernelOutputLimit, stdin, name, args...)
}

// runLimit is Run with its own output bound, for a read that is large by nature (a set's members).
func (runner exactKeeneticKernelRunner) runLimit(
	ctx context.Context,
	limit int,
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
	output := newApplyHostCommandOutput(limit, cancel)
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
	return adapter.teardownSparing(ctx, artifact, nil)
}

// teardownSparing is teardown for a plane being replaced: the DNS redirect and refusals the
// replacement installs too (read from its Script) are left in place, so a list edit does not open a
// window in which client DNS escapes interception and encrypted DNS connects until the new program
// has run. nil spares nothing.
func (adapter *exactKeeneticKernelAdapter) teardownSparing(
	ctx context.Context,
	artifact executionKernelIpsetArtifactV1,
	spare []byte,
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
	if _, err := adapter.runner.Run(ctx, keeneticTeardownProgramSparing(artifact, spare), executionToolShell, "-s"); err != nil {
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
// are likewise cheap enough for every supervision tick. A program that redirects DNS or refuses
// encrypted DNS also needs those rules in nat PREROUTING and filter FORWARD, read the same way.
//
// Existence alone is only half the plane: a set nothing marks against routes nothing. With one MARK
// rule deleted, its list stops being policy-routed, and an existence-only check would still report
// verified:true and the panel "The router is verified to be running this configuration". The NDM
// firewall hook re-asserts the plane within ~30s, but that is not this supervision noticing anything.
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
	return keeneticPlanePostcheck(ctx, artifact, adapter.runner.Run)
}

// keeneticToolRun is exactKeeneticKernelRunner.Run's shape, so the postcheck reads through a stand-in
// in tests.
type keeneticToolRun func(ctx context.Context, stdin string, name string, args ...string) (string, error)

// keeneticPlanePostcheck is postcheck's reading of the router, given the runner to read it with.
func keeneticPlanePostcheck(ctx context.Context, artifact executionKernelIpsetArtifactV1, run keeneticToolRun) error {
	out, err := run(ctx, "", executionToolIpset, "list", "-n")
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
	v4Rules, err := run(ctx, "", executionToolIptables, "-w", "-t", "mangle", "-S")
	if err != nil {
		return fmt.Errorf("%w: iptables -S: %v", errExactProductionKernelApply, err)
	}
	// A missing ip6tables is a router shape, not drift: ask, and judge the v6 sets only if answered.
	v6Rules, v6Err := run(ctx, "", executionToolIp6tables, "-w", "-t", "mangle", "-S")
	if missing := unreferencedSets(artifact.SetNames, v4Rules, v6Rules, v6Err == nil); len(missing) > 0 {
		return fmt.Errorf("%w: set %q exists but no mangle rule reads it",
			errExactProductionKernelApply, missing[0])
	}
	// The DNS redirect and the encrypted-DNS refusals sit in chains NDM rebuilds, and the mangle
	// dump above says nothing about them: a filter rebuild could drop every refusal while this
	// reported the plane present. Their chains are read only when the program installs them.
	dumps := map[keeneticChainRef]string{}
	for _, rule := range keeneticDNSRules(artifact.Script) {
		dump, read := dumps[rule.keeneticChainRef]
		if !read {
			tool := executionToolIptables
			if rule.tool == "ip6tables" {
				tool = executionToolIp6tables
			}
			dump, err = run(ctx, "", tool, "-w", "-t", rule.table, "-S", rule.chain)
			if err != nil && tool == executionToolIp6tables {
				// As for the v6 mangle sets: a router without ip6tables is a shape, not drift.
				dumps[rule.keeneticChainRef] = keeneticDumpUnread
				continue
			}
			if err != nil {
				return fmt.Errorf("%w: iptables -t %s -S %s: %v", errExactProductionKernelApply, rule.table, rule.chain, err)
			}
			dumps[rule.keeneticChainRef] = dump
		}
		if dump == keeneticDumpUnread || rule.suspendable && keeneticDNSSuspended() {
			continue
		}
		if !iptablesDumpHasRule(dump, rule.chain, rule.spec) {
			return fmt.Errorf("%w: %s %s rule %q is missing",
				errExactProductionKernelApply, rule.table, rule.chain, rule.spec)
		}
	}
	if err := keeneticHandoffPostcheck(ctx, artifact, v4Rules, run); err != nil {
		return err
	}
	return keeneticIPRulesPostcheck(ctx, artifact, run)
}

// keeneticOutputJumpRE matches the program's check-then-add of a mangle OUTPUT jump.
var keeneticOutputJumpRE = regexp.MustCompile(`(?m)^iptables -t mangle -C OUTPUT (.+ -j (\S+)) 2>/dev/null \|\| iptables -t mangle -A OUTPUT (.+)$`)

// keeneticHandoffPostcheck reads back what the hand-off's return traffic depends on, when the program
// installs it: the OUTPUT jump (the kernel refused it with an xt_mac rule reachable from
// OUTPUT, and `sh -s` went on), a non-empty return chain, and the return table's loopback route,
// without which the return traffic would be held only by the blackhole rule behind it.
func keeneticHandoffPostcheck(ctx context.Context, artifact executionKernelIpsetArtifactV1, v4Rules string, run keeneticToolRun) error {
	script := string(artifact.Script)
	for _, m := range keeneticOutputJumpRE.FindAllStringSubmatch(script, -1) {
		if m[1] != m[3] || strings.HasSuffix(m[2], pbr.MangleStageSuffix) {
			continue
		}
		if !iptablesDumpHasRule(v4Rules, "OUTPUT", m[1]) {
			return fmt.Errorf("%w: mangle OUTPUT rule %q is missing", errExactProductionKernelApply, m[1])
		}
		if !strings.Contains(v4Rules, "\n-A "+m[2]+" ") && !strings.HasPrefix(v4Rules, "-A "+m[2]+" ") {
			return fmt.Errorf("%w: mangle chain %s is empty", errExactProductionKernelApply, m[2])
		}
	}
	table := pbr.HandoffReturnTable(pbr.Options{})
	if strings.Contains(script, fmt.Sprintf("\nip route replace default dev lo table %d\n", table)) {
		out, err := run(ctx, "", executionToolIP, "route", "show", "table", fmt.Sprint(table))
		if err != nil {
			return fmt.Errorf("%w: ip route show table %d: %v", errExactProductionKernelApply, table, err)
		}
		if !strings.Contains(" "+strings.Join(strings.Fields(out), " ")+" ", " default dev lo ") {
			return fmt.Errorf("%w: the hand-off return table %d has no loopback route", errExactProductionKernelApply, table)
		}
	}
	return nil
}

// keeneticIPRulesPostcheck reads the policy rules back. The program runs under `sh -s`, which
// reports only its last command, so an `ip rule add` the kernel refused passed the Apply while the
// marked traffic fell through to the main table and left by the WAN.
func keeneticIPRulesPostcheck(ctx context.Context, artifact executionKernelIpsetArtifactV1, run keeneticToolRun) error {
	script := string(artifact.Script)
	if !strings.Contains(script, "\nip rule add ") && !strings.Contains(script, "\nip -6 rule add ") {
		return nil
	}
	v4, err := run(ctx, "", executionToolIP, "rule")
	if err != nil {
		return fmt.Errorf("%w: ip rule: %v", errExactProductionKernelApply, err)
	}
	var v6 string
	v6Known := false
	if strings.Contains(script, "\nip -6 rule add ") {
		// A kernel without IPv6 policy routing answers with an error: that is a router shape, not drift.
		out, v6Err := run(ctx, "", executionToolIP, "-6", "rule")
		v6, v6Known = out, v6Err == nil
	}
	if missing := pbr.MissingIPRules(script, v4, v6, v6Known); len(missing) > 0 {
		return fmt.Errorf("%w: policy rule %q is missing", errExactProductionKernelApply, missing[0])
	}
	return nil
}

// pruneRestore deletes the set entries the previous plane added and this one no longer does. The
// restore stream only adds, so without it a CIDR removed from a list would stay in its set and keep
// being routed into the tunnel. Run after the target's own restore, so an entry both keep is never
// absent, not even for a moment.
func (adapter *exactKeeneticKernelAdapter) pruneRestore(ctx context.Context, previous, target []byte) error {
	removals := pbr.IpsetRestoreRemovals(string(previous), string(target))
	if removals == "" {
		return nil
	}
	if _, err := adapter.runner.Run(ctx, removals, executionToolIpset, "restore", "-!"); err != nil {
		return fmt.Errorf("%w: ipset restore (removals): %v", errExactProductionKernelApply, err)
	}
	return nil
}

// keeneticTeardownProgram is what the teardown runs: the artifact's own Teardown, then a delete for
// every rule its Script adds to a chain NDM owns that the Teardown does not delete itself.
//
// For a current artifact that adds nothing, because its Teardown deletes the DNS
// redirect and the encrypted-DNS refusals. An artifact recorded by an older build has a Teardown without
// those deletes, and a router upgraded with interception on tears exactly that one down when
// interception is next turned off, the mode leaves the kernel plane or routing is switched off. The
// deletes are taken from the authenticated Script's own check-then-add lines, so they name only rules
// it installed, and run through the same pinned tools as the rest of the program.
func keeneticTeardownProgram(artifact executionKernelIpsetArtifactV1) string {
	program := string(artifact.Teardown)
	var missing strings.Builder
	for _, rule := range keeneticDNSRules(artifact.Script) {
		del := pbr.DeleteEveryCopy(rule.tool, rule.table, rule.chain, rule.spec)
		if !strings.Contains(program, del) && !strings.Contains(missing.String(), del) {
			missing.WriteString(del)
		}
	}
	if missing.Len() == 0 {
		return program
	}
	return program + "# Recorded before the teardown removed the DNS redirect and refusals.\n" + missing.String()
}

// keeneticTeardownProgramSparing is keeneticTeardownProgram without the deletes of the DNS rules the
// replacement program spare also installs (nil spares nothing).
func keeneticTeardownProgramSparing(artifact executionKernelIpsetArtifactV1, spare []byte) string {
	program := keeneticTeardownProgram(artifact)
	for _, rule := range keeneticDNSRules(spare) {
		program = strings.ReplaceAll(program, pbr.DeleteEveryCopy(rule.tool, rule.table, rule.chain, rule.spec), "")
	}
	return program
}

// keeneticDNSSuspended reports fast mode's DNS enforcement suspended (pbr.FastDNSOpenFlag present):
// the postcheck then does not ask for its rules. A variable for tests.
var keeneticDNSSuspended = func() bool {
	_, err := os.Stat(pbr.FastDNSOpenFlag)
	return err == nil
}

// keeneticDumpUnread marks a chain dump the postcheck could not read and does not judge.
const keeneticDumpUnread = "\x00unread"

// keeneticChainRef names one built-in chain of one table of one family's tool (iptables, ip6tables).
type keeneticChainRef struct{ tool, table, chain string }

// keeneticDNSRule is one rule the program adds to a chain NDM rebuilds.
type keeneticDNSRule struct {
	keeneticChainRef
	spec string
	// line is the program's check-then-add line; suspendable says it is fast mode's enforcement, which
	// pbr.FastDNSOpenFlag suspends.
	line        string
	suspendable bool
}

// keeneticGuardedRuleRE matches the program's check-then-add lines, whose two halves must agree.
var keeneticGuardedRuleRE = regexp.MustCompile(
	`^(ip6?tables)(?: -t (\S+))? -C (\S+) (.+) 2>/dev/null \|\| (ip6?tables)(?: -t (\S+))? -[AI] (\S+) (.+)$`)

// keeneticDNSRules lists the rules the program adds to nat PREROUTING and filter FORWARD: the DNS
// redirect and the encrypted-DNS refusals. They are read from the authenticated program itself, so
// the check follows what was installed, including which of the two switches were on.
func keeneticDNSRules(script []byte) []keeneticDNSRule {
	var out []keeneticDNSRule
	open := false
	for _, line := range strings.Split(string(script), "\n") {
		switch line {
		case "if [ ! -e " + pbr.FastDNSOpenFlag + " ]; then":
			open = true
			continue
		case "fi":
			open = false
			continue
		}
		m := keeneticGuardedRuleRE.FindStringSubmatch(line)
		if m == nil || m[1] != m[5] || m[2] != m[6] || m[3] != m[7] || m[4] != m[8] {
			continue
		}
		table := m[2]
		if table == "" {
			table = "filter"
		}
		ref := keeneticChainRef{tool: m[1], table: table, chain: m[3]}
		if ref.tool == "iptables" && ref.table == "nat" && ref.chain == "PREROUTING" || ref.table == "filter" && ref.chain == "FORWARD" {
			out = append(out, keeneticDNSRule{keeneticChainRef: ref, spec: m[4], line: line, suspendable: open})
		}
	}
	return out
}

// iptablesDumpHasRule reports whether an `iptables -S <chain>` dump carries the rule spec.
//
// iptables prints a rule in its own canonical form rather than as it was typed: the protocol's match
// module appears (`-p udp -m udp --dport 53`), options come in a fixed order and a host address
// gains /32. Both sides are therefore compared as sorted option groups with module names dropped.
func iptablesDumpHasRule(dump, chain, spec string) bool {
	want := iptablesRuleKey(strings.Fields(spec))
	for _, line := range strings.Split(dump, "\n") {
		f := strings.Fields(line)
		if len(f) > 2 && f[0] == "-A" && f[1] == chain && iptablesRuleKey(f[2:]) == want {
			return true
		}
	}
	return false
}

func iptablesRuleKey(fields []string) string {
	var groups []string
	negate := false
	for i := 0; i < len(fields); i++ {
		opt := fields[i]
		if opt == "!" {
			negate = true
			continue
		}
		var values []string
		for i+1 < len(fields) && !strings.HasPrefix(fields[i+1], "-") && fields[i+1] != "!" {
			i++
			values = append(values, fields[i])
		}
		if opt == "-m" {
			negate = false
			continue
		}
		if (opt == "-s" || opt == "-d") && len(values) == 1 && !strings.Contains(values[0], "/") {
			values[0] += "/32"
		}
		group := strings.Join(append([]string{opt}, values...), " ")
		if negate {
			group = "! " + group
			negate = false
		}
		groups = append(groups, group)
	}
	sort.Strings(groups)
	return strings.Join(groups, " ")
}

// unreferencedSets names the owned sets that exist but no mangle rule reads.
//
// A set without its MARK rule routes NOTHING while looking perfectly healthy: `ipset list -n` shows
// it, the members are all there, and the traffic that was supposed to take the tunnel goes out the
// provider instead. Demonstrated on KeeneticOS by deleting one rule — the list stopped
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

// runProgram runs a short program under the artifact's own preamble, so its bare tool names reach the
// authenticated binaries.
func (adapter *exactKeeneticKernelAdapter) runProgram(ctx context.Context, artifact executionKernelIpsetArtifactV1, body string) error {
	preamble, err := keeneticPBRPreamble(artifact)
	if err != nil {
		return err
	}
	if _, err := adapter.runner.Run(ctx, preamble+body, executionToolShell, "-s"); err != nil {
		return fmt.Errorf("%w: %v", errExactProductionKernelApply, err)
	}
	return nil
}

// retireKeeneticPlane removes what only the previous plane had, after the next one is installed: its
// teardown with every line spared that would undo the next program (pbr.RetireProgram), the DNS rules
// the next program keeps spared as before. A dnsmasq config the next plane no longer writes goes too.
func (s *Server) retireKeeneticPlane(ctx context.Context, previous, next executionKernelIpsetArtifactV1) error {
	adapter, err := newExactKeeneticKernelAdapter(previous)
	if err != nil {
		return fmt.Errorf("%w: adapter: %v", errExactProductionKernelApply, err)
	}
	program := pbr.RetireProgram(keeneticTeardownProgramSparing(previous, next.Script), string(next.Script), next.SetNames)
	if _, err := adapter.runner.Run(ctx, program, executionToolShell, "-s"); err != nil {
		return fmt.Errorf("%w: retire script: %v", errExactProductionKernelApply, err)
	}
	if len(previous.DnsmasqConf) != 0 && len(next.DnsmasqConf) == 0 {
		if err := os.Remove(keeneticPBRDnsmasqConfPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("%w: dnsmasq config: %v", errExactProductionKernelApply, err)
		}
		if err := reloadKeeneticDnsmasq(ctx, adapter.runner); err != nil {
			log.Printf("apply: the resolver keeps the previous domain directives until it restarts: %v", err)
		}
	}
	return nil
}
