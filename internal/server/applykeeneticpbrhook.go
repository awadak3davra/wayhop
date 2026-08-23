package server

import (
	"context"
	"fmt"
	"os"
	"strings"

	"wayhop/internal/atomicfile"
)

// applykeeneticpbrhook.go keeps the policy plane installed across NDM's own firewall rebuilds.
//
// KeeneticOS rebuilds netfilter on its own schedule — an interface changing state, a firmware
// component reloading — and drops rules it does not own. A plane installed once would therefore
// disappear minutes later with the panel still reporting it applied. NDM's supported integration
// point is /opt/etc/ndm/netfilter.d: it runs every executable there after a rebuild, exporting
// $table (filter/nat/mangle/raw) and $type (iptables/ip6tables).
//
// The hook carries the SAME authenticated script bytes the Apply executed, so a re-assert cannot
// drift from what was reviewed. It deliberately does NOT re-run the ipset restore: kernel sets
// survive a netfilter rebuild, and re-loading thousands of members on every interface flap would
// turn a routine event into seconds of CPU.

const (
	keeneticPBRHookPath        = "/opt/etc/ndm/netfilter.d/50-wayhop-policy.sh"
	keeneticPBRDnsmasqConfPath = "/opt/etc/dnsmasq.d/wayhop-policy.conf"
	keeneticPBRHookPerm        = os.FileMode(0o755)
	keeneticPBRConfPerm        = os.FileMode(0o644)
)

// renderKeeneticPBRHook wraps the authenticated program in NDM's calling convention.
//
// The guard matters as much as the body: NDM invokes this for every table and both address
// families, and re-running the whole program on `raw:ip6tables` would multiply a rebuild into four
// redundant executions. Only the tables the plane actually writes are answered.
func renderKeeneticPBRHook(script []byte) (string, error) {
	if len(script) == 0 {
		return "", errExactKernelArtifact
	}
	var b strings.Builder
	b.WriteString("#!/opt/bin/sh\n")
	b.WriteString("# WayHop policy plane — re-asserted after an NDM firewall rebuild.\n")
	b.WriteString("# Generated from the authenticated Apply artifact. Do not edit: the next Apply\n")
	b.WriteString("# overwrites it, and an edit here would diverge from the reviewed program.\n")
	b.WriteString("#\n")
	b.WriteString("# NDM exports $table and $type to every script in this directory after a rebuild.\n")
	b.WriteString("# Kernel ipsets survive that rebuild, so only the rules are re-installed here.\n")
	b.WriteString("case \"$table:$type\" in\n")
	b.WriteString("\tmangle:iptables|nat:iptables|mangle:ip6tables) ;;\n")
	b.WriteString("\t*) exit 0 ;;\n")
	b.WriteString("esac\n\n")
	b.Write(script)
	if !strings.HasSuffix(string(script), "\n") {
		b.WriteString("\n")
	}
	b.WriteString("exit 0\n")
	return b.String(), nil
}

// installKeeneticPBRHook writes the hook and, when the plan has domain zones, the dnsmasq config
// that fills those sets from live answers.
//
// Both are plain files rather than commands, which is the one shape the nft plane never had to
// handle. They are written atomically so an interrupted Apply cannot leave NDM executing half a
// script, and the previous contents are returned so a rollback can put back exactly what was there
// — including "nothing", which is the common case on a first Apply.
func installKeeneticPBRHook(artifact executionKernelIpsetArtifactV1) (restore func() error, err error) {
	hook, err := renderKeeneticPBRHook(artifact.Script)
	if err != nil {
		return nil, err
	}
	undo := []func() error{}
	rollback := func() error {
		var firstErr error
		for i := len(undo) - 1; i >= 0; i-- {
			if undoErr := undo[i](); undoErr != nil && firstErr == nil {
				firstErr = undoErr
			}
		}
		return firstErr
	}
	writeStep, err := replaceFilePreservingPrevious(keeneticPBRHookPath, []byte(hook), keeneticPBRHookPerm)
	if err != nil {
		return nil, fmt.Errorf("%w: netfilter.d hook: %v", errExactProductionKernelApply, err)
	}
	undo = append(undo, writeStep)
	if len(artifact.DnsmasqConf) != 0 {
		confStep, confErr := replaceFilePreservingPrevious(
			keeneticPBRDnsmasqConfPath, artifact.DnsmasqConf, keeneticPBRConfPerm)
		if confErr != nil {
			_ = rollback()
			return nil, fmt.Errorf("%w: dnsmasq config: %v", errExactProductionKernelApply, confErr)
		}
		undo = append(undo, confStep)
	}
	return rollback, nil
}

// keeneticDnsmasqInitScript is where Entware installs dnsmasq's service control. Unlike the tools in
// the artifact this is a platform convention rather than an authenticated identity, which is why a
// failure here is reported and not treated as a failed Apply: the directives are already on disk and
// take effect at the resolver's next start either way.
const keeneticDnsmasqInitScript = "/opt/etc/init.d/S56dnsmasq"

// reloadKeeneticDnsmasq makes the resolver read the freshly written ipset= directives.
//
// A restart, not SIGHUP: dnsmasq re-reads hosts and lease files on HUP but not its configuration, so
// hanging the domain plane on a signal would leave the sets unpopulated while everything reported
// success. Domain zones only start filling from the moment the resolver knows about them — entries
// already cached by clients keep their old path until they expire.
func reloadKeeneticDnsmasq(ctx context.Context, runner exactKeeneticKernelRunner) error {
	if _, err := os.Stat(keeneticDnsmasqInitScript); err != nil {
		return fmt.Errorf("%w: dnsmasq service script is absent", errExactProductionKernelApply)
	}
	if _, err := runner.Run(ctx, "", executionToolShell, keeneticDnsmasqInitScript, "restart"); err != nil {
		return fmt.Errorf("%w: dnsmasq restart: %v", errExactProductionKernelApply, err)
	}
	return nil
}

// removeKeeneticPBRHook takes the plane's files back off the router. A hook left behind would keep
// re-installing rules that the ledger no longer owns, which is the one failure mode that survives a
// clean teardown of everything else.
func removeKeeneticPBRHook() error {
	var firstErr error
	for _, path := range []string{keeneticPBRHookPath, keeneticPBRDnsmasqConfPath} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// replaceFilePreservingPrevious writes content and returns the function that puts the previous state
// back — the previous bytes, or removal when the file did not exist.
func replaceFilePreservingPrevious(path string, content []byte, perm os.FileMode) (func() error, error) {
	previous, readErr := os.ReadFile(path)
	existed := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, readErr
	}
	previousPerm := perm
	if existed {
		if info, statErr := os.Stat(path); statErr == nil {
			previousPerm = info.Mode().Perm()
		}
	}
	if err := atomicfile.WriteSynced(path, content, perm); err != nil {
		return nil, err
	}
	return func() error {
		if !existed {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		}
		return atomicfile.WriteSynced(path, previous, previousPerm)
	}, nil
}
