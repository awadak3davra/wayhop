package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"wayhop/internal/atomicfile"
)

// keeneticdnsguard.go guards the restart of Entware dnsmasq that a Keenetic fast-mode Apply makes for
// its wayhop-policy.conf: the real configuration is tested first, and after the restart dnsmasq has to
// run and resolve a real name through 127.0.0.1:53 within keeneticDNSGuardWait, or the previous
// policy file is put back, dnsmasq restarted with it, and the step fails.

var (
	keeneticDNSGuardWait = 10 * time.Second
	keeneticDNSGuardPoll = 200 * time.Millisecond
	// keeneticDnsmasqServicePresent is a variable so fake-runner tests need no router filesystem.
	keeneticDnsmasqServicePresent = func() bool {
		_, err := os.Stat(keeneticDnsmasqInitScript)
		return err == nil
	}
)

// reloadKeeneticDnsmasqWith is reloadKeeneticDnsmasq with a function-shaped runner for tests.
func reloadKeeneticDnsmasqWith(ctx context.Context, run keeneticToolRun) error {
	if !keeneticDnsmasqServicePresent() {
		return fmt.Errorf("%w: dnsmasq service script is absent", errExactProductionKernelApply)
	}
	if _, err := run(ctx, "", executionToolShell, keeneticDnsmasqInitScript, "restart"); err != nil {
		return fmt.Errorf("%w: dnsmasq restart: %v", errExactProductionKernelApply, err)
	}
	return nil
}

// keeneticDNSHealthy is dnsmasq running and answering the policy file's canary on 127.0.0.1:53, and, when upstream is set (it
// resolved a real name before the install), a fresh external name resolved through it.
func keeneticDNSHealthy(ctx context.Context, upstream bool) error {
	// The canary: the answer only a dnsmasq that loaded the policy file gives (HUNT-K #10, #11).
	if err := fastDNSAlive(ctx, true); err != nil {
		return err
	}
	if !upstream {
		return nil
	}
	return fastDNSUpstream(ctx)
}

// waitKeeneticAlive polls for any answer of dnsmasq on 127.0.0.1:53 for keeneticDNSGuardWait.
func waitKeeneticAlive(ctx context.Context) error {
	deadline := time.Now().Add(keeneticDNSGuardWait)
	for {
		err := fastDNSAlive(ctx, false)
		if err == nil || !time.Now().Before(deadline) || ctx.Err() != nil {
			return err
		}
		select {
		case <-ctx.Done():
		case <-time.After(keeneticDNSGuardPoll):
		}
	}
}

// waitKeeneticDNS polls keeneticDNSHealthy until it passes or keeneticDNSGuardWait is over.
func waitKeeneticDNS(ctx context.Context, upstream bool) error {
	deadline := time.Now().Add(keeneticDNSGuardWait)
	for {
		err := keeneticDNSHealthy(ctx, upstream)
		if err == nil {
			return nil
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			return fmt.Errorf("dnsmasq did not answer through 127.0.0.1:53 within %s of its restart: %v", keeneticDNSGuardWait, err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(keeneticDNSGuardPoll):
		}
	}
}

// keeneticPolicyFile is the policy file as it was before an install: its content, or that there was none.
type keeneticPolicyFile struct {
	content []byte
	existed bool
}

// readKeeneticPolicy reads the policy file the next install replaces. A read error other than absence
// is returned: the rollback must not believe there was nothing.
var readKeeneticPolicy = func() (keeneticPolicyFile, error) {
	b, err := os.ReadFile(keeneticPBRDnsmasqConfPath)
	switch {
	case err == nil:
		return keeneticPolicyFile{content: b, existed: true}, nil
	case os.IsNotExist(err):
		return keeneticPolicyFile{}, nil
	default:
		return keeneticPolicyFile{}, err
	}
}

// writeKeeneticPolicy puts a policy file in place (Apply's rollback writes "none" by removing it).
var writeKeeneticPolicy = func(p keeneticPolicyFile) error {
	if !p.existed {
		if err := os.Remove(keeneticPBRDnsmasqConfPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return atomicfile.WriteOutsideDir(keeneticPBRDnsmasqConfPath, p.content, keeneticPBRConfPerm)
}

// keeneticBackoutPolicy is what the post-install watch writes when dnsmasq stalls: the previous working
// file's name mappings with the INSTALLED plan's fail-closed server= pins (HUNT-K #4: the kernel plane
// stays the new one, so a newly kill-switched name must not resolve by an ordinary upstream; a pin
// only the previous plan had is dropped with it). With no previous file, the installed file without
// its ipset= lines. Never no file: removing it would drop every pin.
func keeneticBackoutPolicy(previous keeneticPolicyFile, installed []byte) []byte {
	var b strings.Builder
	if previous.existed {
		for _, line := range strings.SplitAfter(string(previous.content), "\n") {
			if !keeneticPinLine(line) {
				b.WriteString(line)
			}
		}
		if s := b.String(); s != "" && !strings.HasSuffix(s, "\n") {
			b.WriteString("\n")
		}
		for _, line := range strings.SplitAfter(string(installed), "\n") {
			if keeneticPinLine(line) {
				b.WriteString(line)
			}
		}
		return []byte(b.String())
	}
	for _, line := range strings.SplitAfter(string(installed), "\n") {
		if !strings.HasPrefix(line, "ipset=") {
			b.WriteString(line)
		}
	}
	return []byte(b.String())
}

// keeneticPinLine is a line of the policy file's kill-switch section (pbr DnsmasqIpsetConfig): its
// header or a server= pin. The file has no other server= lines.
func keeneticPinLine(line string) bool {
	return strings.HasPrefix(line, "server=") || strings.HasPrefix(line, "# Kill switch:")
}

// reloadKeeneticDnsmasqGuarded checks the real Entware configuration with the new policy file, restarts
// dnsmasq and waits for it to answer. A refused test puts the previous file back without a restart
// (the running dnsmasq never read the new one); a failed restart or no answer puts it back and
// restarts again. Every failure is returned, so the Apply step fails and rolls back.
func reloadKeeneticDnsmasqGuarded(ctx context.Context, run keeneticToolRun, restore func() error, upstream bool) error {
	if restore == nil {
		restore = func() error { return errors.New("no previous dnsmasq policy was saved") }
	}
	if _, err := run(ctx, "", executionToolDnsmasq, "--test", "-C", keeneticMainConf); err != nil {
		return errors.Join(fmt.Errorf("dnsmasq rejected the new policy: %v", err), restore())
	}
	back := func(cause error) error {
		err := errors.Join(cause, restore(), reloadKeeneticDnsmasqWith(ctx, run))
		// The rollback's restart is checked too: dnsmasq answering at all, whatever file;
		// a caller that finds it silent owes the loop a restart.
		if aliveErr := waitKeeneticAlive(ctx); aliveErr != nil {
			err = errors.Join(err, fmt.Errorf("dnsmasq did not answer after the previous policy was put back: %v", aliveErr))
		}
		return err
	}
	if err := reloadKeeneticDnsmasqWith(ctx, run); err != nil {
		return back(err)
	}
	if err := waitKeeneticDNS(ctx, upstream); err != nil {
		return back(err)
	}
	return nil
}
