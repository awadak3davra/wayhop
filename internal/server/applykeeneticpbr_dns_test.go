package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// DNS interception on the Keenetic plane: the netfilter.d hook must put the encrypted-DNS refusals
// back after a filter-table rebuild without re-running the mangle program (QA-115), and the reconcile
// postcheck must notice a missing redirect or refusal (QA-115). The teardown side is in
// internal/pbr (QA-114).

// keeneticDNSProfile routes one documentation prefix through a kernel tunnel, with the DNS switches set.
func keeneticDNSProfile(intercept, reject bool) *model.Profile {
	return &model.Profile{
		Endpoints: []model.Endpoint{{ID: "nl", Engine: model.EngineExternal, Enabled: true,
			Server: "203.0.113.1", Params: map[string]any{"interface": "awg1"}}},
		RoutingLists: []model.RoutingList{{ID: "c", Enabled: true, Outbound: "nl", Manual: []string{"198.51.100.0/24"}}},
		DNS:          &model.DNSSettings{Enabled: true, Intercept: intercept, InterceptRejectEncrypted: reject},
	}
}

func keeneticDNSArtifact(t *testing.T, tools executionKernelIpsetArtifactV1, intercept, reject bool) *executionKernelIpsetArtifactV1 {
	t.Helper()
	p := keeneticDNSProfile(intercept, reject)
	plan, _, err := pbr.Compile(p, pbr.Options{})
	if err != nil {
		t.Fatal(err)
	}
	art, err := buildKeeneticKernelIpsetArtifact(plan, exactKernelOptions(), keeneticPBROptionsFor("eth3", p), tools)
	if err != nil {
		t.Fatal(err)
	}
	return art
}

// keeneticHookDir is a temp dir as Go and as sh name it (they differ on Windows).
type keeneticHookDir struct{ native, sh string }

// keeneticHookShims stands in for the router's binaries under a POSIX path sh can execute, laid out
// like Entware (xtables-multi and BusyBox are multicall hosts), and returns tools pointing at them.
// Every call is logged; -C and -D report "no such rule", as on a freshly rebuilt table.
func keeneticHookShims(t *testing.T, sh string) (executionKernelIpsetArtifactV1, keeneticHookDir) {
	t.Helper()
	dir := keeneticHookDir{native: t.TempDir()}
	out, err := exec.Command(sh, "-c", `cd "$1" && pwd`, "sh", dir.native).Output()
	if err != nil {
		t.Skipf("sh cannot enter the temp dir: %v", err)
	}
	dir.sh = strings.TrimSpace(string(out))
	shim := "#!/bin/sh\necho \"$*\" >> \"$QA_LOG\"\ncase \" $* \" in *\" -C \"*|*\" -D \"*) exit 1 ;; esac\nexit 0\n"
	for _, name := range []string{"ipset", "xtables-multi", "busybox"} {
		if err := os.WriteFile(filepath.Join(dir.native, name), []byte(shim), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tools := keeneticPBRTestTools()
	tools.IpsetTool.ResolvedPath = dir.sh + "/ipset"
	tools.IptablesTool.ResolvedPath = dir.sh + "/xtables-multi"
	tools.IP6Tool.ResolvedPath = dir.sh + "/xtables-multi"
	tools.IPTool.ResolvedPath = dir.sh + "/busybox"
	return tools, dir
}

// runKeeneticHook sources the hook the way NDM runs it after rebuilding one table, and returns the
// tool calls it made, one per line.
func runKeeneticHook(t *testing.T, sh string, dir keeneticHookDir, hook, table, typ string) []string {
	t.Helper()
	name := "hook-" + table + "-" + typ
	if err := os.WriteFile(filepath.Join(dir.native, name+".sh"), []byte(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir.native, name+".log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, "-c", `. "$1"`, "sh", dir.sh+"/"+name+".sh")
	cmd.Env = append(os.Environ(), "table="+table, "type="+typ, "QA_LOG="+dir.sh+"/"+name+".log")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hook for %s:%s: %v %s", table, typ, err, out)
	}
	data, err := os.ReadFile(filepath.Join(dir.native, name+".log"))
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			calls = append(calls, line)
		}
	}
	return calls
}

func countCalls(calls []string, parts ...string) int {
	n := 0
	for _, c := range calls {
		hit := true
		for _, p := range parts {
			if !strings.Contains(c, p) {
				hit = false
				break
			}
		}
		if hit {
			n++
		}
	}
	return n
}

// QA-115: NDM calls each netfilter.d script per table, and a filter rebuild drops the FORWARD
// refusals. The hook let only mangle and nat through, so they stayed gone until the next nat or
// mangle rebuild. It now answers filter:iptables for a program that has refusals, and the program
// stops after its filter section, so that event never re-runs the mangle flush and rebuild.
func TestKeeneticPBRHook_FilterRebuildRestoresOnlyTheRefusals(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh to run the hook with")
	}
	tools, dir := keeneticHookShims(t, sh)
	art := keeneticDNSArtifact(t, tools, true, true)
	hook, err := renderKeeneticPBRHook(art.Script)
	if err != nil {
		t.Fatal(err)
	}
	refusals := 1 + len(pbr.WellKnownDoHEndpoints)

	filter := runKeeneticHook(t, sh, dir, hook, "filter", "iptables")
	if got := countCalls(filter, "iptables -w -I FORWARD -i br0 -p tcp", "-j REJECT --reject-with tcp-reset"); got != refusals {
		t.Errorf("a filter rebuild re-inserted %d refusals, want %d: %q", got, refusals, filter)
	}
	if len(filter) != 2*refusals || countCalls(filter, "-t mangle") != 0 || countCalls(filter, "-t nat") != 0 {
		t.Errorf("a filter rebuild ran more than the filter section (%d calls, want %d): %q", len(filter), 2*refusals, filter)
	}

	// nat and mangle still run the whole program, the refusals included.
	for _, table := range []string{"nat", "mangle"} {
		calls := runKeeneticHook(t, sh, dir, hook, table, "iptables")
		if countCalls(calls, "-j REJECT") != 2*refusals || countCalls(calls, "-t nat -A PREROUTING -i br0", "-j REDIRECT") != 2 ||
			countCalls(calls, "iptables -w -t mangle -F WR_PREROUTING") != 1 {
			t.Errorf("a %s rebuild did not re-run the whole program: %q", table, calls)
		}
	}
	for _, event := range [][2]string{{"raw", "iptables"}, {"filter", "ip6tables"}, {"nat", "ip6tables"}} {
		if calls := runKeeneticHook(t, sh, dir, hook, event[0], event[1]); len(calls) != 0 {
			t.Errorf("%s:%s is not the plane's and must run nothing: %q", event[0], event[1], calls)
		}
	}

	// Without refusals there is no filter section, and a filter rebuild stays a no-op.
	plain, err := renderKeeneticPBRHook(keeneticDNSArtifact(t, tools, true, false).Script)
	if err != nil {
		t.Fatal(err)
	}
	if calls := runKeeneticHook(t, sh, dir, plain, "filter", "iptables"); len(calls) != 0 {
		t.Errorf("a program without refusals ran on a filter rebuild: %q", calls)
	}
}

// The hook for a program without refusals is the one routers run today, byte for byte, so the fix
// changes nothing on them. Pinned literally: this is the header live routers carry.
func TestKeeneticPBRHook_WithoutRefusalsIsUnchanged(t *testing.T) {
	const header = "#!/opt/bin/sh\n" +
		"# WayHop policy plane — re-asserted after an NDM firewall rebuild.\n" +
		"# Generated from the authenticated Apply artifact. Do not edit: the next Apply\n" +
		"# overwrites it, and an edit here would diverge from the reviewed program.\n" +
		"#\n" +
		"# NDM exports $table and $type to every script in this directory after a rebuild.\n" +
		"# Kernel ipsets survive that rebuild, so only the rules are re-installed here.\n" +
		"case \"$table:$type\" in\n" +
		"\tmangle:iptables|nat:iptables|mangle:ip6tables) ;;\n" +
		"\t*) exit 0 ;;\n" +
		"esac\n\n"
	for _, sw := range [][2]bool{{false, false}, {false, true}, {true, false}} {
		art := keeneticDNSArtifact(t, keeneticPBRTestTools(), sw[0], sw[1])
		hook, err := renderKeeneticPBRHook(art.Script)
		if err != nil {
			t.Fatal(err)
		}
		if want := header + string(art.Script) + "exit 0\n"; hook != want {
			t.Errorf("intercept=%v reject=%v: hook changed:\n%s", sw[0], sw[1], hook)
		}
	}
}

// keeneticFakeRouter answers the postcheck's reads the way iptables 1.4.21 prints them.
type keeneticFakeRouter struct {
	sets, mangle4, mangle6, natPrerouting, filterForward string
	calls                                                []string
}

func (r *keeneticFakeRouter) run(_ context.Context, _ string, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	switch call {
	case "ipset list -n":
		return r.sets, nil
	case "iptables -w -t mangle -S":
		return r.mangle4, nil
	case "ip6tables -w -t mangle -S":
		return r.mangle6, nil
	case "iptables -w -t nat -S PREROUTING":
		return r.natPrerouting, nil
	case "iptables -w -t filter -S FORWARD":
		return r.filterForward, nil
	}
	return "", fmt.Errorf("unexpected call %q", call)
}

// healthyKeeneticRouter is a router with the whole plane of art installed, printed in iptables' own
// canonical form: the protocol's match module shown, a host address with /32, NDM's rules around ours.
func healthyKeeneticRouter(art *executionKernelIpsetArtifactV1) *keeneticFakeRouter {
	r := &keeneticFakeRouter{sets: strings.Join(art.SetNames, "\n") + "\n"}
	for _, name := range art.SetNames {
		r.mangle4 += "-A WR_PREROUTING -m set --match-set " + name + " dst -j MARK --set-xmark 0x20000/0xff0000\n"
		r.mangle6 += "-A WR_PREROUTING -m set --match-set " + name + " dst -j MARK --set-xmark 0x20000/0xff0000\n"
	}
	r.natPrerouting = "-P PREROUTING ACCEPT\n-A PREROUTING -j _NDM_STATIC_DNAT\n" +
		"-A PREROUTING -i br0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 53\n" +
		"-A PREROUTING -i br0 -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 53\n"
	r.filterForward = filterForwardWithRefusals()
	return r
}

func filterForwardWithRefusals() string {
	dump := "-P FORWARD DROP\n"
	for _, ip := range pbr.WellKnownDoHEndpoints {
		dump += "-A FORWARD -d " + ip + "/32 -i br0 -p tcp -m tcp --dport 443 -j REJECT --reject-with tcp-reset\n"
	}
	dump += "-A FORWARD -i br0 -p tcp -m tcp --dport 853 -j REJECT --reject-with tcp-reset\n"
	return dump + "-A FORWARD -j _NDM_SL_FORWARD\n"
}

// QA-115: the postcheck read only the sets and mangle, so a router whose filter rebuild had dropped
// every refusal was reported as running the plane and the reconcile loop reinstalled nothing.
func TestKeeneticPostcheck_NoticesAMissingRedirectOrRefusal(t *testing.T) {
	art := keeneticDNSArtifact(t, keeneticPBRTestTools(), true, true)
	ctx := context.Background()

	healthy := healthyKeeneticRouter(art)
	if err := keeneticPlanePostcheck(ctx, *art, healthy.run); err != nil {
		t.Fatalf("a healthy plane failed its postcheck: %v", err)
	}
	for _, want := range []string{"iptables -w -t nat -S PREROUTING", "iptables -w -t filter -S FORWARD"} {
		if countCalls(healthy.calls, want) != 1 {
			t.Errorf("postcheck reads = %q, want %q once", healthy.calls, want)
		}
	}

	lastDoH := pbr.WellKnownDoHEndpoints[len(pbr.WellKnownDoHEndpoints)-1]
	for name, damage := range map[string]func(r *keeneticFakeRouter){
		"filter rebuilt": func(r *keeneticFakeRouter) { r.filterForward = "-P FORWARD DROP\n-A FORWARD -j _NDM_SL_FORWARD\n" },
		"one DoH refusal gone": func(r *keeneticFakeRouter) {
			r.filterForward = strings.Replace(r.filterForward, "-A FORWARD -d "+lastDoH+"/32 ", "-A FORWARD -d 192.0.2.53/32 ", 1)
		},
		"DoT refusal gone": func(r *keeneticFakeRouter) {
			r.filterForward = strings.Replace(r.filterForward, "--dport 853 -j REJECT", "--dport 853 -j ACCEPT", 1)
		},
		"udp redirect gone": func(r *keeneticFakeRouter) {
			r.natPrerouting = strings.Replace(r.natPrerouting, "-A PREROUTING -i br0 -p udp", "-A PREROUTING -i br1 -p udp", 1)
		},
		"nat rebuilt": func(r *keeneticFakeRouter) { r.natPrerouting = "-P PREROUTING ACCEPT\n" },
	} {
		r := healthyKeeneticRouter(art)
		damage(r)
		err := keeneticPlanePostcheck(ctx, *art, r.run)
		if !errors.Is(err, errExactProductionKernelApply) {
			t.Errorf("%s: postcheck = %v, want the plane reported missing", name, err)
		}
	}

	// A read that fails is not a healthy plane either.
	failing := healthyKeeneticRouter(art)
	failRun := func(ctx context.Context, stdin, name string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "-t filter") {
			return "", errors.New("exit status 4")
		}
		return failing.run(ctx, stdin, name, args...)
	}
	if err := keeneticPlanePostcheck(ctx, *art, failRun); !errors.Is(err, errExactProductionKernelApply) {
		t.Errorf("an unreadable filter table passed the postcheck: %v", err)
	}
}

// Without the switches nothing more is read, so the 30 s tick costs what it did; with interception
// alone only nat is read.
func TestKeeneticPostcheck_ReadsOnlyTheChainsThePlaneWrites(t *testing.T) {
	for _, tc := range []struct {
		intercept, reject bool
		want              []string
	}{
		{false, false, []string{"ipset list -n", "iptables -w -t mangle -S", "ip6tables -w -t mangle -S"}},
		{true, false, []string{"ipset list -n", "iptables -w -t mangle -S", "ip6tables -w -t mangle -S", "iptables -w -t nat -S PREROUTING"}},
	} {
		art := keeneticDNSArtifact(t, keeneticPBRTestTools(), tc.intercept, tc.reject)
		r := healthyKeeneticRouter(art)
		r.filterForward = "-P FORWARD DROP\n"
		if err := keeneticPlanePostcheck(context.Background(), *art, r.run); err != nil {
			t.Errorf("intercept=%v: %v", tc.intercept, err)
		}
		if strings.Join(r.calls, "|") != strings.Join(tc.want, "|") {
			t.Errorf("intercept=%v: reads = %q, want %q", tc.intercept, r.calls, tc.want)
		}
	}
}

// The reconcile loop is the backstop between NDM rebuilds: with the refusals dropped it must report
// the plane missing, reinstall it and verify it back.
func TestReconcileKernelPlane_ReinstallsRefusalsAFilterRebuildDropped(t *testing.T) {
	noReconcileSettle(t)
	s, fake := applytest_server(t)
	art := keeneticDNSArtifact(t, keeneticPBRTestTools(), true, true)
	m := applyboot_kernelMaterialization()
	m.Kernel.Ipset = art
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: m})

	router := healthyKeeneticRouter(art)
	router.filterForward = "-P FORWARD DROP\n-A FORWARD -j _NDM_SL_FORWARD\n" // NDM rebuilt filter
	ops := fake.ops()
	ops.kernelPostcheck = func(ctx context.Context, kernel executionKernelArtifactV1) error {
		fake.record("kernelPostcheck")
		return keeneticPlanePostcheck(ctx, *kernel.Ipset, router.run)
	}
	install := ops.kernel
	ops.kernel = func(ctx context.Context, target executionKernelArtifactV1, previous *executionKernelArtifactV1) error {
		err := install(ctx, target, previous)
		router.filterForward = filterForwardWithRefusals() // the program's -C || -I puts them back
		return err
	}
	s.execOps = &ops

	s.reconcileKernelPlane(context.Background())

	// One reinstall, verified after it. How many reads come before it is the loop's own business
	// (QA-118 reads twice, a settle apart), so only their kind is pinned.
	got := fake.snapshot()
	if len(got) < 3 || countCalls(got, "kernel:ensure_present") != 1 || countCalls(got, "kernelPostcheck") != len(got)-1 ||
		got[0] != "kernelPostcheck" || got[len(got)-1] != "kernelPostcheck" {
		t.Fatalf("reconcile ops = %q, want postchecks, one reinstall, a postcheck", got)
	}
	if s.kernelPlaneObserved() != kernelPlanePresent {
		t.Error("a verified reinstall must record the plane as present")
	}

	// The refusals are back, so the next tick reads and does nothing: no reinstall every 30 s.
	s.reconcileKernelPlane(context.Background())
	if next := fake.snapshot()[len(got):]; strings.Join(next, ",") != "kernelPostcheck" {
		t.Errorf("the tick after the reinstall ran %q, want one postcheck", next)
	}
}

// With interception and the refusals off the postcheck reads neither chain, so whatever nat and
// filter hold (NDM's own rules, or a redirect an earlier plane left) cannot make the reconcile loop
// reinstall the plane: one read per tick, every tick.
func TestReconcileKernelPlane_DNSOffNeverReinstalls(t *testing.T) {
	noReconcileSettle(t)
	for _, sw := range [][2]bool{{false, false}, {false, true}} {
		s, fake := applytest_server(t)
		art := keeneticDNSArtifact(t, keeneticPBRTestTools(), sw[0], sw[1])
		m := applyboot_kernelMaterialization()
		m.Kernel.Ipset = art
		s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: m})

		router := healthyKeeneticRouter(art)
		router.natPrerouting, router.filterForward = "-P PREROUTING ACCEPT\n", "-P FORWARD DROP\n"
		ops := fake.ops()
		ops.kernelPostcheck = func(ctx context.Context, kernel executionKernelArtifactV1) error {
			fake.record("kernelPostcheck")
			return keeneticPlanePostcheck(ctx, *kernel.Ipset, router.run)
		}
		s.execOps = &ops

		for range 3 {
			s.reconcileKernelPlane(context.Background())
		}
		if got := strings.Join(fake.snapshot(), ","); got != "kernelPostcheck,kernelPostcheck,kernelPostcheck" {
			t.Errorf("intercept=%v reject=%v: three ticks ran %s, want three postchecks", sw[0], sw[1], got)
		}
		if countCalls(router.calls, "-t nat") != 0 || countCalls(router.calls, "-t filter") != 0 {
			t.Errorf("intercept=%v reject=%v: postcheck read nat or filter: %q", sw[0], sw[1], router.calls)
		}
		if s.kernelPlaneObserved() != kernelPlanePresent {
			t.Errorf("intercept=%v reject=%v: plane not recorded present", sw[0], sw[1])
		}
	}
}

// keeneticTeardownShim is an iptables that reports every rule present twice: each distinct -D
// succeeds two times and then answers "no such rule", as a router holding a duplicate would.
const keeneticTeardownShim = "#!/bin/sh\n" +
	"echo \"$*\" >> \"$QA_LOG\"\n" +
	"case \" $* \" in *\" -D \"*)\n" +
	"\t[ \"$(grep -cxF -- \"$*\" \"$QA_LOG\")\" -le 2 ] && exit 0\n" +
	"\texit 1 ;;\n" +
	"esac\n" +
	"exit 0\n"

// runKeeneticTeardown runs program under sh against the duplicate-holding shim and returns its calls.
func runKeeneticTeardown(t *testing.T, sh string, dir keeneticHookDir, name, program string) []string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir.native, "xtables-multi"), []byte(keeneticTeardownShim), 0o755); err != nil {
		t.Fatal(err)
	}
	return runKeeneticHook(t, sh, dir, program, name, "teardown")
}

// QA-114: the teardown that turning interception off, leaving the kernel plane or switching routing
// off runs must delete the redirect and every refusal, every copy, waiting for the xtables lock, on
// the interface the program installed them on. It is run here, not just read.
func TestKeeneticTeardown_DeletesEveryCopyOfTheDNSRules(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh to run the teardown with")
	}
	tools, dir := keeneticHookShims(t, sh)
	art := keeneticDNSArtifact(t, tools, true, true)
	refusals := 1 + len(pbr.WellKnownDoHEndpoints)

	calls := runKeeneticTeardown(t, sh, dir, "current", keeneticTeardownProgram(*art))
	// Two copies deleted and a third -D that finds none: three calls per rule.
	for _, proto := range []string{"udp", "tcp"} {
		if got := countCalls(calls, "iptables -w -t nat -D PREROUTING -i br0 -p "+proto+" --dport 53 -j REDIRECT --to-ports 53"); got != 3 {
			t.Errorf("%s redirect: %d deletes, want 3 (two copies, then none): %q", proto, got, calls)
		}
	}
	if got := countCalls(calls, "iptables -w -D FORWARD -i br0 -p tcp", "-j REJECT --reject-with tcp-reset"); got != 3*refusals {
		t.Errorf("refusals: %d deletes, want %d: %q", got, 3*refusals, calls)
	}
	for _, c := range calls {
		if strings.Contains(c, " -D ") && !strings.HasPrefix(c, "iptables -w ") && !strings.HasPrefix(c, "ip6tables -w ") {
			t.Errorf("a delete ran without waiting for the xtables lock: %q", c)
		}
	}

	// A plane with both switches off still takes them out: the plane it replaces may have had them.
	off := keeneticDNSArtifact(t, tools, false, false)
	calls = runKeeneticTeardown(t, sh, dir, "off", keeneticTeardownProgram(*off))
	if got := countCalls(calls, "-j REDIRECT --to-ports 53") + countCalls(calls, "-j REJECT"); got != 3*(2+refusals) {
		t.Errorf("a plane with interception off deleted %d DNS rules, want %d: %q", got, 3*(2+refusals), calls)
	}
}

// legacyKeeneticTeardown is art's Teardown as the renderer wrote it before QA-114: without a delete
// for the redirect or the refusals.
func legacyKeeneticTeardown(art *executionKernelIpsetArtifactV1) []byte {
	var keep []string
	for _, line := range strings.SplitAfter(string(art.Teardown), "\n") {
		if strings.HasPrefix(line, "while iptables -t nat -D PREROUTING ") || strings.HasPrefix(line, "while iptables -D FORWARD ") {
			continue
		}
		keep = append(keep, line)
	}
	return []byte(strings.Join(keep, ""))
}

// A router upgraded with interception on holds an artifact whose Teardown predates QA-114, and that is
// the one turning interception off or routing off tears down. The executor adds the deletes from the
// artifact's own Script; an artifact rendered now runs its Teardown byte for byte.
func TestKeeneticTeardownProgram_CoversAPlaneRecordedBeforeTheFix(t *testing.T) {
	refusals := 1 + len(pbr.WellKnownDoHEndpoints)
	for _, tc := range []struct {
		intercept, reject bool
		deletes           int
	}{{false, false, 0}, {false, true, 0}, {true, false, 2}, {true, true, 2 + refusals}} {
		art := keeneticDNSArtifact(t, keeneticPBRTestTools(), tc.intercept, tc.reject)
		if got := keeneticTeardownProgram(*art); got != string(art.Teardown) {
			t.Errorf("intercept=%v reject=%v: a current artifact's teardown was changed:\n%s", tc.intercept, tc.reject, got)
		}
		legacy := *art
		legacy.Teardown = legacyKeeneticTeardown(art)
		if bytes.Equal(legacy.Teardown, art.Teardown) {
			t.Fatal("the legacy teardown still carries the DNS deletes")
		}
		got := keeneticTeardownProgram(legacy)
		added, found := strings.CutPrefix(got, string(legacy.Teardown))
		if !found {
			t.Fatalf("the legacy teardown is not run first:\n%s", got)
		}
		if n := strings.Count(added, "while iptables "); n != tc.deletes {
			t.Errorf("intercept=%v reject=%v: %d deletes added, want %d:\n%s", tc.intercept, tc.reject, n, tc.deletes, added)
		}
		for _, line := range strings.Split(strings.TrimSuffix(added, "\n"), "\n") {
			if line != "" && !strings.HasPrefix(line, "# ") && !strings.Contains(string(art.Teardown), line+"\n") {
				t.Errorf("added %q, which the current renderer would not write", line)
			}
		}
	}
}

// iptables prints a rule in its own form; the comparison must see through that and nothing more.
// A replaced plane keeps the DNS rules the new program installs too: a list edit must not open a
// window in which client DNS escapes interception and encrypted DNS connects (#212 review of QA-114).
func TestKeeneticReplaceTeardownSparesTheRulesTheNewPlaneKeeps(t *testing.T) {
	tools := keeneticPBRTestTools()
	both := keeneticDNSArtifact(t, tools, true, true)
	interceptOnly := keeneticDNSArtifact(t, tools, true, false)
	full := keeneticTeardownProgram(*both)
	rules := keeneticDNSRules(both.Script)
	if len(rules) != 15 {
		t.Fatalf("intercept+reject plane has %d DNS rules, want 15", len(rules))
	}
	deletes := func(program string) (n int) {
		for _, r := range rules {
			if strings.Contains(program, pbr.IptablesDeleteEveryCopy(r.table, r.chain, r.spec)) {
				n++
			}
		}
		return n
	}
	if got := deletes(full); got != 15 {
		t.Fatalf("a plain teardown deletes %d of the 15 DNS rules", got)
	}
	if got := deletes(keeneticTeardownProgramSparing(*both, both.Script)); got != 0 {
		t.Errorf("replacing with the same DNS rules still deleted %d of them", got)
	}
	// Turning reject off: the 13 refusals go, the 2 redirects stay.
	if got := deletes(keeneticTeardownProgramSparing(*both, interceptOnly.Script)); got != 13 {
		t.Errorf("replacing with intercept only deleted %d DNS rules, want the 13 refusals", got)
	}
	// Everything else in the teardown is untouched.
	spared := keeneticTeardownProgramSparing(*both, both.Script)
	for _, line := range strings.Split(full, "\n") {
		if line != "" && !strings.Contains(line, "--dport") && !strings.Contains(spared, line) {
			t.Fatalf("sparing dropped a non-DNS teardown line: %q", line)
		}
	}
	if keeneticTeardownProgramSparing(*both, nil) != full {
		t.Error("nil must spare nothing")
	}
}

func TestIptablesDumpHasRule(t *testing.T) {
	spec := "-i br0 -p tcp -d 192.0.2.53 --dport 443 -j REJECT --reject-with tcp-reset"
	dump := "-P FORWARD DROP\n-A FORWARD -d 192.0.2.53/32 -i br0 -p tcp -m tcp --dport 443 -j REJECT --reject-with tcp-reset\n"
	if !iptablesDumpHasRule(dump, "FORWARD", spec) {
		t.Error("the canonical form of the rule was not recognised")
	}
	for _, other := range []string{
		"-A FORWARD -d 192.0.2.54/32 -i br0 -p tcp -m tcp --dport 443 -j REJECT --reject-with tcp-reset", // another address
		"-A FORWARD ! -d 192.0.2.53/32 -i br0 -p tcp -m tcp --dport 443 -j REJECT --reject-with tcp-reset",
		"-A FORWARD -d 192.0.2.53/32 -i br0 -p tcp -m tcp --dport 443 -j REJECT", // another reject type
		"-A INPUT -d 192.0.2.53/32 -i br0 -p tcp -m tcp --dport 443 -j REJECT --reject-with tcp-reset",
	} {
		if iptablesDumpHasRule(other+"\n", "FORWARD", spec) {
			t.Errorf("%q was taken for %q", other, spec)
		}
	}
}
