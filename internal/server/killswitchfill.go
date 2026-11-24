package server

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/pbr"
	"wayhop/internal/rtblackhole"
)

// killswitchfill.go is `wayhop backstop-fill`: the hook runs it once per boot, after the broad hold and
// the backstop rules are in and before the marking chain, to put every kill-switched destination it knows into the backstop table
// without waiting for the daemon. The static prefixes come from the plane's restore
// file, the learned members of kill-switched domain sets from the daemon's learned file. With every
// piece present it writes the ready stamp and removes the broad boot hold, so from then on only
// kill-switched destinations are held, whether or not the daemon ever starts.

// ksFillPartial is the exit status of a fill that installed what it had but not everything.
const ksFillPartial = 3

// ksFillMaxLines bounds what one fill reads from either file.
const ksFillMaxLines = 400000

var validFillPath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// ksBootFillTool is the binary the hook runs as `backstop-fill`: this one, when its path can be
// rendered into the program unquoted. "" = no fill (the broad hold and its lift still apply).
func ksBootFillTool() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return ksFillToolFor(filepath.ToSlash(filepath.Clean(exe)), ksInstalledBinary, isExecutableFile)
}

// ksInstalledBinary is where the package installs WayHop (packaging/install.sh, the Entware feed).
const ksInstalledBinary = "/opt/sbin/wayhop"

// ksFillToolFor picks the fill tool: a binary started from tmpfs (a test build in /tmp,
// the hotfix loop) is gone after the reboot the fill exists for, so the installed one is rendered
// instead when it is there.
func ksFillToolFor(exe, installed string, executable func(string) bool) string {
	volatile := strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/var/") || strings.HasPrefix(exe, "/dev/shm/")
	if volatile && exe != installed && executable(installed) {
		exe = installed
	}
	if !validFillPath.MatchString(exe) {
		return ""
	}
	return exe
}

func isExecutableFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0
}

// ksBootHoldLift is the configured lift in seconds for the program (0 = never).
func ksBootHoldLift(cfg config.Config) int {
	switch {
	case cfg.KillSwitchBootHoldLift < 0:
		return 0
	case cfg.KillSwitchBootHoldLift == 0:
		return pbr.DefaultBootHoldLift
	}
	return cfg.KillSwitchBootHoldLift
}

// ksFillData is what a fill found in the two files.
type ksFillData struct {
	static, learned []netip.Prefix
	missing         []string // why it is incomplete; empty = complete
}

// readStaticKS reads the static members of sets from an ipset restore stream.
func readStaticKS(r io.Reader, sets []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 0; sc.Scan(); n++ {
		if n > ksFillMaxLines {
			return out, errors.New("too many lines")
		}
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[0] != "add" || !slices.Contains(sets, f[1]) {
			continue
		}
		if p, ok := parseSetEntry(f[2]); ok {
			out = append(out, p)
		}
	}
	return out, sc.Err()
}

// parseSetEntry reads an ipset member: an address or a prefix.
func parseSetEntry(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// readLearnedKS reads the learned file (killswitchlearned.go): `add` lines and the trailer that says
// how many there are. A file without a matching trailer is damaged; what it holds is still used.
func readLearnedKS(r io.Reader, sets []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	lines, want := 0, -1
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if rest, ok := strings.CutPrefix(line, ksLearnedTrailer); ok {
			want, _ = strconv.Atoi(strings.TrimSpace(rest))
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "add" {
			continue
		}
		if lines++; lines > ksFillMaxLines {
			return out, errors.New("too many lines")
		}
		if !slices.Contains(sets, f[1]) {
			continue
		}
		if p, ok := parseSetEntry(f[2]); ok {
			out = append(out, p)
		}
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	if want != lines {
		return out, fmt.Errorf("damaged: %d entries, trailer says %d", lines, want)
	}
	return out, nil
}

// gatherFill reads both files.
func gatherFill(static, learned string, sets, domains []string) ksFillData {
	var d ksFillData
	if static == "" {
		d.missing = append(d.missing, "no restore file")
	} else if f, err := os.Open(static); err != nil {
		d.missing = append(d.missing, "restore file: "+err.Error())
	} else {
		d.static, err = readStaticKS(f, sets)
		f.Close()
		if err != nil {
			d.missing = append(d.missing, "restore file: "+err.Error())
		}
	}
	if len(domains) == 0 {
		return d
	}
	if learned == "" {
		d.missing = append(d.missing, "no learned file")
	} else if f, err := os.Open(learned); err != nil {
		d.missing = append(d.missing, "learned addresses: "+err.Error())
	} else {
		d.learned, err = readLearnedKS(f, domains)
		f.Close()
		if err != nil {
			d.missing = append(d.missing, "learned addresses: "+err.Error())
		}
	}
	return d
}

// fillRoutes is what the table gets: the static prefixes aggregated, then learned members no static
// prefix covers.
func fillRoutes(d ksFillData) []netip.Prefix {
	var v4, v6 []netip.Prefix
	for _, p := range d.static {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	bs := pbr.Backstop{V4: pbr.AggregatePrefixes(v4), V6: pbr.AggregatePrefixes(v6)}
	want, _, _ := ksWant(bs, d.learned, nil, ksFillMaxLines)
	return want
}

// The fill's bounds: the hook, and NDM's rebuild with it, waits for the fill, and each
// refused or unanswered route can cost the socket's 3 s receive timeout. Past either bound the fill
// stops and exits partial; the broad hold and its timer stay in charge.
var (
	ksFillBudget        = 20 * time.Second
	ksFillMaxConsecFail = 16
)

// runBackstopFill installs the routes and writes the stamps; the exit status.
func runBackstopFill(t rtblackhole.Table, ready string, d ksFillData, stderr io.Writer) int {
	routes := fillRoutes(d)
	failed, consec, done := 0, 0, 0
	no6 := false // a kernel that refuses IPv6 routes forwards no IPv6
	start := time.Now()
	for _, p := range routes {
		if no6 && p.Addr().Is6() {
			done++
			continue
		}
		if consec >= ksFillMaxConsecFail {
			d.missing = append(d.missing, fmt.Sprintf("stopped after %d refusals in a row", consec))
			break
		}
		if time.Since(start) > ksFillBudget {
			d.missing = append(d.missing, fmt.Sprintf("stopped at the %s deadline", ksFillBudget))
			break
		}
		done++
		if err := t.Add(p); err != nil {
			if p.Addr().Is6() && errors.Is(err, rtblackhole.ErrFamilyUnsupported) {
				no6 = true
				fmt.Fprintf(stderr, "backstop-fill: the kernel refuses IPv6 routes (%v); IPv6 routes skipped\n", err)
				continue
			}
			failed++
			consec++
			if failed <= 3 {
				fmt.Fprintf(stderr, "backstop-fill: add %s: %v\n", p, err)
			}
			continue
		}
		consec = 0
	}
	if failed > 0 || done < len(routes) {
		d.missing = append(d.missing, fmt.Sprintf("%d of %d routes in", done-failed, len(routes)))
	}
	// The filled stamp records that every route read was installed. It is not proof that both fallback
	// files completed: the lift still verifies them (a fill cut short by its bounds leaves their routes).
	if failed == 0 && done == len(routes) {
		_ = os.WriteFile(ready+pbr.StampFilled, []byte(strconv.Itoa(done)+"\n"), 0o644)
	}
	if len(d.missing) > 0 {
		_ = os.WriteFile(ready+pbr.StampPartial, []byte(strings.Join(d.missing, "; ")+"\n"), 0o644)
		fmt.Fprintf(stderr, "backstop-fill: incomplete, the broad hold stays: %s\n", strings.Join(d.missing, "; "))
		return ksFillPartial
	}
	// Complete: the stamp first (the hook stops re-adding the hold), then the hold goes.
	if err := os.WriteFile(ready, nil, 0o644); err != nil {
		fmt.Fprintf(stderr, "backstop-fill: stamp %s: %v\n", ready, err)
		return 1
	}
	for _, p := range ksHold {
		if !slices.Contains(routes, p) {
			_ = t.Del(p)
		}
	}
	for _, p := range pbr.HoldSharedThrows() { // the hold's throws go with it
		_ = t.DelThrow(p)
	}
	return 0
}

// BackstopFill is `wayhop backstop-fill`; it returns the process exit status.
func BackstopFill(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("backstop-fill", flag.ContinueOnError)
	fs.SetOutput(stderr)
	table := fs.Int("table", 0, "backstop routing table")
	ready := fs.String("ready", "", "ready stamp (tmpfs)")
	static := fs.String("static", "", "the plane's ipset restore file")
	learned := fs.String("learned", "", "the learned members of kill-switched domain sets")
	sets := fs.String("sets", "", "every set of a kill-switched zone, comma-separated")
	domains := fs.String("domains", "", "the kill-switched domain sets, comma-separated")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *table <= 0 || !validFillPath.MatchString(*ready) || *sets == "" {
		fmt.Fprintln(stderr, "usage: wayhop backstop-fill -table N -ready STAMP -sets a,b [-static F] [-domains a] [-learned F]")
		return 2
	}
	split := func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.Split(s, ",")
	}
	d := gatherFill(*static, *learned, split(*sets), split(*domains))
	t, err := rtblackhole.Open(*table)
	if err != nil {
		fmt.Fprintf(stderr, "backstop-fill: %v\n", err)
		return 1
	}
	defer t.Close()
	return runBackstopFill(t, *ready, d, stderr)
}
