package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/rtblackhole"
)

// A kernel that refuses IPv6 route operations (no IPv6 routing: EOPNOTSUPP) made the
// first v6 member's add fail the whole sync, before releaseHold: no ready stamp, the broad hold for the
// full lift after every reboot. Nothing of that family is forwarded then; the family is skipped and
// the hold goes. A refused v4 route still fails the sync.
func TestBackstopSyncSkipsARefusedV6Family(t *testing.T) {
	s, table, _ := mirrorServer(t)
	hold4 := netip.MustParsePrefix("0.0.0.0/0")
	m4, m6 := netip.MustParsePrefix("198.51.100.9/32"), netip.MustParsePrefix("2001:db8::9/128")
	table.routes[hold4] = true
	table.refuse6 = fmt.Errorf("%w: operation not supported", rtblackhole.ErrFamilyUnsupported)
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(_ context.Context, set string) ([]netip.Prefix, error) {
			if strings.HasSuffix(set, "6") {
				return []netip.Prefix{m6}, nil
			}
			return []netip.Prefix{m4}, nil
		}
	}
	s.killSwitchMirrorTick(context.Background())
	if _, err := os.Stat(s.ksb.ready); err != nil {
		t.Fatal("no ready stamp: a refused v6 family blocked the hold's release")
	}
	if table.routes[hold4] || !table.routes[m4] {
		t.Fatalf("routes after the sync: %v", table.routes)
	}

	s2, table2, _ := mirrorServer(t)
	table2.addErr = errors.New("operation not permitted") // v4 refused: never optional
	s2.ksb.reader = s.ksb.reader
	table2.routes[hold4] = true
	s2.killSwitchMirrorTick(context.Background())
	if _, err := os.Stat(s2.ksb.ready); err == nil || !table2.routes[hold4] {
		t.Fatal("a refused v4 route released the hold")
	}
}

// The boot fill skips a v6 family the kernel refuses instead of exiting partial.
func TestBackstopFillSkipsARefusedV6Family(t *testing.T) {
	dir := t.TempDir()
	static := filepath.Join(dir, "policy.ipset")
	_ = os.WriteFile(static, []byte("add wr_list_tg_4 149.154.160.0/20 -exist\nadd wr_list_tg_6 2001:db8:100::/48 -exist\n"), 0o644)
	hold4 := netip.MustParsePrefix("0.0.0.0/0")
	table := &fakeRouteTable{routes: map[netip.Prefix]bool{hold4: true},
		refuse6: fmt.Errorf("%w: operation not supported", rtblackhole.ErrFamilyUnsupported)}
	ready := filepath.Join(dir, "ready")
	var errb bytes.Buffer
	code := runBackstopFill(table, ready, gatherFill(static, "", []string{"wr_list_tg_4", "wr_list_tg_6"}, nil), &errb)
	if code != 0 || table.routes[hold4] || !table.routes[netip.MustParsePrefix("149.154.160.0/20")] {
		t.Fatalf("code %d routes %v: %s", code, table.routes, errb.String())
	}
	if _, err := os.Stat(ready); err != nil {
		t.Fatal("no ready stamp")
	}
}
