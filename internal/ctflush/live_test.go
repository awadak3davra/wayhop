package ctflush

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"wayhop/internal/pbr"
)

// ownFlows narrows the real table to the test's own flows, so nothing else on the host can be
// judged, let alone deleted.
type ownFlows struct {
	Table
	dsts map[netip.Addr]bool
}

func (o ownFlows) Dump(fam uint8, visit func(Entry)) error {
	return o.Table.Dump(fam, func(e Entry) {
		if o.dsts[e.Dst] {
			visit(e)
		}
	})
}

// TestLiveFlush runs against the real kernel (root, nft, nf_conntrack_netlink): two UDP flows into a
// dummy interface are marked in conntrack by a throwaway nft table, the plan moves one of them to
// another exit, and only that one must leave the table. WR_CTFLUSH_LIVE=1 to run, in a throwaway
// environment (WSL as root); it refuses to run where WayHop's own plane is installed.
func TestLiveFlush(t *testing.T) {
	if os.Getenv("WR_CTFLUSH_LIVE") != "1" {
		t.Skip("WR_CTFLUSH_LIVE not set — needs root, nft and nf_conntrack_netlink")
	}
	if exec.Command("nft", "list", "table", "inet", "wayhop_pbr").Run() == nil {
		t.Fatal("WayHop's routing plane is installed on this host; run the live test somewhere disposable")
	}
	const table, dev = "wr_ctflush_test", "wrct0"
	run := func(args ...string) {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	_ = exec.Command("ip", "link", "del", dev).Run()
	run("ip", "link", "add", dev, "type", "dummy")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", dev).Run() })
	run("ip", "addr", "add", "198.51.100.1/24", "dev", dev)
	run("ip", "link", "set", dev, "up")
	rules := `table inet ` + table + ` {
	chain out {
		type filter hook output priority 0; policy accept;
		ip daddr 198.51.100.2 udp dport 40001 ct mark set 0x00030000
		ip daddr 198.51.100.3 udp dport 40001 ct mark set 0x00020000
	}
}`
	_ = exec.Command("nft", "delete", "table", "inet", table).Run()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", table).Run() })

	a, b := netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("198.51.100.3")
	for _, dst := range []string{"198.51.100.2:40001", "198.51.100.3:40001"} {
		c, err := net.Dial("udp", dst)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("x"))
		_ = c.Close()
	}

	real, err := Open()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer real.Close()
	tbl := ownFlows{Table: real, dsts: map[netip.Addr]bool{a: true, b: true}}
	present := func() map[netip.Addr]uint32 {
		got := map[netip.Addr]uint32{}
		if err := tbl.Dump(2, func(e Entry) { got[e.Dst] = e.Mark }); err != nil {
			t.Fatalf("dump: %v", err)
		}
		return got
	}
	before := present()
	if before[a] != 0x30000 || before[b] != 0x20000 {
		t.Fatalf("test flows not in the table with their marks: %v", before)
	}

	eg := []pbr.Egress{{Tag: "direct"}, {Tag: "awg1", Mark: 0x20000}, {Tag: "awg2", Mark: 0x30000}}
	old := &pbr.Plan{Mask: 0x00ff0000, Egresses: eg, Zones: []pbr.Zone{
		{Name: "a", Mark: 0x30000, V4: []string{"198.51.100.2/32"}}, {Name: "b", Mark: 0x20000, V4: []string{"198.51.100.3/32"}}}}
	cur := &pbr.Plan{Mask: 0x00ff0000, Egresses: eg, Zones: []pbr.Zone{
		{Name: "a", Mark: 0x20000, V4: []string{"198.51.100.2/32"}}, {Name: "b", Mark: 0x20000, V4: []string{"198.51.100.3/32"}}}}
	res, err := Flush(tbl, old, cur, Options{Limit: 2})
	if err != nil {
		t.Fatalf("flush: %v (%+v)", err, res)
	}
	after := present()
	if _, ok := after[a]; ok || res.Deleted != 1 {
		t.Errorf("the moved flow is still there: %v (%+v)", after, res)
	}
	if after[b] != 0x20000 {
		t.Errorf("the unchanged flow was removed: %v (%+v)", after, res)
	}
	t.Logf("flush: %+v; before %v; after %v", res, before, after)
}
