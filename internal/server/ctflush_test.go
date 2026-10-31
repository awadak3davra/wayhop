package server

import (
	"errors"
	"net/netip"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/ctflush"
	"wayhop/internal/pbr"
)

type countingTable struct{ dumps, deletes int }

func (c *countingTable) Dump(uint8, func(ctflush.Entry)) error { c.dumps++; return nil }
func (c *countingTable) Delete(ctflush.Entry) error            { c.deletes++; return nil }
func (c *countingTable) Close() error                          { return nil }

// The flush runs only when the kernel plan changed, and a router without ctnetlink (or a platform
// without netlink) changes nothing and fails nothing.
func TestFlushStaleFlows(t *testing.T) {
	orig := ctflushOpen
	t.Cleanup(func() { ctflushOpen = orig })
	tbl := &countingTable{}
	opens := 0
	ctflushOpen = func() (ctflush.Table, error) { opens++; return tbl, nil }

	p := &pbr.Plan{Mask: 0x00ff0000, Egresses: []pbr.Egress{{Tag: "direct"}, {Tag: "awg1", Mark: 0x20000}},
		Zones: []pbr.Zone{{Name: "a", Mark: 0x20000, V4: []string{"203.0.113.0/24"}}}}
	s := &Server{cfg: &config.Config{}}
	s.flushStaleFlows(p, p)
	if opens != 0 {
		t.Errorf("an unchanged plan opened conntrack %d time(s)", opens)
	}
	moved := &pbr.Plan{Mask: p.Mask, Egresses: p.Egresses}
	s.flushStaleFlows(p, moved)
	if opens != 1 || tbl.dumps != 2 {
		t.Errorf("a changed plan: opens %d, dumps %d; want 1 open and both families dumped", opens, tbl.dumps)
	}
	ctflushOpen = func() (ctflush.Table, error) { return nil, ctflush.ErrUnsupported }
	s.flushStaleFlows(p, nil) // must neither panic nor fail
	ctflushOpen = func() (ctflush.Table, error) { return nil, errors.New("protocol not supported") }
	s.flushStaleFlows(p, nil)

	// The demo daemon never touches the host's conntrack.
	opens = 0
	ctflushOpen = func() (ctflush.Table, error) { opens++; return tbl, nil }
	s.cfg.Demo = true
	s.flushStaleFlows(p, moved)
	if opens != 0 {
		t.Error("demo mode opened conntrack")
	}
}

// The router's own addresses come from its interfaces; loopback is always among them.
func TestOwnAddrs(t *testing.T) {
	own := ownAddrs()
	if !own(netip.MustParseAddr("127.0.0.1")) || own(netip.MustParseAddr("192.0.2.123")) {
		t.Error("ownAddrs must hold loopback and not a documentation address")
	}
}
