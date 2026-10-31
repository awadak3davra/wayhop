// Package ctflush removes the conntrack entries a routing change left pointing the wrong way.
//
// The kernel plane saves each flow's egress mark in its connmark and restores it on every packet, so
// an established flow can keep the exit it started on after an Apply moved its destination elsewhere -
// for QUIC or a Telegram call, for hours. HydraRoute Neo deletes such entries over netlink (competitor
// gap 5); this does the same, conservatively.
//
// The flush runs after the new plane is live and asks one question per entry: will the kernel route
// this flow's next packet differently from a new flow to the same place? Where the kernel already
// re-marks the flow itself, the entry is left alone. The two planes differ:
//
//   - nft (OpenWrt, pbr/render.go): a saved mark that is one of the plan's egress marks is restored
//     and the chain ends there, so such a flow is pinned; any other flow is re-marked by the zones.
//     In hybrid mode a flow without a mark may instead be held by the TUN's redirect.
//   - iptables + ipset (Keenetic, pbr/render_ipset.go): the restore does not end the chain, so a zone
//     that matches re-marks the flow; only a destination no zone matches keeps its restored mark.
//
// Anything the plan cannot see is kept: a zone whose membership dnsmasq fills at query time, a source
// predicate on MAC, interface or port, the bypass set (tunnel servers, routed to the WAN ahead of the
// restore), private destinations (pinned to the main table by ip rules), and the router's own
// connections (never marked: the mark hook is prerouting).
package ctflush

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"

	"wayhop/internal/pbr"
)

// ErrUnsupported is returned where there is no ctnetlink (not Linux).
var ErrUnsupported = errors.New("conntrack netlink is not available on this platform")

// ErrNoModule is returned when the kernel has no conntrack netlink subsystem loaded.
var ErrNoModule = errors.New("the kernel module nf_conntrack_netlink is not loaded")

// Entry is one conntrack entry as the dump reports it.
type Entry struct {
	Family uint8      // AF_INET (2) or AF_INET6 (10)
	Src    netip.Addr // original-direction source
	Dst    netip.Addr // original-direction destination
	Mark   uint32     // CTA_MARK
	tuple  []byte     // the raw CTA_TUPLE_ORIG attribute, sent back to delete it
	zone   []byte     // the raw CTA_ZONE attribute, when the entry is not in the default zone
	id     []byte     // the raw CTA_ID attribute: the delete then removes this entry and no other
}

// Table is the conntrack table: the netlink one on Linux, a fake in tests. Dump hands each entry to
// visit as it is read; the entry's raw attributes are valid only during the call.
type Table interface {
	Dump(family uint8, visit func(Entry)) error
	Delete(e Entry) error
	Close() error
}

// Plane is the kernel plane that installed the plan.
type Plane int

const (
	PlaneNft   Plane = iota // OpenWrt: restore-and-accept for the plan's egress marks
	PlaneIpset              // Keenetic: restore, then the zones re-mark
)

// Options bound and steer a flush.
type Options struct {
	Limit  int                   // most deletions per flush; 0 = no limit
	Local  func(netip.Addr) bool // the router's own addresses; their flows are never touched
	Plane  Plane
	Hybrid bool // nft with a TUN beside it: a flow without a mark may be held by the TUN's redirect
}

// Result says what a flush did.
type Result struct {
	Seen    int // entries examined
	Deleted int // entries removed
	Gone    int // entries that vanished between the dump and the delete
	Capped  bool
}

// tri is a three-valued match: the plan may not be able to tell.
type tri int8

const (
	no tri = iota
	yes
	unknown
)

// zoneView is one zone as the decider needs it.
type zoneView struct {
	mark       uint32
	v4, v6     []netip.Prefix // static members, sorted, non-overlapping (pbr collapses each zone)
	domains    bool           // dnsmasq adds members at query time (the Keenetic plane)
	sourceOnly bool           // no destination set: every destination of its sources
	scoped     bool
	srcHidden  bool // MAC, interface or port predicates: conntrack does not show them
	src4, src6 []netip.Prefix
	negate     bool
}

// view is what one plan says about where a new flow goes.
type view struct {
	tags   map[uint32]string // owned egress mark -> tag
	wan    map[uint32]bool   // marks that route like no mark (the WAN egress: main table)
	zones  []zoneView        // plan order: the kernel emits them so, and the last match wins
	bypass []netip.Prefix
}

func newView(p *pbr.Plan, mask uint32) view {
	v := view{tags: map[uint32]string{}, wan: map[uint32]bool{}}
	if p == nil {
		return v
	}
	for _, e := range p.Egresses {
		m := e.Mark & mask
		if m == 0 {
			continue
		}
		v.tags[m] = e.Tag
		if e.Kind == pbr.EgressWAN {
			v.wan[m] = true
		}
	}
	// A KeeneticOS access policy's slot is what its flows' connmark holds (the rewrite into NDM's mark
	// comes after the save), so the plan owns it like an egress mark. Without it, routing off or a
	// rollback to no plane left policy flows on their NAT binding to the tunnel while the main table now
	// sent them out of the WAN - dead until the app gave up (QA-062).
	for _, ps := range p.NDMPolicySlots() {
		if m := ps.Slot & mask; m != 0 {
			v.tags[m] = "ndm-policy:" + ps.Name
		}
	}
	for _, z := range p.Zones {
		zv := zoneView{
			mark: z.Mark & mask, v4: parsePrefixes(z.V4), v6: parsePrefixes(z.V6), domains: len(z.Domains) > 0,
			scoped:    z.SrcScoped || len(z.SrcV4)+len(z.SrcV6)+len(z.SrcMAC)+len(z.SrcIface)+len(z.SrcPort) > 0,
			srcHidden: len(z.SrcMAC)+len(z.SrcIface)+len(z.SrcPort) > 0,
			src4:      parsePrefixes(z.SrcV4), src6: parsePrefixes(z.SrcV6), negate: z.SrcNegate,
		}
		zv.sourceOnly = zv.scoped && len(zv.v4)+len(zv.v6) == 0 && !zv.domains
		if len(zv.v4)+len(zv.v6) == 0 && !zv.domains && !zv.sourceOnly {
			continue // matches nothing
		}
		v.zones = append(v.zones, zv)
	}
	v.bypass = append(parsePrefixes(p.BypassV4), parsePrefixes(p.BypassV6)...)
	return v
}

func (v view) owns(m uint32) bool { _, ok := v.tags[m]; return ok }

func parsePrefixes(cidrs []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(c); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr().Less(out[j].Addr()) })
	return out
}

// contains reports whether the sorted, non-overlapping prefixes of one zone hold a: the last prefix
// starting at or before a is the only one that can.
func contains(ps []netip.Prefix, a netip.Addr) bool {
	k := sort.Search(len(ps), func(j int) bool { return a.Less(ps[j].Addr()) }) - 1
	return k >= 0 && ps[k].Contains(a)
}

// containsAny is contains for a list that may overlap.
func containsAny(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// match is whether zone z marks e: its destination test AND its source test, as the planes render them.
func (z zoneView) match(e Entry) tri {
	v6 := e.Dst.Is6()
	dst := no
	switch {
	case z.sourceOnly:
		dst = yes
	case !v6 && contains(z.v4, e.Dst), v6 && contains(z.v6, e.Dst):
		dst = yes
	case z.domains:
		dst = unknown
	}
	if dst == no {
		return no
	}
	src := yes
	switch {
	case !z.scoped:
	case z.srcHidden || !e.Src.IsValid() || len(z.src4)+len(z.src6) == 0:
		src = unknown
	default:
		set := z.src4
		if v6 {
			set = z.src6
		}
		// A positive group with no address of this family has no rule for it (render.go emits none);
		// a negated one ("every device except") matches every source of that family.
		if containsAny(set, e.Src) == z.negate {
			src = no
		}
	}
	switch {
	case src == no:
		return no
	case dst == yes && src == yes:
		return yes
	}
	return unknown
}

// eval is the mark the plan gives a new flow like e: the last zone that matches wins (matched), none
// means no mark. known is false when a zone the decision depends on cannot be evaluated.
func (v view) eval(e Entry) (mark uint32, matched, known bool) {
	for i := len(v.zones) - 1; i >= 0; i-- {
		switch v.zones[i].match(e) {
		case yes:
			return v.zones[i].mark, true, true
		case unknown:
			return 0, false, false
		}
	}
	return 0, false, true
}

// route folds the marks that route like no mark at all (the WAN egress) into 0. In hybrid mode an
// unmarked flow may belong to the TUN while a WAN-marked one goes straight out, so folding them can
// only keep a flow that should move, never move one that should stay.
func (v view) route(m uint32) uint32 {
	if v.wan[m] {
		return 0
	}
	return m
}

// privateDst is what pbr pins to the main table ahead of the fwmark rules (render.go privateExcludes):
// a mark does not move such a flow, so deleting it would only reset it.
var privateDst = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// decider holds what the plans say and how the plane applies them.
type decider struct {
	mask     uint32
	old, cur view
	removed  bool // no plane now
	opt      Options
}

func newDecider(old, cur *pbr.Plan, opt Options) decider {
	d := decider{removed: cur == nil, opt: opt}
	switch {
	case cur != nil && cur.Mask != 0:
		d.mask = cur.Mask
	case old != nil && old.Mask != 0:
		d.mask = old.Mask
	default:
		d.mask = 0x00ff0000
	}
	d.old, d.cur = newView(old, d.mask), newView(cur, d.mask)
	return d
}

// stale reports whether the kernel will route e's next packet somewhere other than where the plan now
// sends a new flow to the same destination.
func (d decider) stale(e Entry) bool {
	e.Src, e.Dst = e.Src.Unmap(), e.Dst.Unmap()
	if !e.Dst.IsValid() || e.Dst.IsLoopback() || containsAny(privateDst, e.Dst) || containsAny(d.cur.bypass, e.Dst) {
		return false
	}
	if d.opt.Local != nil && (d.opt.Local(e.Dst) || (e.Src.IsValid() && d.opt.Local(e.Src))) {
		return false
	}
	m := e.Mark & d.mask
	if d.removed {
		// No plane: no restore, no fwmark rules. A flow the old plane sent to a tunnel now leaves by
		// the WAN under that tunnel's NAT binding - dead, but kept alive by its own retries. Only the
		// old plan can say a mark was its own; without one nothing is touched.
		return m != 0 && d.old.owns(m) && !d.old.wan[m]
	}
	nm, matched, known := d.cur.eval(e)
	if !known {
		return false
	}
	if d.opt.Plane == PlaneIpset {
		if matched {
			return false // the zone re-marks the next packet after the restore
		}
		// No zone: the restored mark stays and routes the flow.
		return d.cur.owns(m) && d.cur.route(m) != 0
	}
	if m != 0 && d.cur.owns(m) {
		return d.cur.route(nm) != d.cur.route(m) // restored and accepted: pinned to m's exit
	}
	// No mark, or one the plan no longer has: the zones re-mark the next packet. Only a flow the TUN
	// redirected cannot follow a destination that now goes to a kernel exit.
	return m == 0 && d.opt.Hybrid && d.cur.route(nm) != 0
}

// Changed reports whether moving from old to cur can leave a flow on the wrong exit at all: the mask,
// the egresses, the bypass set or any zone (its members, sources or mark) changed. An unchanged plan
// needs no dump.
func Changed(old, cur *pbr.Plan) bool {
	if (old == nil) != (cur == nil) {
		return true
	}
	if old == nil {
		return false
	}
	return old.Mask != cur.Mask || !reflect.DeepEqual(old.Egresses, cur.Egresses) ||
		!reflect.DeepEqual(old.Zones, cur.Zones) || !reflect.DeepEqual(old.BypassV4, cur.BypassV4) ||
		!reflect.DeepEqual(old.BypassV6, cur.BypassV6)
}

// Flush deletes the entries the move from old to cur left on the wrong exit, both families. cur nil
// means the kernel plane was removed. The table is walked, not held: only entries to delete are kept,
// at most Limit+1 of them. Any dump error ends the flush before a single delete.
func Flush(t Table, old, cur *pbr.Plan, opt Options) (Result, error) {
	var res Result
	if old == nil && cur == nil {
		return res, nil
	}
	d := newDecider(old, cur, opt)
	var doomed []Entry
	for _, fam := range []uint8{2, 10} {
		err := t.Dump(fam, func(e Entry) {
			res.Seen++
			if (opt.Limit <= 0 || len(doomed) <= opt.Limit) && d.stale(e) {
				doomed = append(doomed, e.detach())
			}
		})
		if err != nil {
			if errors.Is(err, ErrNoModule) {
				return res, err
			}
			return res, fmt.Errorf("conntrack dump (family %d): %w", fam, err)
		}
	}
	var firstErr error
	for _, e := range doomed {
		if opt.Limit > 0 && res.Deleted+res.Gone >= opt.Limit {
			res.Capped = true
			break
		}
		switch err := t.Delete(e); {
		case err == nil:
			res.Deleted++
		case errors.Is(err, errNoEntry):
			res.Gone++
		default:
			if firstErr == nil {
				firstErr = fmt.Errorf("conntrack delete: %w", err)
			}
		}
	}
	return res, firstErr
}

// errNoEntry is the kernel's ENOENT for a delete: the flow ended between the dump and the delete.
var errNoEntry = errors.New("conntrack entry already gone")
