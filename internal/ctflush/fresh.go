package ctflush

import (
	"errors"
	"fmt"
	"net/netip"
)

// Fresh steers FlushFresh.
type Fresh struct {
	// Mask is the plan's mark mask: a flow with a mark under it is the kernel plane's already.
	Mask uint32
	// CoreMark is the core TUN's input mark: such a flow is the core's already.
	CoreMark uint32
	// Stale is, per address, a plan mark that no longer wins it: the WAN mark of an
	// address a tunnel or block list's names have just taken. A flow saved with it is the weaker
	// list's and is deleted like an unmarked one; its replacement is classified afresh.
	Stale map[netip.Addr]uint32
	// Keep reports a source whose WAN flow a stronger direct exemption (a device-scoped direct list)
	// holds on the WAN anyway: its replacement would go the same way, so a live call is
	// not reset for nothing. nil: none.
	Keep func(src netip.Addr) bool
}

// FlushFresh deletes the flows to addresses that have just entered a resolver-fed set of the fast DNS
// plane (keen-pbr #129). The mark of a flow is set on its first packet, so a connection opened to an
// address before dnsmasq put it into a list's set keeps going the default way (or stays pinned past
// the core) for as long as it lives. Deleted, it starts again and is routed like any new flow.
//
// Only flows with no plan mark (or the mark Fresh.Stale names for their address) and not held by the
// core (its mark, or a destination NAT to another address: the core's TCP redirect) are touched; a DNAT to the flow's own destination is the core pin,
// which is exactly what has to go. The router's own flows (opt.Local) are kept, opt.Limit bounds the
// deletions.
func FlushFresh(t Table, addrs map[netip.Addr]bool, opt Options, f Fresh) (Result, error) {
	var res Result
	if len(addrs) == 0 {
		return res, nil
	}
	local := func(a netip.Addr) bool { return opt.Local != nil && opt.Local(a) }
	var doomed []Entry
	for _, fam := range []uint8{2, 10} {
		err := t.Dump(fam, func(e Entry) {
			res.Seen++
			dst, src := e.Dst.Unmap(), e.Src.Unmap()
			if !addrs[dst] || local(src) || local(dst) {
				return
			}
			if f.Mask != 0 && e.Mark&f.Mask != 0 {
				if stale, ok := f.Stale[dst]; !ok || e.Mark&f.Mask != stale || (f.Keep != nil && f.Keep(src)) {
					return
				}
			}
			if f.CoreMark != 0 && e.Mark&^f.Mask == f.CoreMark {
				return
			}
			if r := e.ReplySrc.Unmap(); r.IsValid() && r != dst {
				return
			}
			if opt.Limit <= 0 || len(doomed) <= opt.Limit {
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
