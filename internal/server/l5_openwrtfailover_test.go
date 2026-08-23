package server

import (
	"os"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestListFailoverIsNotKeeneticShaped (L5): the owner that repoints a routing list's table must run
// on the routers that need it, not only on the one it was written against.
//
// Measured on a live AX3000T (OpenWrt 25.12.2) over ssh:
//
//	ipset     MISSING
//	iptables  MISSING
//	nft       /usr/sbin/nft
//	150: from all fwmark 0x20000/0xff0000 lookup 151   → table 151: default dev awg0
//	151: from all fwmark 0x30000/0xff0000 lookup 152   → table 152: default dev awg1
//	                                                     table 153: default dev awg1
//
// The tick's precondition used to be "ipset AND iptables present" — a Keenetic-shaped question that
// answers NO on that router. Three WayHop tables, pinned to whatever Apply chose, and no owner: when
// the pinned member dies the kernel flushes the route, the fwmark lookup finds an empty table and
// falls through to main — the provider. The leak this file exists to close, closed on one platform.
//
// The precondition is now iproute2, which is what the loop actually uses. Pinned at the source
// because the regression IS a precondition: a behavioural assertion cannot distinguish "asks about
// iproute2" from "asks about iproute2 and also about ipset" on a host that has both.
func TestListFailoverIsNotKeeneticShaped(t *testing.T) {
	src, err := os.ReadFile("listfailover.go")
	if err != nil {
		t.Fatalf("read listfailover.go: %v", err)
	}
	start := strings.Index(string(src), "func (s *Server) listFailoverTick(")
	if start < 0 {
		t.Fatal("listFailoverTick is gone — this gate is about its precondition")
	}
	// The end marker is the closing brace at column 0. An earlier version looked for the next
	// "newline + // listFailover" comment — which matches a comment INSIDE the function
	// ("listFailoverTargets only yields a table that..."), truncating the body just before the
	// precondition this gate exists to read. Both mutations passed against that. A gate that
	// cannot see its own subject asserts nothing.
	rest := string(src)[start:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatal("listFailoverTick has no closing brace at column 0")
	}
	body := rest[:end]
	if !strings.Contains(body, "iprouteAvailable()") {
		t.Errorf("the loop writes with iproute2, so that is the thing to require")
	}
	// The prose above the check names both tools, deliberately, to record what was removed — so the
	// scan is over CODE with comment lines dropped, not over the whole function.
	code := []string{}
	for _, line := range strings.Split(body, "\n") {
		if trimmed := strings.TrimSpace(line); !strings.HasPrefix(trimmed, "//") {
			code = append(code, line)
		}
	}
	// Case-insensitive on purpose: the identifier that reintroduces the platform question is spelled
	// keeneticKernelPBRPresent, and a scan for "Keenetic" walked straight past it — the mutation that
	// re-added exactly that call passed this gate.
	lowered := strings.ToLower(strings.Join(code, "\n"))
	for _, banned := range []string{"ipset", "iptables", "keenetic"} {
		if strings.Contains(lowered, banned) {
			t.Errorf("the precondition must not be platform-shaped again: %q is back in listFailoverTick", banned)
		}
	}
}

// TestElectMemberOnAMixedGroup (L5): which member a table may be repointed to, on the exact group
// shape a live OpenWrt router runs — one native tunnel beside one an engine carries.
//
// The election is over KERNEL links: a member the core carries has no interface for `ip route
// replace` to name, so it can never be elected into a table. That is what makes "2 exits deep"
// false for a list riding this group, and it is why the honest answer when the native member dies is
// "no candidate" rather than a second name that cannot be written.
func TestElectMemberOnAMixedGroup(t *testing.T) {
	mixed := model.Group{ID: "group-failover", Type: "fallback", Members: []string{"tunnel-a", "proxy-member"}}
	ifaceOf := map[string]string{"tunnel-a": "awg1"} // the socks member has no kernel link

	if iface, ok := electMember(mixed, ifaceOf, map[string]bool{"tunnel-a": true, "proxy-member": true}); !ok || iface != "awg1" {
		t.Errorf("a healthy native member is the one that can be written: %q %v", iface, ok)
	}
	// The measured failure: native down, proxy up. There is nothing to write, and saying so is the
	// point — electing the proxy would name an interface that does not exist.
	if iface, ok := electMember(mixed, ifaceOf, map[string]bool{"tunnel-a": false, "proxy-member": true}); ok {
		t.Errorf("a member with no kernel link must never be elected, got %q", iface)
	}

	// Two native members: the operator's ORDER decides, and a dead first member falls to the second.
	// This is the failover the whole file exists to perform.
	ordered := model.Group{ID: "g", Type: "fallback", Members: []string{"a", "b", "c"}}
	links := map[string]string{"a": "awg0", "b": "awg1", "c": "awg2"}
	if iface, ok := electMember(ordered, links, map[string]bool{"a": false, "b": true, "c": true}); !ok || iface != "awg1" {
		t.Errorf("the first HEALTHY member in the operator's order carries it: %q %v", iface, ok)
	}
	if iface, ok := electMember(ordered, links, map[string]bool{"a": true, "b": true, "c": true}); !ok || iface != "awg0" {
		t.Errorf("with everything up the first member keeps it: %q %v", iface, ok)
	}
	// Nothing alive, and an empty group, are both "do not write" rather than "write the first name".
	if _, ok := electMember(ordered, links, map[string]bool{}); ok {
		t.Error("with no healthy member there is nothing to elect")
	}
	if _, ok := electMember(model.Group{ID: "empty"}, links, map[string]bool{}); ok {
		t.Error("an empty group elects nothing")
	}
}
