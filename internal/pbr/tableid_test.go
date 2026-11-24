package pbr

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// Measured on a KeeneticOS router (BusyBox 1.37 ip): `table 59999` is refused ("invalid argument"),
// tables 151..153, 407, 4096 and 16389 are in use. Every table WayHop allocates (per-egress and
// per-list tables, the backstop, the hand-off and its return table) stays below MaxTableID.
func TestEveryAllocatedTableStaysWithinTheBusyBoxBound(t *testing.T) {
	var opt Options
	opt.withDefaults()
	top := HandoffReturnTable(opt)
	for _, n := range []int{opt.TableBase, opt.TableBase + 255, BackstopTable(opt), HandoffTable(opt), top} {
		if n < 1 || n > MaxTableID {
			t.Fatalf("table %d outside 1..%d", n, MaxTableID)
		}
	}
	if top != opt.TableBase+258 || BackstopTable(opt) >= HandoffTable(opt) {
		t.Fatalf("the window changed: base %d top %d", opt.TableBase, top)
	}
	_, _, err := Compile(&model.Profile{}, Options{TableBase: MaxTableID - 100})
	if err == nil || !strings.Contains(err.Error(), "routing table") {
		t.Fatalf("a table base whose window passes %d compiled: %v", MaxTableID, err)
	}
}
