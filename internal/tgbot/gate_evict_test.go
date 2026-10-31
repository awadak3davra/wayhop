package tgbot

import (
	"testing"
	"time"
)

// A chat sending wrong codes while a flood from fresh chats keeps the memory at its cap must still hit
// the limit. With equal timestamps the eviction picked whichever entry the map yielded first, which
// could be the sender itself, resetting its count (QA-057). Repeated, because map order is random.
func TestWrongCodeLimitSurvivesEvictionAtTheCap(t *testing.T) {
	for round := 0; round < 200; round++ {
		g := NewGate()
		now := testNow
		g.now = func() time.Time { return now }
		for id := int64(1); id <= maxBadChats; id++ {
			g.Redeem(Chat{ID: id, Type: "private"}, "ZZZZZZZZ")
		}
		for i := 0; i < maxBadCodes; i++ {
			g.Redeem(Chat{ID: 9999, Type: "private"}, "ZZZZZZZZ")
		}
		if _, res := g.Redeem(Chat{ID: 9999, Type: "private"}, "ZZZZZZZZ"); res != RedeemLimited {
			t.Fatalf("round %d: the sender's count was reset by eviction: %v", round, res)
		}
	}
}
