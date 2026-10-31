package server

import (
	"context"
	"testing"
)

// The bot's switch is the panel's switch, recorded as Telegram's, and the watcher's pulse says so.
func TestTelegramBackendSwitchesRouting(t *testing.T) {
	s, _, _ := routingtest_server(t)
	be := tgBackend{s: s}
	if err := be.SetRouting(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if v := s.routingSwitchView(); v.Enabled || v.By != routingByTelegram {
		t.Fatalf("switched from Telegram: %+v", v)
	}
	if p := be.Pulse(context.Background()); !p.RoutingOff || p.LocalFault {
		t.Fatalf("pulse with routing off: %+v", p)
	}
	if err := be.SetRouting(context.Background(), true); err != nil || s.routingIsOff() {
		t.Fatalf("switch on from Telegram: %v, off=%v", err, s.routingIsOff())
	}
	if p := be.Pulse(context.Background()); p.RoutingOff {
		t.Fatal("pulse still says routing is off")
	}
}
