package model

import "testing"

// A media list is recognised by whole words of its id and name, not by a substring.
func TestMediaListMatchesWholeWords(t *testing.T) {
	for _, tt := range []struct {
		id, name string
		want     bool
	}{
		{"cidr-telegram", "Telegram networks", true},
		{"svc-telegram-calls", "Telegram calls (voice IPs)", true},
		{"svc-youtube", "YouTube", true},
		{"cidr-meta", "Meta networks", true},
		{"custom-1", "Instagram + Threads", true},
		{"my_youtube", "", true},
		{"custom-2", "Metal shop", false},
		{"metamask", "MetaMask", false},
		{"custom-3", "metacritic reviews", false},
		{"metadata", "Cloud metadata", false},
		{"work", "Work", false},
	} {
		rl := RoutingList{ID: tt.id, Name: tt.name}
		if got := MediaList(rl); got != tt.want {
			t.Errorf("MediaList(%q, %q) = %v, want %v", tt.id, tt.name, got, tt.want)
		}
		wantMode := ElectionLatency
		if tt.want {
			wantMode = ElectionMixed
		}
		if got := (FastestPolicy{}).ElectionFor(rl); got != wantMode {
			t.Errorf("ElectionFor(%q) = %q, want %q", tt.id, got, wantMode)
		}
	}
}
