package config

import (
	"encoding/json"
	"slices"
	"testing"
)

// A chat's own alert switches survive a save, and a copy shares nothing with what it was taken
// from: the bot edits copies, and an edit that leaked into the live settings would skip validation.
func TestTelegramChatAlertsOffAndClone(t *testing.T) {
	in := Telegram{
		AlertsOff: []string{"switches"},
		Chats:     []TelegramChat{{ID: 600, Name: "Mom", Role: TelegramViewer, AlertsOff: []string{"apply", "updates"}}},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Telegram
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(out.Chats[0].AlertsOff, []string{"apply", "updates"}) {
		t.Fatalf("round trip lost the chat's switches: %s", raw)
	}

	c := in.Clone()
	c.Chats[0].AlertsOff[0] = "exits"
	c.Chats[0].Role = TelegramOwner
	c.AlertsOff[0] = "core"
	if in.Chats[0].AlertsOff[0] != "apply" || in.Chats[0].Role != TelegramViewer || in.AlertsOff[0] != "switches" {
		t.Fatalf("the clone wrote through to the original: %+v", in)
	}
	if r := in.Redacted(); &r.Chats[0].AlertsOff[0] == &in.Chats[0].AlertsOff[0] {
		t.Fatal("Redacted shares a chat's switches with the original")
	}
}
