package keenetic

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

func awgProfile() *model.Profile {
	awg := awgEndpoint()
	awg.ID, awg.Enabled = "awg-nl", true
	return &model.Profile{
		Endpoints:    []model.Endpoint{awg},
		RoutingLists: []model.RoutingList{{ID: "ru", Manual: []string{"109.254.0.0/16"}, Outbound: "awg-nl", Enabled: true}},
	}
}

func TestBackend_Apply_Idempotent(t *testing.T) {
	ts, recorded := fakeKeenetic(t, "admin", "secret")
	rci, _ := NewRCIClient(ts.URL, "admin", "secret")
	b := NewBackend(rci, &recRunner{}, CompileOptions{BaseIndex: 10}, ApplyOptions{Save: true}, SingboxApplyOptions{})

	if b.Platform() != platform.Keenetic {
		t.Fatalf("Platform = %q, want keenetic", b.Platform())
	}

	ctx := context.Background()
	p := awgProfile()

	// First apply: deploy, no teardown.
	if err := b.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	first := strings.Join(*recorded, "\n")
	if !strings.Contains(first, "interface Wireguard10") {
		t.Errorf("first apply must deploy the interface\n%s", first)
	}
	if strings.Contains(first, "no interface") {
		t.Errorf("first apply must NOT tear anything down\n%s", first)
	}

	mark := len(*recorded)

	// Second apply: must tear the prior plan down BEFORE redeploying.
	if err := b.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	second := strings.Join((*recorded)[mark:], "\n")
	if !strings.Contains(second, "no interface Wireguard10") {
		t.Errorf("re-apply must remove the prior interface\n%s", second)
	}
	if !strings.Contains(second, "no ip route 109.254.0.0 255.255.0.0 Wireguard10") {
		t.Errorf("re-apply must remove the prior route\n%s", second)
	}
	if !strings.Contains(second, "wireguard peer") { // deploy-only command ⇒ redeploy happened
		t.Errorf("re-apply must redeploy\n%s", second)
	}
	if strings.Index(second, "no interface Wireguard10") > strings.Index(second, "wireguard peer") {
		t.Errorf("teardown must precede redeploy\n%s", second)
	}
}

func TestBackend_Teardown(t *testing.T) {
	ts, recorded := fakeKeenetic(t, "admin", "secret")
	rci, _ := NewRCIClient(ts.URL, "admin", "secret")
	b := NewBackend(rci, &recRunner{}, CompileOptions{BaseIndex: 10}, ApplyOptions{}, SingboxApplyOptions{})
	ctx := context.Background()

	if err := b.Apply(ctx, awgProfile()); err != nil {
		t.Fatal(err)
	}
	if b.last == nil {
		t.Fatal("last plan must be remembered after Apply")
	}
	mark := len(*recorded)

	if err := b.Teardown(ctx); err != nil {
		t.Fatal(err)
	}
	td := strings.Join((*recorded)[mark:], "\n")
	if !strings.Contains(td, "no interface Wireguard10") {
		t.Errorf("Teardown must remove the interface\n%s", td)
	}
	if b.last != nil {
		t.Error("last plan must be cleared after Teardown")
	}

	// Teardown again is a no-op (nothing applied).
	mark = len(*recorded)
	if err := b.Teardown(ctx); err != nil {
		t.Fatal(err)
	}
	if len(*recorded) != mark {
		t.Error("second Teardown must be a no-op")
	}
}

// TestBackend_StatePersistence: a fresh Backend pointed at a prior state file remembers the
// last plan, so its FIRST Apply tears the prior config down (cross-restart idempotency).
func TestBackend_StatePersistence(t *testing.T) {
	ts, recorded := fakeKeenetic(t, "admin", "secret")
	rci, _ := NewRCIClient(ts.URL, "admin", "secret")
	ctx := context.Background()
	statePath := filepath.Join(t.TempDir(), "keen-state.json")

	// First daemon "instance" applies and persists.
	b1 := NewBackend(rci, &recRunner{}, CompileOptions{BaseIndex: 10}, ApplyOptions{}, SingboxApplyOptions{}).WithStatePath(statePath)
	if err := b1.Apply(ctx, awgProfile()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state file not written: %v", err)
	}

	// Second "instance" (simulating a restart) loads the state — its first Apply must tear
	// the prior interface down before redeploying.
	b2 := NewBackend(rci, &recRunner{}, CompileOptions{BaseIndex: 10}, ApplyOptions{}, SingboxApplyOptions{}).WithStatePath(statePath)
	if b2.last == nil {
		t.Fatal("restart must load the persisted last plan")
	}
	mark := len(*recorded)
	if err := b2.Apply(ctx, awgProfile()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join((*recorded)[mark:], "\n"), "no interface Wireguard10") {
		t.Error("post-restart Apply must tear down the persisted prior config")
	}

	// Teardown clears the state file.
	if err := b2.Teardown(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Error("Teardown must remove the state file")
	}
}
