package keenetic

import (
	"context"
	"strings"
	"testing"
	"time"

	"wayhop/internal/failsafe"
)

// longGraceMgr builds a failsafe Manager whose timers never fire during a test, so the armed
// goroutine blocks on the grace timer and the test drives the state machine synchronously via
// Confirm()/RollbackNow() (both cancel the goroutine).
func longGraceMgr() *failsafe.Manager {
	return failsafe.New(failsafe.Durations{
		Grace: time.Hour, Interval: time.Hour, RollbackAfter: time.Hour, RebootAfter: time.Hour, KeepWindow: time.Hour,
	})
}

func TestBackend_Reboot(t *testing.T) {
	ts, recorded := fakeKeenetic(t, "admin", "secret")
	rci, _ := NewRCIClient(ts.URL, "admin", "secret")
	b := NewBackend(rci, &recRunner{}, CompileOptions{BaseIndex: 10}, ApplyOptions{}, SingboxApplyOptions{})
	if err := b.Reboot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(*recorded, "\n"), "system reboot") {
		t.Error("Reboot must submit `system reboot`")
	}
}

func TestSafeApply_DeploysUnsavedAndArms(t *testing.T) {
	ts, recorded := fakeKeenetic(t, "admin", "secret")
	rci, _ := NewRCIClient(ts.URL, "admin", "secret")
	b := NewBackend(rci, &recRunner{}, CompileOptions{BaseIndex: 10}, ApplyOptions{Save: true}, SingboxApplyOptions{})
	mgr := longGraceMgr()

	if err := b.SafeApply(context.Background(), awgProfile(), mgr, func() bool { return true }, false); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(*recorded, "\n")
	if !strings.Contains(got, "interface Wireguard10") {
		t.Error("SafeApply must deploy the candidate")
	}
	if strings.Contains(got, "system configuration save") {
		t.Error("SafeApply must NOT save — the window is intentionally unsaved so a reboot reverts")
	}
	if !mgr.Status().Pending {
		t.Error("the failsafe window must be armed")
	}
	if b.candidate == nil {
		t.Error("candidate must be set")
	}
	mgr.Confirm() // stop the armed goroutine
}

func TestConfirmSafe(t *testing.T) {
	ts, recorded := fakeKeenetic(t, "admin", "secret")
	rci, _ := NewRCIClient(ts.URL, "admin", "secret")
	b := NewBackend(rci, &recRunner{}, CompileOptions{BaseIndex: 10}, ApplyOptions{}, SingboxApplyOptions{})
	mgr := longGraceMgr()
	ctx := context.Background()

	if err := b.SafeApply(ctx, awgProfile(), mgr, func() bool { return true }, false); err != nil {
		t.Fatal(err)
	}
	cand := b.candidate
	mark := len(*recorded)
	if err := b.ConfirmSafe(ctx, mgr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join((*recorded)[mark:], "\n"), "system configuration save") {
		t.Error("ConfirmSafe must save the config")
	}
	if b.last != cand {
		t.Error("the candidate must be promoted to last")
	}
	if b.candidate != nil {
		t.Error("candidate must be cleared after confirm")
	}
	if ph := mgr.Status().Phase; ph != "committed" {
		t.Errorf("failsafe phase = %q, want committed", ph)
	}
	// Confirming with no candidate errors.
	if err := b.ConfirmSafe(ctx, mgr); err == nil {
		t.Error("ConfirmSafe with no candidate must error")
	}
}

func TestSafeApply_Rollback(t *testing.T) {
	ts, recorded := fakeKeenetic(t, "admin", "secret")
	rci, _ := NewRCIClient(ts.URL, "admin", "secret")
	b := NewBackend(rci, &recRunner{}, CompileOptions{BaseIndex: 10}, ApplyOptions{}, SingboxApplyOptions{})
	ctx := context.Background()

	// Establish a confirmed prior plan (the rollback target).
	mgr1 := longGraceMgr()
	if err := b.SafeApply(ctx, awgProfile(), mgr1, func() bool { return true }, false); err != nil {
		t.Fatal(err)
	}
	if err := b.ConfirmSafe(ctx, mgr1); err != nil {
		t.Fatal(err)
	}

	// New SafeApply (connectivity reported bad), then roll back.
	mgr2 := longGraceMgr()
	if err := b.SafeApply(ctx, awgProfile(), mgr2, func() bool { return false }, false); err != nil {
		t.Fatal(err)
	}
	mark := len(*recorded)
	if err := mgr2.RollbackNow(); err != nil {
		t.Fatal(err)
	}
	rb := strings.Join((*recorded)[mark:], "\n")
	if !strings.Contains(rb, "no interface Wireguard10") {
		t.Error("rollback must tear the candidate down")
	}
	if !strings.Contains(rb, "wireguard peer") { // deploy-only command ⇒ the prior plan was redeployed
		t.Error("rollback must redeploy the prior good plan")
	}
	if b.candidate != nil {
		t.Error("candidate must be cleared after rollback")
	}
}
