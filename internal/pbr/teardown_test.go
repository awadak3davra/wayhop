package pbr

import (
	"errors"
	"strings"
	"testing"
)

// failRunner fails any command whose text contains one of `fail`, with the given error.
type failRunner struct {
	fail []string
	err  error
	ran  []string
}

func (f *failRunner) Run(stdin, name string, args ...string) (string, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.ran = append(f.ran, cmd)
	for _, m := range f.fail {
		if strings.Contains(cmd, m) {
			return "", f.err
		}
	}
	return "", nil
}

func teardownPlan() *Plan {
	return &Plan{Table: "wayhop_test", Zones: []Zone{{Name: "z1", EgressTag: "e1", Mark: 0x100, V4: []string{"10.0.0.0/8"}}}}
}

// A teardown that removed nothing still reported success, because Teardown discarded every error
// and always returned nil. Rules it failed to delete keep steering traffic.
func TestTeardownVerified_ReportsWhatCouldNotBeRemoved(t *testing.T) {
	pl := teardownPlan()
	r := &failRunner{fail: []string{"rule del"}, err: errors.New("RTNETLINK answers: Operation not permitted")}
	res := pl.TeardownVerified(r, Options{})
	if res.Commands == 0 {
		t.Fatal("no teardown commands were issued — the test proves nothing")
	}
	if res.Clean() {
		t.Fatal("a permission failure left rules in the kernel; this must not report clean")
	}
	if res.Err() == nil {
		t.Error("Err() must be non-nil when something is left behind")
	}
	for _, f := range res.Failed {
		if !strings.Contains(f, "rule del") {
			t.Errorf("unexpected command reported as failed: %q", f)
		}
	}
}

// Removing something already gone is the NORMAL outcome of an idempotent teardown — nft and
// iproute2 both exit non-zero for it — and must not be reported as a failure, or every second
// teardown would look broken.
func TestTeardownVerified_AlreadyAbsentIsClean(t *testing.T) {
	for _, msg := range []string{
		"No such file or directory",
		"Error: No such file or directory",
		"RTNETLINK answers: No such process",
		"Cannot find device \"awg0\"",
		"does not exist",
	} {
		pl := teardownPlan()
		r := &failRunner{fail: []string{""}, err: errors.New(msg)} // "" matches every command
		res := pl.TeardownVerified(r, Options{})
		if !res.Clean() {
			t.Errorf("%q means the object was already gone — teardown is clean, got %v", msg, res.Failed)
		}
	}
}

func TestTeardownVerified_FullSuccessIsClean(t *testing.T) {
	pl := teardownPlan()
	r := &failRunner{}
	res := pl.TeardownVerified(r, Options{})
	if !res.Clean() || res.Err() != nil {
		t.Fatalf("every command succeeded, expected clean: %v", res.Failed)
	}
	if res.Commands != len(r.ran) {
		t.Errorf("Commands=%d but %d commands ran", res.Commands, len(r.ran))
	}
}

// The old signature is kept for callers that cannot act on the outcome; it must still run the
// teardown, so replacing it did not silently stop tearing anything down.
func TestTeardown_StillRunsEveryCommand(t *testing.T) {
	pl := teardownPlan()
	r := &failRunner{}
	if err := pl.Teardown(r, Options{}); err != nil {
		t.Fatalf("the compatibility form reports nil by contract, got %v", err)
	}
	if len(r.ran) == 0 {
		t.Fatal("the compatibility form issued no commands")
	}
	verified := &failRunner{}
	teardownPlan().TeardownVerified(verified, Options{})
	if len(r.ran) != len(verified.ran) {
		t.Errorf("the two forms issued different commands: %d vs %d", len(r.ran), len(verified.ran))
	}
}
