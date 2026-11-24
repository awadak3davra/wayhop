package server

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// Before an Apply's program, a kill-switched domain set the program is about to create
// reads as empty, so the pre-program sync releases the hold instead of keeping it up for the Apply or
// leaving a false "lifted". A set the replaced plane had, missing, is still a failed read (a boot).
func TestKillSwitchPreSyncReadsANewSetAsEmpty(t *testing.T) {
	member := netip.MustParsePrefix("198.51.100.7/32")
	read := func(_ context.Context, set string) ([]netip.Prefix, error) {
		if set == "wr_live_4" {
			return []netip.Prefix{member}, nil
		}
		return nil, errors.New("the set with the given name does not exist")
	}
	list := func() (string, error) { return "wr_bypass_4\nwr_live_4\n", nil }
	r := ksNewSetsEmpty(read, list, []string{"wr_old_4"})
	ctx := context.Background()
	if got, err := r(ctx, "wr_new_4"); err != nil || len(got) != 0 {
		t.Fatalf("new set: %v %v", got, err)
	}
	if _, err := r(ctx, "wr_old_4"); err == nil {
		t.Fatal("a set of the replaced plane, missing, read as empty")
	}
	if got, err := r(ctx, "wr_live_4"); err != nil || len(got) != 1 {
		t.Fatalf("live set: %v %v", got, err)
	}
	broken := ksNewSetsEmpty(read, func() (string, error) { return "", errors.New("ipset: no such tool") }, nil)
	if _, err := broken(ctx, "wr_new_4"); err == nil {
		t.Fatal("unreadable set list: a missing set read as empty")
	}
}
