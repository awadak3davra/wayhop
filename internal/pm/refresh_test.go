package pm

import (
	"context"
	"reflect"
	"testing"
)

type refreshRecordRunner struct {
	out   string
	calls [][]string
}

func (r *refreshRecordRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	return r.out, nil
}

func TestRefreshArgvAndExecution(t *testing.T) {
	for _, tc := range []struct {
		kind Kind
		want []string
	}{
		{Apk, []string{"apk", "update"}},
		{Opkg, []string{"opkg", "update"}},
		{None, nil},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			r := &refreshRecordRunner{out: "catalog refreshed"}
			m := Manager{Kind: tc.kind, Runner: r}
			if got := m.RefreshArgv(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("RefreshArgv() = %#v, want %#v", got, tc.want)
			}
			out, err := m.Refresh(context.Background())
			if tc.kind == None {
				if err == nil || len(r.calls) != 0 {
					t.Fatalf("Refresh(None) = %q, %v, calls=%#v", out, err, r.calls)
				}
				return
			}
			if err != nil || out != "catalog refreshed" {
				t.Fatalf("Refresh() = %q, %v", out, err)
			}
			if len(r.calls) != 1 || !reflect.DeepEqual(r.calls[0], tc.want) {
				t.Fatalf("calls = %#v, want %#v", r.calls, tc.want)
			}
		})
	}
}
