package watchdog

import "testing"

func TestParseStatTicks(t *testing.T) {
	cases := map[string]struct {
		in   string
		want uint64
		bad  bool
	}{
		"plain":                  {in: "1200 (sing-box) S 1165 1 1 0 -1 4194560 10 0 0 0 700 50 0 0 20 0 9 0 5149 1 1", want: 750},
		"parens in the name":     {in: "1200 (a) b) c) S 1165 1 1 0 -1 4194560 10 0 0 0 700 50 0 0 20 0 9 0 5149 1 1", want: 750},
		"no command name":        {in: "1200 sing-box S", bad: true},
		"cut short":              {in: "1200 (sing-box) S 1165", bad: true},
		"a field is not a count": {in: "1200 (sing-box) S 1165 1 1 0 -1 4194560 10 0 0 0 x 50 0", bad: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseStatTicks([]byte(c.in))
			if (err != nil) != c.bad || got != c.want {
				t.Fatalf("got %d, %v; want %d, bad=%v", got, err, c.want, c.bad)
			}
		})
	}
}

const netlinkTableFixture = `sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode
ffff000000000001 0   1200       00000440 213248   0        0     2        65298    1001
ffff000000000002 0   1201       00000001 0        0        0     2        0        1002
ffff000000000003 0   1202       00000000 33024    0        0     2        0        1003
ffff000000000004 15  1203       00000001 4096     0        0     2        7        1004
ffff000000000005 0   999        00000440 8192     0        0     2        5        2001
`

func TestParseNetlinkQueues(t *testing.T) {
	got, err := parseNetlinkQueues([]byte(netlinkTableFixture),
		map[uint64]bool{1001: true, 1002: true, 1003: true, 1004: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %+v, want only the rtnetlink subscriptions of this process", got)
	}
	if q := got[1001]; q.rmem != 213248 || q.drops != 65298 {
		t.Fatalf("1001 = %+v", q)
	}
	if q, ok := got[1002]; !ok || q.rmem != 0 || q.drops != 0 {
		t.Fatalf("1002 = %+v, %v", q, ok)
	}
}

func TestParseNetlinkQueues_RefusesATableOfAnotherShape(t *testing.T) {
	for _, table := range []string{"", "sk Eth Pid Groups Rmem Wmem Dump Locks Inode\n"} {
		if _, err := parseNetlinkQueues([]byte(table), map[uint64]bool{1: true}); err == nil {
			t.Fatalf("no error for %q", table)
		}
	}
}
