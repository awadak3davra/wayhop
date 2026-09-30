package pm

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// recordRunner answers by argv and remembers what it was asked.
type recordRunner struct {
	answers map[string]string
	err     error
	seen    []string
}

func (r *recordRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	r.seen = append(r.seen, key)
	if r.err != nil {
		return "", r.err
	}
	return r.answers[key], nil
}

// The exact bytes apk-tools 3.0.5 answers with on the test router, header and all.
const apkSizesJSON = `[
  {"name":"sing-box","version":"1.12.17-r1","installed-size":40537528,"file-size":14485215},
  {"name":"sing-box","version":"1.13.21-r1","installed-size":44466473,"file-size":15591117}
]`

func TestSizes_ReadsTheFeedsOwnFigures(t *testing.T) {
	r := &recordRunner{answers: map[string]string{
		"apk query --format json --fields name,version,installed-size,file-size --all-matches sing-box": apkSizesJSON,
	}}
	m := Manager{Kind: Apk, Runner: r}
	sizes, err := m.Sizes(context.Background(), "sing-box")
	if err != nil {
		t.Fatalf("sizes: %v", err)
	}
	if got, ok := SizeOf(sizes, "1.13.21-r1"); !ok || got != 44466473 {
		t.Fatalf("offered build = %d (%v), want 44466473", got, ok)
	}
	if got, ok := SizeOf(sizes, "1.12.17-r1"); !ok || got != 40537528 {
		t.Fatalf("installed build = %d (%v), want 40537528", got, ok)
	}
	if _, ok := SizeOf(sizes, "9.9.9-r9"); ok {
		t.Fatal("a version the feed does not carry must not report a size")
	}
}

// A sibling package that merely matched the query is not the package asked about. Answering with
// sing-box-doc's size would put a two-megabyte figure where a forty-megabyte decision is made.
func TestParseApkSizes_KeepsOnlyThePackageAskedAbout(t *testing.T) {
	out := `[{"name":"sing-box-doc","version":"1.13.21-r1","installed-size":2048,"file-size":900},
	         {"name":"sing-box","version":"1.13.21-r1","installed-size":44466473,"file-size":15591117}]`
	sizes, err := parseApkSizes(out, "sing-box")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(sizes) != 1 {
		t.Fatalf("sizes = %+v, want only sing-box", sizes)
	}
	if sizes[0].Installed != 44466473 {
		t.Fatalf("installed = %d", sizes[0].Installed)
	}
}

// One version can be answered for twice — the installed database and a repository both know it. The
// larger figure is the one a space guard has to use; picking the smaller is how a write starts and
// fails halfway.
func TestParseApkSizes_KeepsTheLargerOfTwoAnswersForOneVersion(t *testing.T) {
	out := `[{"name":"sing-box","version":"1.13.21-r1","installed-size":44466473,"file-size":15591117},
	         {"name":"sing-box","version":"1.13.21-r1","installed-size":40000000,"file-size":15591117}]`
	sizes, err := parseApkSizes(out, "sing-box")
	if err != nil || len(sizes) != 1 || sizes[0].Installed != 44466473 {
		t.Fatalf("sizes = %+v, err = %v", sizes, err)
	}
}

// An apk too old for `query --fields` prints a usage error. That is "cannot answer", and the caller
// must be able to tell it apart from "the answer is zero" — it skips its guard on the first and
// would refuse a perfectly possible upgrade on the second.
func TestSizes_AnUnansweredQueryIsNotAZeroSize(t *testing.T) {
	if _, err := parseApkSizes("ERROR: invalid argument for option 'fields'", "sing-box"); !errors.Is(err, ErrNoSizes) {
		t.Fatalf("err = %v, want ErrNoSizes", err)
	}
	m := Manager{Kind: Opkg, Runner: &recordRunner{}}
	if _, err := m.Sizes(context.Background(), "sing-box"); !errors.Is(err, ErrNoSizes) {
		t.Fatalf("opkg err = %v, want ErrNoSizes", err)
	}
}
