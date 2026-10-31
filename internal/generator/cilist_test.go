package generator

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ciCoreCheckExcluded names the tests that run a real sing-box (WR_SINGBOX) but are deliberately left
// out of CI's singbox-check job, each with the reason. Every TUN inbound the generator emits carries
// auto_redirect, and `sing-box check` initializes it, which FATALs "auto-redirect: invalid argument"
// on a CI runner (no router nftables); these run where a core and nftables exist (WSL as root, a
// router).
var ciCoreCheckExcluded = map[string]string{
	"TestHybridSingBoxCheck":               "hybrid TUN: auto_redirect",
	"TestFetchedFeedsFollowTheHybridSplit": "hybrid TUN: auto_redirect",
	"TestFetchedFeedsReachTheCore":         "TUN: auto_redirect",
	"TestGenerateDNSFakeIPKeptInTun":       "TUN: auto_redirect",
}

// TestSingBoxGatedTestsRunInCI keeps CI's singbox-check allowlist in step with the tests that use a
// real core. The list is written by hand in .github/workflows/ci.yml and had drifted: twelve tests
// that check their config with WR_SINGBOX (every DNS check among them) never met a real sing-box in
// CI, so a schema the core refuses could pass there. A test counts as gated when its body, or a
// helper it calls (transitively), names WR_SINGBOX.
func TestSingBoxGatedTestsRunInCI(t *testing.T) {
	ci, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	m := regexp.MustCompile(`go test -run '([^']+)' -count=1 \./internal/generator/`).FindAllSubmatch(ci, -1)
	if len(m) != 1 {
		t.Fatalf("want exactly one singbox-check `go test -run '...' -count=1 ./internal/generator/` line in ci.yml, found %d", len(m))
	}
	run, err := regexp.Compile(string(m[0][1]))
	if err != nil {
		t.Fatalf("ci.yml -run pattern: %v", err)
	}

	files, _ := filepath.Glob("*_test.go")
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Body != nil {
				funcs[fd.Name.Name] = fd
			}
		}
	}
	// gated[name]: the function reaches WR_SINGBOX. Seed with the direct uses, then propagate through
	// calls until nothing changes.
	calls := map[string][]string{}
	gated := map[string]bool{}
	for name, fd := range funcs {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				if s, err := strconv.Unquote(x.Value); err == nil && s == "WR_"+"SINGBOX" { // split: this test is no user
					gated[name] = true
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok {
					calls[name] = append(calls[name], id.Name)
				}
			}
			return true
		})
	}
	for changed := true; changed; {
		changed = false
		for name, callees := range calls {
			if gated[name] {
				continue
			}
			for _, c := range callees {
				if gated[c] {
					gated[name], changed = true, true
					break
				}
			}
		}
	}

	var missing, stale []string
	for name := range gated {
		if !strings.HasPrefix(name, "Test") {
			continue
		}
		if _, ex := ciCoreCheckExcluded[name]; ex {
			if run.MatchString(name) {
				stale = append(stale, name+" (excluded here but matched by ci.yml)")
			}
			continue
		}
		if !run.MatchString(name) {
			missing = append(missing, name)
		}
	}
	for name := range ciCoreCheckExcluded {
		if !gated[name] {
			stale = append(stale, name+" (no longer a real-core test)")
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("tests that run a real sing-box but are not in ci.yml's singbox-check -run list: %s - add them there, or to ciCoreCheckExcluded with the reason", strings.Join(missing, ", "))
	}
	if len(stale) > 0 {
		t.Errorf("stale ciCoreCheckExcluded entries: %s", strings.Join(stale, "; "))
	}
}
