package importer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// The sample-driven check (TestSourceFields_CoverWhatEachParserWrites) sees only what its inputs
// happen to set: a helper no sample reached (clashHysteria2Extras writing obfs_min_packet_size) let a
// key the Clash parser writes stay off the Clash list, and a re-import kept a stale value the provider
// had dropped. This one reads the parsers' source instead: from each format's entry functions it walks
// every function of the package they call, collects every params key, TLS field and top-level knob
// those functions write, and requires the format's list to name each one. A write it cannot resolve to
// a key fails it, so a new way of writing params cannot slip past unseen.
//
// The other direction holds too: every key and field a list names must be one its parser's code can
// write, or a re-import would clear a value the user set that the format could never have carried
// (the overshoot that wiped ssh host keys). Surge is the one format checked in that direction only:
// its lines become Clash proxies, so the whole Clash converter is reachable from it though a Surge
// line feeds only part of it; what it can write is left to the samples.
var formatEntries = map[string][]string{
	linkFormat("vless"):           {"parseVLESS"},
	linkFormat("vmess"):           {"parseVMess"},
	linkFormat("trojan"):          {"parseTrojan"},
	linkFormat("anytls"):          {"parseAnyTLS"},
	linkFormat("ss"):              {"parseShadowsocks"},
	linkFormat("hysteria2"):       {"parseHysteria2"},
	linkFormat("hysteria2+realm"): {"parseHysteria2Realm"},
	linkFormat("tuic"):            {"parseTUIC"},
	linkFormat("wireguard"):       {"parseWireGuardURL"},
	linkFormat("ssh"):             {"parseSSHURL"},
	FormatSurge:                   {"parseSurgeSingle", "ParseSurge"},
	FormatClash:                   {"parseClash", "parseClashSingle"},
	FormatSingbox:                 {"parseSingbox"},
	FormatConf:                    {"parseConf"},
	FormatOpenVPN:                 {"parseOpenVPN"},
}

type scanWrites struct {
	params, tls, knobs map[string]bool
	unresolved         []string
	calls              map[string]bool
}

func TestSourceFields_CoverEveryHelperTheParserCalls(t *testing.T) {
	fset := token.NewFileSet()
	files := scanParse(t, fset, ".")
	consts := scanModelConsts(t, fset)
	pkgVars := map[string]ast.Expr{}
	funcs := map[string]*ast.FuncDecl{}
	methods := map[string]bool{}
	for _, f := range files {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				funcs[d.Name.Name] = d // methods by name too: over-reaching is safe here
				if d.Recv != nil {
					methods[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					if vs, ok := sp.(*ast.ValueSpec); ok {
						for i, n := range vs.Names {
							if i < len(vs.Values) {
								pkgVars[n.Name] = vs.Values[i]
							}
						}
					}
				}
			}
		}
	}
	tlsJSON := jsonNames(reflect.TypeOf(model.TLS{}))
	writes := map[string]scanWrites{}
	for name, fd := range funcs {
		writes[name] = scanFunc(fset, fd, consts, pkgVars, funcs, methods, tlsJSON)
	}
	formats := make([]string, 0, len(formatEntries))
	for f := range formatEntries {
		formats = append(formats, f)
	}
	sort.Strings(formats)
	for _, format := range formats {
		spec, ok := fieldsOf(format)
		if !ok {
			t.Errorf("%s has no list", format)
			continue
		}
		seen := map[string]bool{}
		reach := scanWrites{params: map[string]bool{}, tls: map[string]bool{}, knobs: map[string]bool{}}
		queue := append([]string{}, formatEntries[format]...)
		for len(queue) > 0 {
			n := queue[0]
			queue = queue[1:]
			if seen[n] || funcs[n] == nil {
				continue
			}
			seen[n] = true
			w := writes[n]
			for k := range w.params {
				reach.params[k] = true
			}
			for k := range w.tls {
				reach.tls[k] = true
			}
			for k := range w.knobs {
				reach.knobs[k] = true
			}
			if format == FormatSurge {
				for c := range w.calls {
					queue = append(queue, c)
				}
				continue
			}
			for _, u := range w.unresolved {
				t.Errorf("%s: %s writes a params key this scan cannot resolve (%s): teach the scan, or write the key plainly", format, n, u)
			}
			for k := range w.params {
				if !containsPin(spec.params, k) {
					t.Errorf("%s: %s writes param %q, which the %s list does not name", format, n, k, format)
				}
			}
			for k := range w.tls {
				if !containsPin(spec.tls, k) && !(spec.pins && containsPin(pinFields, k)) {
					t.Errorf("%s: %s sets TLS field %q, which the %s list does not name", format, n, k, format)
				}
			}
			for k := range w.knobs {
				if (k == "MTU" && !spec.mtu) || (k == "PersistentKeepalive" && !spec.keepalive) ||
					(k == "Multiplex" && !spec.multiplex) || (k == "Transport" && !spec.transport) {
					t.Errorf("%s: %s sets %s, which the %s list does not name", format, n, k, format)
				}
			}
			for c := range w.calls {
				queue = append(queue, c)
			}
		}
		for _, k := range spec.params {
			// The param an older WayHop kept a Hysteria2 pinSHA256 in: the link now brings that pin in
			// the TLS block, so its import clears the old copy instead of writing it.
			if !reach.params[k] && k != model.ParamLegacyPin {
				t.Errorf("%s: the list names param %q, which its parser never writes: a re-import would clear it", format, k)
			}
		}
		for _, k := range spec.tls {
			if !reach.tls[k] && k != "enabled" && k != "type" {
				t.Errorf("%s: the list names TLS field %q, which its parser never sets", format, k)
			}
		}
		for k, on := range map[string]bool{"MTU": spec.mtu, "PersistentKeepalive": spec.keepalive, "Multiplex": spec.multiplex, "Transport": spec.transport} {
			if on && !reach.knobs[k] {
				t.Errorf("%s: the list names %s, which its parser never sets", format, k)
			}
		}
	}
}

func scanParse(t *testing.T, fset *token.FileSet, dir string) []*ast.File {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	var out []*ast.File
	for _, m := range matches {
		if strings.HasSuffix(m, "_test.go") {
			continue
		}
		src, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, m, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

// scanModelConsts maps the model package's string constants (model.ParamQUICDisablePMTUD) to values.
func scanModelConsts(t *testing.T, fset *token.FileSet) map[string]string {
	out := map[string]string{}
	for _, f := range scanParse(t, fset, filepath.Join("..", "model")) {
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			for _, sp := range g.Specs {
				vs := sp.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						if s, ok := stringLit(vs.Values[i]); ok {
							out[n.Name] = s
						}
					}
				}
			}
		}
	}
	return out
}

func jsonNames(t reflect.Type) map[string]string {
	out := map[string]string{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		out[f.Name] = strings.Split(f.Tag.Get("json"), ",")[0]
	}
	return out
}

func stringLit(e ast.Expr) (string, bool) {
	if b, ok := e.(*ast.BasicLit); ok && b.Kind == token.STRING {
		s, err := strconv.Unquote(b.Value)
		return s, err == nil
	}
	return "", false
}

// scanFunc collects what one function writes and which package functions it calls.
func scanFunc(fset *token.FileSet, fd *ast.FuncDecl, consts map[string]string, pkgVars map[string]ast.Expr,
	funcs map[string]*ast.FuncDecl, methods map[string]bool, tlsJSON map[string]string) scanWrites {
	w := scanWrites{params: map[string]bool{}, tls: map[string]bool{}, knobs: map[string]bool{}, calls: map[string]bool{}}
	if fd.Body == nil {
		return w
	}
	// Names that hold the endpoint's params map: bound from x.Params, handed over as Params: x, or a
	// map[string]any parameter (a helper handed e.Params, as clashHysteria2Extras is).
	paramsVars := map[string]bool{}
	for _, f := range fd.Type.Params.List {
		if m, ok := f.Type.(*ast.MapType); ok {
			if k, ok := m.Key.(*ast.Ident); ok && k.Name == "string" {
				if v, ok := m.Value.(*ast.Ident); ok && v.Name == "any" {
					for _, n := range f.Names {
						paramsVars[n.Name] = true
					}
				}
			}
		}
	}
	var ranges []*ast.RangeStmt
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for i, r := range n.Rhs {
				if s, ok := r.(*ast.SelectorExpr); ok && s.Sel.Name == "Params" && i < len(n.Lhs) {
					if id, ok := n.Lhs[i].(*ast.Ident); ok {
						paramsVars[id.Name] = true
					}
				}
			}
		case *ast.KeyValueExpr:
			if k, ok := n.Key.(*ast.Ident); ok && k.Name == "Params" {
				if id, ok := n.Value.(*ast.Ident); ok {
					paramsVars[id.Name] = true
				}
			}
		case *ast.RangeStmt:
			ranges = append(ranges, n)
		}
		return true
	})
	isParams := func(x ast.Expr) bool {
		switch x := x.(type) {
		case *ast.SelectorExpr:
			return x.Sel.Name == "Params"
		case *ast.Ident:
			return paramsVars[x.Name]
		}
		return false
	}
	// rangeOf finds the innermost range statement around pos binding name.
	rangeOf := func(name string, pos token.Pos) (*ast.RangeStmt, bool) {
		var best *ast.RangeStmt
		for _, r := range ranges {
			if pos < r.Body.Pos() || pos > r.Body.End() {
				continue
			}
			if k, ok := r.Key.(*ast.Ident); ok && k.Name == name {
				if best == nil || r.Pos() > best.Pos() {
					best = r
				}
			}
			if v, ok := r.Value.(*ast.Ident); ok && v.Name == name {
				if best == nil || r.Pos() > best.Pos() {
					best = r
				}
			}
		}
		return best, best != nil
	}
	elems := func(x ast.Expr) *ast.CompositeLit {
		if id, ok := x.(*ast.Ident); ok {
			x = pkgVars[id.Name]
		}
		c, _ := x.(*ast.CompositeLit)
		return c
	}
	var resolve func(k ast.Expr, pos token.Pos) ([]string, bool)
	resolve = func(k ast.Expr, pos token.Pos) ([]string, bool) {
		if s, ok := stringLit(k); ok {
			return []string{s}, true
		}
		switch k := k.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := k.X.(*ast.Ident); ok && pkg.Name == "model" {
				v, ok := consts[k.Sel.Name]
				return []string{v}, ok
			}
			// k.param, where k ranges over a slice of struct literals: the named field of each.
			if id, ok := k.X.(*ast.Ident); ok {
				if r, ok := rangeOf(id.Name, pos); ok {
					c := elems(r.X)
					if c == nil {
						return nil, false
					}
					st, _ := c.Type.(*ast.ArrayType)
					var fields []string
					if st != nil {
						if s, ok := st.Elt.(*ast.StructType); ok {
							for _, f := range s.Fields.List {
								for _, n := range f.Names {
									fields = append(fields, n.Name)
								}
							}
						}
					}
					var out []string
					for _, el := range c.Elts {
						cl, ok := el.(*ast.CompositeLit)
						if !ok {
							return nil, false
						}
						for i, v := range cl.Elts {
							name := ""
							if kv, ok := v.(*ast.KeyValueExpr); ok {
								name = kv.Key.(*ast.Ident).Name
								v = kv.Value
							} else if i < len(fields) {
								name = fields[i]
							}
							if name == k.Sel.Name {
								s, ok := stringLit(v)
								if !ok {
									return nil, false
								}
								out = append(out, s)
							}
						}
					}
					return out, len(out) > 0
				}
			}
		case *ast.Ident:
			r, ok := rangeOf(k.Name, pos)
			if !ok {
				return nil, false
			}
			c := elems(r.X)
			if c == nil {
				return nil, false
			}
			var out []string
			for _, el := range c.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					// A map literal: its keys when k is the key, its values when k is the value.
					if key, ok := r.Key.(*ast.Ident); ok && key.Name == k.Name {
						el = kv.Key
					} else {
						el = kv.Value
					}
				}
				s, ok := stringLit(el)
				if !ok {
					return nil, false
				}
				out = append(out, s)
			}
			return out, true
		case *ast.IndexExpr:
			// table[x], a package map literal: any of its values.
			c := elems(k.X)
			if c == nil {
				return nil, false
			}
			var out []string
			for _, el := range c.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					return nil, false
				}
				s, ok := stringLit(kv.Value)
				if !ok {
					return nil, false
				}
				out = append(out, s)
			}
			return out, true
		case *ast.BinaryExpr:
			if k.Op == token.ADD {
				left, ok1 := resolve(k.X, pos)
				right, ok2 := resolve(k.Y, pos)
				if !ok1 || !ok2 {
					return nil, false
				}
				var out []string
				for _, l := range left {
					for _, r := range right {
						out = append(out, l+r)
					}
				}
				return out, true
			}
		}
		return nil, false
	}
	topNames := map[string]bool{"MTU": true, "PersistentKeepalive": true, "Multiplex": true, "Transport": true}
	tlsUnique := map[string]bool{}
	for g := range tlsJSON {
		if g != "Enabled" && g != "Type" {
			tlsUnique[g] = true
		}
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			switch f := n.Fun.(type) {
			case *ast.Ident:
				if funcs[f.Name] != nil {
					w.calls[f.Name] = true
				}
			case *ast.SelectorExpr:
				// x.m() is this package's method m; pkg.F() (url.Parse) is another package's.
				if methods[f.Sel.Name] {
					w.calls[f.Sel.Name] = true
				}
			}
			// A function passed as a value (tagged(...)(parse(...)) aside) is a call too.
			for _, a := range n.Args {
				if id, ok := a.(*ast.Ident); ok && funcs[id.Name] != nil {
					w.calls[id.Name] = true
				}
			}
		case *ast.AssignStmt:
			for _, l := range n.Lhs {
				switch l := l.(type) {
				case *ast.IndexExpr:
					if !isParams(l.X) {
						continue
					}
					keys, ok := resolve(l.Index, l.Pos())
					if !ok {
						w.unresolved = append(w.unresolved, fset.Position(l.Pos()).String())
					}
					for _, k := range keys {
						w.params[k] = true
					}
				case *ast.SelectorExpr:
					if topNames[l.Sel.Name] {
						w.knobs[l.Sel.Name] = true
					}
					if tlsUnique[l.Sel.Name] {
						w.tls[tlsJSON[l.Sel.Name]] = true
					}
				}
			}
			// x := map[string]any{...} for a params variable.
			for i, r := range n.Rhs {
				if i < len(n.Lhs) && isParams(n.Lhs[i]) {
					if c, ok := r.(*ast.CompositeLit); ok {
						for _, el := range c.Elts {
							if kv, ok := el.(*ast.KeyValueExpr); ok {
								if s, ok := stringLit(kv.Key); ok {
									w.params[s] = true
								}
							}
						}
					}
				}
			}
		case *ast.CompositeLit:
			sel, _ := n.Type.(*ast.SelectorExpr)
			if sel == nil {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "model" {
				return true
			}
			for _, el := range n.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				field := kv.Key.(*ast.Ident).Name
				switch sel.Sel.Name {
				case "TLS":
					w.tls[tlsJSON[field]] = true
				case "Endpoint":
					if topNames[field] {
						w.knobs[field] = true
					}
					if field == "Params" {
						if c, ok := kv.Value.(*ast.CompositeLit); ok {
							for _, p := range c.Elts {
								if pkv, ok := p.(*ast.KeyValueExpr); ok {
									if s, ok := stringLit(pkv.Key); ok {
										w.params[s] = true
									}
								}
							}
						}
					}
				}
			}
		}
		return true
	})
	return w
}
