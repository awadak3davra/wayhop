package generator

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"path/filepath"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// QA-136: sing-box has no finalmask, so a link's fm= changes nothing in the config: each connection
// renders byte for byte as the same link without it.
func TestFinalMaskNotRendered(t *testing.T) {
	const uuid = "00000000-0000-4000-8000-000000000136"
	fm := `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello"}}],"udp":[{"type":"noise"},{"type":"udphop"}]}`
	links := func(fm string) []string {
		q := ""
		if fm != "" {
			q = "&fm=" + url.QueryEscape(fm)
		}
		m := map[string]any{"v": "2", "ps": "vm", "add": "192.0.2.136", "port": "443", "id": uuid, "aid": "0",
			"net": "ws", "path": "/w", "tls": "tls", "sni": "example.com"}
		if fm != "" {
			m["fm"] = fm
		}
		vm, _ := json.Marshal(m)
		return []string{
			"vless://" + uuid + "@192.0.2.136:443?security=tls&sni=example.com&type=grpc&serviceName=g" + q + "#vless",
			"trojan://invented-pw@192.0.2.136:443?sni=example.com" + q + "#trojan",
			"anytls://invented-pw@192.0.2.136:443?sni=example.com" + q + "#anytls",
			"tuic://" + uuid + ":invented-pw@192.0.2.136:443?sni=example.com" + q + "#tuic",
			"hysteria2://invented-pw@192.0.2.136:443/?sni=example.com&obfs=salamander&obfs-password=invented-obfs" + q + "#hy2",
			"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:invented-pw")) + "@192.0.2.136:8388?udp-over-tcp=1" + q + "#ss",
			"vmess://" + base64.StdEncoding.EncodeToString(vm),
		}
	}
	render := func(fm string) []byte {
		prof := &model.Profile{}
		for _, l := range links(fm) {
			e, err := importer.Parse(l)
			if err != nil {
				t.Fatalf("%s: %v", l, err)
			}
			if _, ok := e.Params[model.ParamFinalMask]; ok != (fm != "") {
				t.Fatalf("%s: params %v", l, e.Params)
			}
			e.ID, e.Enabled = e.Name, true
			prof.Endpoints = append(prof.Endpoints, *e)
		}
		prof.Rules = []model.Rule{{ID: "def", Default: true, Outbound: prof.Endpoints[0].ID}}
		res, err := Generate(prof, Options{MixedPort: 7890, CoreVersion: "sing-box version 1.13.21",
			CacheFile: filepath.Join("cache", "cache.db")})
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(res.Config)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if with, without := render(fm), render(""); !bytes.Equal(with, without) {
		t.Errorf("fm changed the config:\n%s\n%s", with, without)
	}
}
