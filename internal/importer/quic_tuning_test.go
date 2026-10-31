package importer

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// sing-box 1.14's QUIC fields on hysteria2 and tuic outbounds reach the params the generator emits; a
// packet size quic-go would not use as given comes in as the one it used (9000 runs at 1452), which
// saving accepts, and an outbound without them gets none.
func TestParseSingbox_QUICTuning(t *testing.T) {
	cfg := `{"outbounds":[
	{"type":"hysteria2","tag":"hy","server":"192.0.2.4","server_port":8443,"password":"pw","tls":{"enabled":true,"server_name":"hy.example.com"},"initial_packet_size":1232,"disable_path_mtu_discovery":true},
	{"type":"tuic","tag":"tu","server":"192.0.2.5","server_port":8443,"uuid":"2dd61d93-75d8-4da4-ac0e-6aece7eac365","password":"pw","tls":{"enabled":true,"server_name":"tuic.example.com"},"initial_packet_size":9000,"disable_path_mtu_discovery":true},
	{"type":"tuic","tag":"plain","server":"192.0.2.6","server_port":8443,"uuid":"2dd61d93-75d8-4da4-ac0e-6aece7eac365","password":"pw","tls":{"enabled":true,"server_name":"tuic2.example.com"}}]}`
	eps, errs := ParseSingbox(cfg)
	if len(eps) != 3 || len(errs) != 0 {
		t.Fatalf("eps %v errs %v", eps, errs)
	}
	hy, tu, plain := eps[0].Params, eps[1].Params, eps[2].Params
	if hy[model.ParamQUICInitialPacketSize] != 1232 || hy[model.ParamQUICDisablePMTUD] != true {
		t.Errorf("hysteria2 params = %v", hy)
	}
	if tu[model.ParamQUICInitialPacketSize] != 1452 || tu[model.ParamQUICDisablePMTUD] != true {
		t.Errorf("tuic with a 9000-byte size = %v, want the 1452 quic-go ran with", tu)
	}
	saved := model.Profile{Endpoints: append([]model.Endpoint(nil), eps...)}
	for i := range saved.Endpoints {
		saved.Endpoints[i].ID = saved.Endpoints[i].Name
	}
	if err := saved.Validate(); err != nil {
		t.Errorf("the imported connections must save: %v", err)
	}
	if _, ok := plain[model.ParamQUICInitialPacketSize]; ok {
		t.Errorf("untuned tuic gained a size: %v", plain)
	}
	if _, ok := plain[model.ParamQUICDisablePMTUD]; ok {
		t.Errorf("untuned tuic gained a switch: %v", plain)
	}
}

// mihomo's TUIC disable-mtu-discovery is the same switch; mihomo has no initial packet size, and its
// Hysteria2 udp-mtu sizes relayed datagrams, so it is not read as one.
func TestParseClash_QUICTuning(t *testing.T) {
	yaml := strings.Join([]string{
		"proxies:",
		"  - {name: t, type: tuic, server: 192.0.2.5, port: 8443, uuid: 2dd61d93-75d8-4da4-ac0e-6aece7eac365, password: pw, disable-mtu-discovery: true}",
		"  - {name: u, type: tuic, server: 192.0.2.6, port: 8443, uuid: 2dd61d93-75d8-4da4-ac0e-6aece7eac365, password: pw, disable-mtu-discovery: false}",
		"  - {name: h, type: hysteria2, server: 192.0.2.7, port: 8443, password: pw, udp-mtu: 1250}",
	}, "\n")
	eps, errs := ParseClash(yaml)
	if len(eps) != 3 || len(errs) != 0 {
		t.Fatalf("eps %v errs %v", eps, errs)
	}
	if eps[0].Params[model.ParamQUICDisablePMTUD] != true {
		t.Errorf("tuic with disable-mtu-discovery = %v", eps[0].Params)
	}
	for i := 1; i < len(eps); i++ {
		if e := &eps[i]; model.HasQUICTuning(e) {
			t.Errorf("%s gained QUIC tuning: %v", e.Name, e.Params)
		}
	}
}
