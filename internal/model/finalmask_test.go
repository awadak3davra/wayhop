package model

import (
	"reflect"
	"strings"
	"testing"
)

// QA-136: what each of Xray's finalmask types asks of a client (Xray-core v26.10.29, the masks'
// config.go): nothing (filter), only what it sends (fragment, noise, udphop), or a transform the
// server undoes (everything else), by list, with the type matched as Xray matches it.
func TestParseFinalMask_Classifies(t *testing.T) {
	for _, c := range []struct {
		name, raw    string
		sender, peer []string
	}{
		{"empty", `{}`, nil, nil},
		{"quicParams only", `{"quicParams":{"congestion":"bbr"}}`, nil, nil},
		{"filter, both lists", `{"tcp":[{"type":"filter","settings":{"allowedSourceIPs":["192.0.2.0/24"]}}],"udp":[{"type":"filter"}]}`, nil, nil},
		{"fragment", `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200","delay":"10-20"}}]}`, []string{"fragment"}, nil},
		{"noise", `{"udp":[{"type":"noise","settings":{"noise":[{"type":"rand","packet":"10-20","delay":"10-16"}]}}]}`, []string{"noise"}, nil},
		{"udphop", `{"udp":[{"type":"udphop","settings":{"remotePorts":"20000-30000","interval":"5-10"}}]}`, []string{"udphop"}, nil},
		{"case as Xray matches it", `{"tcp":[{"type":"Fragment"}],"udp":[{"type":"NOISE"}]}`, []string{"fragment", "noise"}, nil},
		{"named once", `{"tcp":[{"type":"fragment"},{"type":"fragment"}]}`, []string{"fragment"}, nil},
		{"header-custom tcp", `{"tcp":[{"type":"header-custom","settings":{"clients":[],"servers":[]}}]}`, nil, []string{"header-custom"}},
		{"header-custom udp", `{"udp":[{"type":"header-custom","settings":{"client":[],"server":[]}}]}`, nil, []string{"header-custom"}},
		{"mkcp-legacy", `{"udp":[{"type":"mkcp-legacy","settings":{"header":"wechat"}}]}`, nil, []string{"mkcp-legacy"}},
		{"salamander", `{"udp":[{"type":"salamander","settings":{"password":"invented-obfs"}}]}`, nil, []string{"salamander"}},
		{"salamander as gecko", `{"udp":[{"type":"salamander","settings":{"password":"invented-obfs","packetSize":"100-1200"}}]}`, nil, []string{"salamander"}},
		{"sudoku both lists", `{"tcp":[{"type":"sudoku"}],"udp":[{"type":"sudoku"}]}`, nil, []string{"sudoku"}},
		{"xmc", `{"tcp":[{"type":"xmc"}]}`, nil, []string{"xmc"}},
		{"xdns", `{"udp":[{"type":"xdns"}]}`, nil, []string{"xdns"}},
		{"xicmp", `{"udp":[{"type":"xicmp"}]}`, nil, []string{"xicmp"}},
		{"realm", `{"udp":[{"type":"realm"}]}`, nil, []string{"realm"}},
		{"mixed", `{"tcp":[{"type":"fragment"}],"udp":[{"type":"noise"},{"type":"salamander"}]}`, []string{"fragment", "noise"}, []string{"salamander"}},
	} {
		got, err := ParseFinalMask(c.raw)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(got.Sender, c.sender) || !reflect.DeepEqual(got.Peer, c.peer) {
			t.Errorf("%s: sender %v peer %v, want %v %v", c.name, got.Sender, got.Peer, c.sender, c.peer)
		}
	}
}

// What Xray's loader takes is taken: keys it does not know (encoding/json ignores them, as Xray does),
// settings left out or null, and each value form of its Int32Range and PortList.
func TestParseFinalMask_TakesWhatXrayLoads(t *testing.T) {
	for _, raw := range []string{
		`{"tcp":[],"udp":null,"invented":{"x":1}}`,
		`{"tcp":[{"type":"fragment","settings":null}]}`,
		`{"tcp":[{"type":"fragment","settings":{"packets":"1-3","length":100,"delay":"-5-10","lengths":["1-2",3],"delays":null,"maxSplit":"","invented":true}}]}`,
		`{"tcp":[{"type":"fragment","settings":{"length":"-10--5"}}]}`,
		`{"udp":[{"type":"noise","settings":{"reset":"5-10","noise":[{"rand":"10-20","randRange":"0-255","type":"base64","packet":"AAAA","delay":5}]}}]}`,
		`{"udp":[{"type":"noise","settings":{"script":"return 1"}}]}`,
		`{"udp":[{"type":"udphop","settings":{"remotePorts":"443, 20000-30000,env:INVENTED_PORTS","interval":"5-10","remoteIPs":["192.0.2.1"]}}]}`,
		`{"udp":[{"type":"udphop","settings":{"remotePorts":8443}}]}`,
		`{"quicParams":{"congestion":"brutal","brutalUp":"100 mbps","maxIdleTimeout":30,"disableGSO":true}}`,
	} {
		if _, err := ParseFinalMask(raw); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

// What Xray itself refuses (a type unknown to that list, a shape that does not decode) is refused,
// and the reason never carries a mask's settings, which hold its password.
func TestParseFinalMask_Refuses(t *testing.T) {
	for _, c := range []struct{ name, raw, want string }{
		{"truncated", `{"tcp":[{"type":"fragment"`, "not valid JSON"},
		{"not an object", `"fragment"`, "not a JSON object"},
		{"null", `null`, "not a JSON object"},
		{"a list", `[{"type":"fragment"}]`, "not a JSON object"},
		{"tcp not a list", `{"tcp":{"type":"fragment"}}`, "not Xray's finalmask"},
		{"type not a string", `{"udp":[{"type":5,"settings":{"password":"invented-secret"}}]}`, "not Xray's finalmask"},
		{"fragment is a tcp mask", `{"udp":[{"type":"fragment"}]}`, `unknown udp mask "fragment"`},
		{"noise is a udp mask", `{"tcp":[{"type":"noise"}]}`, `unknown tcp mask "noise"`},
		{"no type", `{"tcp":[{}]}`, `unknown tcp mask ""`},
		{"unknown", `{"udp":[{"type":"invented","settings":{"password":"invented-secret"}}]}`, `unknown udp mask "invented"`},
		{"long type cut", `{"udp":[{"type":"` + strings.Repeat("x", 40) + `"}]}`, `"` + strings.Repeat("x", 24) + `..."`},
		// What Xray's loader cannot decode (encoding/json into QuicParamsConfig and the masks' settings).
		{"quicParams a string", `{"quicParams":"x"}`, `"quicParams" holds a value of the wrong type`},
		{"quicParams field type", `{"quicParams":{"congestion":5}}`, `"quicParams" holds a value of the wrong type`},
		{"quicParams brutalUp is a string", `{"quicParams":{"brutalUp":100}}`, `"quicParams"`},
		{"fragment settings a string", `{"tcp":[{"type":"fragment","settings":"invented-secret"}]}`, "the fragment mask's settings"},
		{"fragment length not a range", `{"tcp":[{"type":"fragment","settings":{"length":"1-2-x"}}]}`, "the fragment mask's settings"},
		{"fragment length an object", `{"tcp":[{"type":"fragment","settings":{"length":{"a":1}}}]}`, "the fragment mask's settings"},
		{"fragment lengths not a list", `{"tcp":[{"type":"fragment","settings":{"lengths":"1-2"}}]}`, "the fragment mask's settings"},
		{"fragment length beyond 32 bits", `{"tcp":[{"type":"fragment","settings":{"length":4294967296}}]}`, "the fragment mask's settings"},
		{"noise list a string", `{"udp":[{"type":"noise","settings":{"noise":"invented-secret"}}]}`, "the noise mask's settings"},
		{"noise script a number", `{"udp":[{"type":"noise","settings":{"script":5}}]}`, "the noise mask's settings"},
		{"udphop port too high", `{"udp":[{"type":"udphop","settings":{"remotePorts":"20000-70000"}}]}`, "the udphop mask's settings"},
		{"udphop port not a number", `{"udp":[{"type":"udphop","settings":{"remotePorts":"443,x"}}]}`, "the udphop mask's settings"},
		{"filter IPs a string", `{"tcp":[{"type":"filter","settings":{"allowedSourceIPs":"192.0.2.0/24"}}]}`, "the filter mask's settings"},
	} {
		_, err := ParseFinalMask(c.raw)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
			continue
		}
		if strings.Contains(err.Error(), "invented-secret") {
			t.Errorf("%s: the reason carries a setting: %v", c.name, err)
		}
	}
}
