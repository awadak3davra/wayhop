package awg

import (
	"encoding/binary"
	"errors"
	"testing"
)

// The thresholds are upstream's own numbers (WG_GENL_VERSION and WGDEVICE_A_MAX, counted from
// src/uapi/wireguard.h at each tag), so a change here is a change in what upstream shipped.
func TestClassify(t *testing.T) {
	cases := []struct {
		version, maxAttr uint32
		want             Generation
		why              string
	}{
		{0, 0, GenNone, "family not registered"},
		{1, 20, Gen1, "original AmneziaWG 1.0"},
		{2, 25, Gen2, "upstream v1.0.2026xxxx tags are generation 2 despite the name"},
		{3, 32, Gen30, "v3.0.20260805: version 3 but no RandomTrailers/DisableCookies"},
		{3, 33, Gen30, "version 3 short of DisableCookies is still not 3.1"},
		{3, 34, Gen31, "v3.1.20260906"},
		{4, 40, Gen31, "a later generation appends attributes, so it still accepts 3.1"},
	}
	for _, c := range cases {
		if got := Classify(c.version, c.maxAttr); got != c.want {
			t.Errorf("Classify(%d, %d) = %v, want %v (%s)", c.version, c.maxAttr, got, c.want, c.why)
		}
	}
}

// Decide is where the 3.0-versus-3.1 trap and the real routers land. The AX3000T runs a generation-2
// kmod with /dev/net/tun; every Keenetic has no generation-3 module at all.
func TestDecide(t *testing.T) {
	cases := []struct {
		name   string
		kernel Generation
		tun    bool
		need   Generation
		want   Path
	}{
		{"3.1 module, 3.1 config", Gen31, true, Gen31, PathKernel},
		{"3.1 module serves an older config", Gen31, false, Gen2, PathKernel},
		{"AX3000T: gen-2 kmod, 3.1 config", Gen2, true, Gen31, PathUserspace},
		{"3.0 module is not enough for 3.1", Gen30, true, Gen31, PathUserspace},
		{"Keenetic: no module, TUN present", GenNone, true, Gen31, PathUserspace},
		{"nothing at all", GenNone, false, Gen31, PathUnavailable},
		{"old module, no TUN", Gen2, false, Gen31, PathUnavailable},
	}
	for _, c := range cases {
		d := Decide(c.kernel, c.tun, c.need)
		if d.Path != c.want {
			t.Errorf("%s: path %v, want %v (%s)", c.name, d.Path, c.want, d.Reason)
		}
		if d.Reason == "" {
			t.Errorf("%s: a decision must say why", c.name)
		}
	}
}

// --- netlink fixtures, built to the kernel's wire format -----------------------------------------

func u32(bo binary.ByteOrder, v uint32) []byte {
	b := make([]byte, 4)
	bo.PutUint32(b, v)
	return b
}

// errCode is a negative errno as the kernel writes it into nlmsgerr: the int32's bits in a u32 field.
func errCode(code int32) uint32 { return uint32(code) }

func nla(bo binary.ByteOrder, typ uint16, val []byte) []byte {
	l := nlaHdrLen + len(val)
	b := make([]byte, align4(l))
	bo.PutUint16(b[0:], uint16(l))
	bo.PutUint16(b[2:], typ)
	copy(b[nlaHdrLen:], val)
	return b
}

func nlmsg(bo binary.ByteOrder, typ uint16, payload []byte) []byte {
	l := nlmsgHdrLen + len(payload)
	b := make([]byte, align4(l))
	bo.PutUint32(b[0:], uint32(l))
	bo.PutUint16(b[4:], typ)
	copy(b[nlmsgHdrLen:], payload)
	return b
}

// newFamily is a controller reply shaped like the real one for "amneziawg": id, name, version,
// hdrsize, maxattr, and a nested ops list the parser must step over without reading into it.
func newFamily(bo binary.ByteOrder, version, maxAttr uint32, withVersion bool) []byte {
	payload := []byte{ctrlCmdNewFamily, 2, 0, 0}
	payload = append(payload, nla(bo, 1, []byte{0x1f, 0x00})...) // CTRL_ATTR_FAMILY_ID
	payload = append(payload, nla(bo, ctrlAttrFamilyName, []byte("amneziawg\x00"))...)
	if withVersion {
		payload = append(payload, nla(bo, ctrlAttrVersion, u32(bo, version))...)
	}
	payload = append(payload, nla(bo, 4, u32(bo, 0))...) // CTRL_ATTR_HDRSIZE
	payload = append(payload, nla(bo, ctrlAttrMaxAttr, u32(bo, maxAttr))...)
	ops := append(nla(bo, 1, u32(bo, 0)), nla(bo, 2, u32(bo, 1))...)
	payload = append(payload, nla(bo, 6|0x8000, ops)...) // CTRL_ATTR_OPS, NLA_F_NESTED set
	return nlmsg(bo, genlIDCtrl, payload)
}

func TestParseGetFamilyReply_BothByteOrders(t *testing.T) {
	for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		v, m, err := parseGetFamilyReply(bo, newFamily(bo, 3, 34, true))
		if err != nil || v != 3 || m != 34 {
			t.Errorf("%v: got version %d maxattr %d err %v, want 3/34", bo, v, m, err)
		}
		if g := Classify(v, m); g != Gen31 {
			t.Errorf("%v: a v3/34 reply classified as %v", bo, g)
		}
	}
}

func TestParseGetFamilyReply_ModuleNotLoaded(t *testing.T) {
	for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		errMsg := nlmsg(bo, nlmsgError, append(u32(bo, errCode(-errnoENOENT)), make([]byte, 16)...))
		if _, _, err := parseGetFamilyReply(bo, errMsg); !errors.Is(err, errFamilyNotFound) {
			t.Errorf("%v: ENOENT read as %v, want errFamilyNotFound", bo, err)
		}
	}
}

// A reply without CTRL_ATTR_VERSION must not become "version 0" - that reads as "no module" and
// would push a working kernel module's endpoints to userspace.
func TestParseGetFamilyReply_MissingVersionIsAnError(t *testing.T) {
	bo := binary.LittleEndian
	if _, _, err := parseGetFamilyReply(bo, newFamily(bo, 0, 34, false)); err == nil {
		t.Fatal("a family reply without a version was accepted")
	}
}

func TestParseGetFamilyReply_OtherControllerErrors(t *testing.T) {
	bo := binary.LittleEndian
	errMsg := nlmsg(bo, nlmsgError, append(u32(bo, errCode(-13)), make([]byte, 16)...)) // EACCES
	if _, _, err := parseGetFamilyReply(bo, errMsg); err == nil || errors.Is(err, errFamilyNotFound) {
		t.Fatalf("EACCES must be a probe failure, not 'module not loaded': %v", err)
	}
}

func TestGetFamilyRequest_WireFormat(t *testing.T) {
	for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b := getFamilyRequest(bo, 7, "amneziawg")
		if int(bo.Uint32(b[0:])) != len(b) || len(b)%4 != 0 {
			t.Errorf("%v: length field %d, buffer %d", bo, bo.Uint32(b[0:]), len(b))
		}
		if bo.Uint16(b[4:]) != genlIDCtrl || bo.Uint16(b[6:])&nlmFRequest == 0 || bo.Uint32(b[8:]) != 7 {
			t.Errorf("%v: header wrong: % x", bo, b[:16])
		}
		if b[16] != ctrlCmdGetFamily {
			t.Errorf("%v: command %d, want GETFAMILY", bo, b[16])
		}
		attrLen := int(bo.Uint16(b[20:]))
		if bo.Uint16(b[22:]) != ctrlAttrFamilyName || string(b[24:20+attrLen]) != "amneziawg\x00" {
			t.Errorf("%v: family name attribute wrong: % x", bo, b[20:])
		}
	}
}

// The parser reads bytes from the kernel, but a malformed length must still be an error, never a
// panic or an out-of-range slice.
func FuzzParseGetFamilyReply(f *testing.F) {
	f.Add(newFamily(binary.LittleEndian, 3, 34, true))
	f.Add(newFamily(binary.BigEndian, 2, 25, true))
	f.Add([]byte{0xff, 0xff, 0, 0, 0x10, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = parseGetFamilyReply(binary.LittleEndian, b)
		_, _, _ = parseGetFamilyReply(binary.BigEndian, b)
	})
}
