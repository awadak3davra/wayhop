package awg

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Generic netlink, from include/uapi/linux/netlink.h and include/uapi/linux/genetlink.h. The request
// and the parser live here, free of any socket, so they are tested on every platform the project
// builds on - including in BOTH byte orders, because netlink is host-endian and mips routers are
// big-endian: a parser that assumed little-endian would read every length wrong on exactly those.
const (
	nlmsgHdrLen = 16
	genlHdrLen  = 4
	nlaHdrLen   = 4

	nlmsgError  = 2
	nlmsgDone   = 3
	nlmFRequest = 1

	genlIDCtrl         = 0x10 // GENL_ID_CTRL, which equals NLMSG_MIN_TYPE
	ctrlCmdNewFamily   = 1
	ctrlCmdGetFamily   = 3
	ctrlAttrFamilyName = 2
	ctrlAttrVersion    = 3
	ctrlAttrMaxAttr    = 5

	nlaTypeMask = 0x3fff // strips NLA_F_NESTED and NLA_F_NET_BYTEORDER
	errnoENOENT = 2      // the controller's answer when no such family is registered
)

// errFamilyNotFound is the kernel saying the family is not registered - for "amneziawg", that the
// module is not loaded. It is an answer, not a failure of the probe.
var errFamilyNotFound = errors.New("generic netlink family is not registered")

func align4(n int) int { return (n + 3) &^ 3 }

// getFamilyRequest builds CTRL_CMD_GETFAMILY for `name` in byte order bo.
func getFamilyRequest(bo binary.ByteOrder, seq uint32, name string) []byte {
	val := append([]byte(name), 0) // NUL-terminated, as the controller's policy requires
	attrLen := nlaHdrLen + len(val)
	total := nlmsgHdrLen + genlHdrLen + align4(attrLen)
	b := make([]byte, total)
	bo.PutUint32(b[0:], uint32(total))
	bo.PutUint16(b[4:], genlIDCtrl)
	bo.PutUint16(b[6:], nlmFRequest)
	bo.PutUint32(b[8:], seq)
	// b[12:16] is the port id; 0 addresses the kernel.
	b[16] = ctrlCmdGetFamily
	b[17] = 1 // controller version
	bo.PutUint16(b[20:], uint16(attrLen))
	bo.PutUint16(b[22:], ctrlAttrFamilyName)
	copy(b[24:], val)
	return b
}

// parseGetFamilyReply reads the family's version and maxattr from the controller's reply, which may
// hold several netlink messages. errFamilyNotFound when the kernel answered ENOENT.
func parseGetFamilyReply(bo binary.ByteOrder, buf []byte) (version, maxAttr uint32, err error) {
	for len(buf) >= nlmsgHdrLen {
		l := int(bo.Uint32(buf[0:]))
		if l < nlmsgHdrLen || l > len(buf) {
			return 0, 0, fmt.Errorf("malformed netlink message: length %d with %d bytes left", l, len(buf))
		}
		msg := buf[:l]
		switch bo.Uint16(msg[4:]) {
		case nlmsgError:
			if l < nlmsgHdrLen+4 {
				return 0, 0, fmt.Errorf("truncated netlink error message (%d bytes)", l)
			}
			code := int32(bo.Uint32(msg[nlmsgHdrLen:]))
			if code == -errnoENOENT {
				return 0, 0, errFamilyNotFound
			}
			if code != 0 { // 0 is a bare acknowledgement, which carries nothing
				return 0, 0, fmt.Errorf("netlink controller error %d", code)
			}
		case nlmsgDone:
		case genlIDCtrl:
			if l >= nlmsgHdrLen+genlHdrLen && msg[nlmsgHdrLen] == ctrlCmdNewFamily {
				return familyAttrs(bo, msg[nlmsgHdrLen+genlHdrLen:])
			}
		}
		next := align4(l)
		if next >= len(buf) {
			break
		}
		buf = buf[next:]
	}
	return 0, 0, errors.New("the netlink reply carried no family information")
}

// familyAttrs walks a NEWFAMILY message's attributes for CTRL_ATTR_VERSION and CTRL_ATTR_MAXATTR.
// A reply without a version is refused rather than reported as version 0 - which would read as
// "module not loaded" and route a working kernel module's endpoints to userspace for no reason.
func familyAttrs(bo binary.ByteOrder, attrs []byte) (version, maxAttr uint32, err error) {
	haveVersion := false
	for len(attrs) >= nlaHdrLen {
		l := int(bo.Uint16(attrs[0:]))
		if l < nlaHdrLen || l > len(attrs) {
			return 0, 0, fmt.Errorf("malformed netlink attribute: length %d with %d bytes left", l, len(attrs))
		}
		typ := bo.Uint16(attrs[2:]) & nlaTypeMask
		val := attrs[nlaHdrLen:l]
		switch {
		case typ == ctrlAttrVersion && len(val) >= 4:
			version, haveVersion = bo.Uint32(val), true
		case typ == ctrlAttrMaxAttr && len(val) >= 4:
			maxAttr = bo.Uint32(val)
		}
		next := align4(l)
		if next >= len(attrs) {
			break
		}
		attrs = attrs[next:]
	}
	if !haveVersion {
		return 0, 0, errors.New("the family reply has no CTRL_ATTR_VERSION")
	}
	return version, maxAttr, nil
}
