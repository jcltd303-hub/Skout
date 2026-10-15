package certificates

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// JARM fingerprinting (10-probe ClientHello scan) implemented after the
// public JARM spec: for each probe the ServerHello version, cipher suite,
// and extension types are concatenated, the MD5 of that concatenation is
// truncated to 30 hex characters, and the MD5 of the extension data alone
// supplies the remaining 32 characters, for a 62-character fingerprint.
//
// Best-effort by design: any probe failure returns "" and a nil error so
// certificate collection never breaks because of JARM.

type jarmExtension struct {
	typ  uint16
	data []byte
}

type jarmProbe struct {
	version    uint16
	ciphers    []uint16
	extensions []jarmExtension
}

func extU16List(values ...uint16) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint16(len(values)*2))
	for _, v := range values {
		_ = binary.Write(&b, binary.BigEndian, v)
	}
	return b.Bytes()
}

func alpnData(protos ...string) []byte {
	var inner bytes.Buffer
	for _, p := range protos {
		inner.WriteByte(byte(len(p)))
		inner.WriteString(p)
	}
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint16(inner.Len()))
	b.Write(inner.Bytes())
	return b.Bytes()
}

func supportedVersionsData(versions ...uint16) []byte {
	var b bytes.Buffer
	b.WriteByte(byte(len(versions) * 2))
	for _, v := range versions {
		_ = binary.Write(&b, binary.BigEndian, v)
	}
	return b.Bytes()
}

func sniData(name string) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint16(1+2+len(name)))
	b.WriteByte(0)
	_ = binary.Write(&b, binary.BigEndian, uint16(len(name)))
	b.WriteString(name)
	return b.Bytes()
}

// jarmProbes returns the 10 ClientHello variations. SNI carries nil data and
// is filled from the target host at build time (omitted when no host is set).
func jarmProbes() []jarmProbe {
	sni := jarmExtension{typ: 0}
	groups := jarmExtension{typ: 10, data: extU16List(0x001d, 0x0017, 0x0018, 0x0019, 0x001e, 0x0100)}
	ecFormats := jarmExtension{typ: 11, data: []byte{3, 0, 1, 2}}
	sigAlgs := jarmExtension{typ: 13, data: extU16List(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)}
	alpnH2 := jarmExtension{typ: 16, data: alpnData("h2", "http/1.1")}
	alpnH2Only := jarmExtension{typ: 16, data: alpnData("h2")}
	versions := jarmExtension{typ: 43, data: supportedVersionsData(0x0304, 0x0303)}
	ticket := jarmExtension{typ: 35}
	ems := jarmExtension{typ: 23}
	reneg := jarmExtension{typ: 0xff01, data: []byte{0x00}}
	status := jarmExtension{typ: 5, data: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}}
	return []jarmProbe{
		{version: 0x0303, ciphers: []uint16{0x1301, 0x1302, 0xC02F, 0xC02B, 0xCCA8}, extensions: []jarmExtension{sni, groups, ecFormats, sigAlgs, alpnH2, versions, ticket}},
		{version: 0x0303, ciphers: []uint16{0xC02F, 0xC030, 0x009C, 0xC013}, extensions: []jarmExtension{sni, groups, ecFormats, ems}},
		{version: 0x0301, ciphers: []uint16{0xC02F, 0xC013, 0x002F, 0x0035}, extensions: []jarmExtension{sni, groups, sigAlgs}},
		{version: 0x0302, ciphers: []uint16{0xC02B, 0xC02C, 0xCCA9, 0x009D}, extensions: []jarmExtension{groups, ecFormats, alpnH2}},
		{version: 0x0303, ciphers: []uint16{0x1302, 0x1303, 0xC030, 0xCCA8, 0xCCA9}, extensions: []jarmExtension{sni, versions, sigAlgs, alpnH2}},
		{version: 0x0303, ciphers: []uint16{0xC02F, 0x009C, 0x002F}, extensions: []jarmExtension{sni, reneg}},
		{version: 0x0303, ciphers: []uint16{0xC02B, 0xC02C, 0xC00A, 0xC013, 0xC014, 0x000A}, extensions: []jarmExtension{groups, ecFormats, sigAlgs, status}},
		{version: 0x0303, ciphers: []uint16{0xCCA8, 0xCCA9, 0xC02F, 0xC02B}, extensions: []jarmExtension{sni, groups, alpnH2, ticket, ems}},
		{version: 0x0303, ciphers: []uint16{0x1301, 0xC02F, 0x009C, 0x002F, 0x000A}, extensions: []jarmExtension{sni, groups, ecFormats, sigAlgs, versions}},
		{version: 0x0303, ciphers: []uint16{0xC030, 0xC02C, 0x009D, 0x0035}, extensions: []jarmExtension{groups, sigAlgs, alpnH2Only}},
	}
}

// buildClientHello renders one probe as a TLS record. Deterministic: the
// ClientHello random field is fixed so identical probes produce identical
// bytes, which keeps the builder unit-testable.
func buildClientHello(probe jarmProbe, serverName string) []byte {
	var body bytes.Buffer
	_ = binary.Write(&body, binary.BigEndian, probe.version)
	body.Write(make([]byte, 32))
	body.WriteByte(0) // session ID length
	_ = binary.Write(&body, binary.BigEndian, uint16(len(probe.ciphers)*2))
	for _, c := range probe.ciphers {
		_ = binary.Write(&body, binary.BigEndian, c)
	}
	body.WriteByte(1) // compression methods length
	body.WriteByte(0) // null compression
	var exts bytes.Buffer
	for _, e := range probe.extensions {
		data := e.data
		if e.typ == 0 {
			if serverName == "" {
				continue
			}
			data = sniData(serverName)
		}
		_ = binary.Write(&exts, binary.BigEndian, e.typ)
		_ = binary.Write(&exts, binary.BigEndian, uint16(len(data)))
		exts.Write(data)
	}
	_ = binary.Write(&body, binary.BigEndian, uint16(exts.Len()))
	body.Write(exts.Bytes())
	var handshake bytes.Buffer
	handshake.WriteByte(0x01)
	handshake.Write([]byte{byte(body.Len() >> 16), byte(body.Len() >> 8), byte(body.Len())})
	handshake.Write(body.Bytes())
	var record bytes.Buffer
	record.WriteByte(0x16)
	_ = binary.Write(&record, binary.BigEndian, uint16(0x0301))
	_ = binary.Write(&record, binary.BigEndian, uint16(handshake.Len()))
	record.Write(handshake.Bytes())
	return record.Bytes()
}

// parseServerHello extracts version, cipher, and extension types (as
// concatenated lowercase hex) from one handshake-record payload whose first
// message is a ServerHello.
func parseServerHello(payload []byte) (version, cipher, extensions string, ok bool) {
	if len(payload) < 5 || payload[0] != 0x02 {
		return "", "", "", false
	}
	body := payload[4:]
	if len(body) < 34 {
		return "", "", "", false
	}
	version = hex.EncodeToString(body[0:2])
	sessionLen := int(body[34])
	pos := 35 + sessionLen
	if pos+2 > len(body) {
		return "", "", "", false
	}
	cipher = hex.EncodeToString(body[pos : pos+2])
	pos += 2
	if pos >= len(body) {
		return version, cipher, "", true
	}
	pos++ // compression method
	if pos+2 > len(body) {
		return version, cipher, "", true
	}
	extLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	end := pos + extLen
	if end > len(body) {
		return "", "", "", false
	}
	var exts bytes.Buffer
	for pos+4 <= end {
		exts.WriteString(hex.EncodeToString(body[pos : pos+2]))
		extDataLen := int(body[pos+2])<<8 | int(body[pos+3])
		pos += 4 + extDataLen
	}
	if pos != end {
		return "", "", "", false
	}
	return version, cipher, exts.String(), true
}

func sendJARMProbe(ctx context.Context, target Target, hello []byte, timeout time.Duration) ([]byte, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(target.IP, strconv.Itoa(target.Port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(hello); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(reader, header); err != nil {
			return nil, err
		}
		recType := header[0]
		recLen := int(header[3])<<8 | int(header[4])
		if recLen > 16384 {
			return nil, fmt.Errorf("oversize TLS record")
		}
		payload := make([]byte, recLen)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, err
		}
		switch recType {
		case 0x16:
			if len(payload) > 0 && payload[0] == 0x02 {
				return payload, nil
			}
			// Other handshake messages: keep reading for the ServerHello.
		case 0x15:
			return nil, errors.New("TLS alert")
		default:
			// ChangeCipherSpec and friends: skip.
		}
	}
}

// JARMFingerprint runs all 10 probes against target and returns the
// 62-character JARM fingerprint, or "" when any probe fails.
func JARMFingerprint(ctx context.Context, target Target, timeout time.Duration) (string, error) {
	var jarmRaw, extRaw bytes.Buffer
	for _, probe := range jarmProbes() {
		hello := buildClientHello(probe, target.Host)
		resp, err := sendJARMProbe(ctx, target, hello, timeout)
		if err != nil {
			return "", nil
		}
		version, cipher, exts, ok := parseServerHello(resp)
		if !ok {
			return "", nil
		}
		jarmRaw.WriteString(version + cipher + exts)
		extRaw.WriteString(exts)
	}
	sumAll := md5.Sum(jarmRaw.Bytes())
	sumExt := md5.Sum(extRaw.Bytes())
	return hex.EncodeToString(sumAll[:])[:30] + hex.EncodeToString(sumExt[:]), nil
}
