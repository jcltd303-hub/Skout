package certificates

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"
)

// FuzzNormalizeName checks that name normalization never panics, that an
// accepted name is lowercase with no trailing dot, and that normalizing an
// accepted name again is a no-op (idempotent).
func FuzzNormalizeName(f *testing.F) {
	for _, seed := range []string{
		"", "example.com", " EXAMPLE.COM. ", "*.WWW.Example.COM",
		"münchen.de", "_dmarc.example.com", "127.0.0.1", "foo..bar",
		"a\nb.example", "https://example.com", "xn--bcher-kva.example",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, ok := NormalizeName(s)
		if !ok {
			if got != "" {
				t.Fatalf("rejected %q but returned %q", s, got)
			}
			return
		}
		if got != strings.ToLower(got) {
			t.Fatalf("accepted name %q is not lowercase", got)
		}
		if strings.HasSuffix(got, ".") {
			t.Fatalf("accepted name %q has a trailing dot", got)
		}
		again, ok := NormalizeName(got)
		if !ok || again != got {
			t.Fatalf("NormalizeName not idempotent: %q -> %q (%v)", got, again, ok)
		}
	})
}

// FuzzParseTarget checks that endpoint parsing never panics and that an
// accepted target has a literal IP and a port in range.
func FuzzParseTarget(f *testing.F) {
	for _, seed := range []string{
		`{"ip":"192.0.2.10","port":443}`,
		`{"ip":"192.0.2.10","port":"443","host":"www.example.com"}`,
		`{"ip":"192.0.2.10","port":443.0}`,
		`{"ip":"192.0.2.10","port":443.5}`,
		`{"ip":"example.com","port":443}`,
		`{}`, `null`, `[]`, ``, `{"ip":"127.0.0.1"}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := ParseTarget([]byte(s))
		if err != nil {
			return
		}
		if net.ParseIP(got.IP) == nil {
			t.Fatalf("accepted non-IP target %q", got.IP)
		}
		if got.Port < 1 || got.Port > 65535 {
			t.Fatalf("accepted out-of-range port %d", got.Port)
		}
	})
}

// FuzzReplyReader drives the bounded STARTTLS reply parser: line() and
// code() must never panic and must terminate on arbitrary bytes.
func FuzzReplyReader(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("220 Ready\r\n"),
		[]byte("250-STARTTLS\r\n250 \r\n"),
		[]byte("250-"),
		[]byte(strings.Repeat("250-STARTTLS\r\n", 200)),
		[]byte(strings.Repeat("x", 9000)),
		{},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := &replyReader{reader: bufio.NewReader(bytes.NewReader(data))}
		for i := 0; i < 200; i++ {
			if _, err := r.line(); err != nil {
				break
			}
		}
		r2 := &replyReader{reader: bufio.NewReader(bytes.NewReader(data))}
		if _, err := r2.code(220, false); err != nil {
			_ = err
		}
		r3 := &replyReader{reader: bufio.NewReader(bytes.NewReader(data))}
		if _, err := r3.code(250, true); err != nil {
			_ = err
		}
	})
}
