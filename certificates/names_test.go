package certificates

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"reflect"
	"testing"
)

func TestNormalizeName(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{" EXAMPLE.COM. ", "example.com", true},
		{"*.WWW.Example.COM", "*.www.example.com", true},
		{"xn--bcher-kva.example", "xn--bcher-kva.example", true},
		{"127.0.0.1", "", false}, {"2001:db8::1", "", false},
		{"localhost", "", false}, {"Example Corp", "", false},
		{"foo..example.com", "", false}, {"-foo.example", "", false},
		{"foo-.example", "", false}, {"foo.*.example", "", false},
		{"https://example.com", "", false}, {"a\nb.example", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := NormalizeName(tc.in)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("got (%q,%v), want (%q,%v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestCertificateNamesKeepWildcardAndCommonName(t *testing.T) {
	c := &x509.Certificate{Subject: pkix.Name{CommonName: "Legacy.Example.COM"}, DNSNames: []string{"WWW.example.com.", "www.example.com", "*.example.com", "127.0.0.1"}}
	want := []string{"*.example.com", "legacy.example.com", "www.example.com"}
	if got := CertificateNames(c); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseTargetAcceptsL9StringAndNumericPort(t *testing.T) {
	for _, line := range []string{`{"ip":"192.0.2.10","port":"443","host":"WWW.Example.COM."}`, `{"ip":"192.0.2.10","port":443,"host":"WWW.Example.COM."}`} {
		got, err := ParseTarget([]byte(line))
		if err != nil || got.IP != "192.0.2.10" || got.Port != 443 || got.Host != "www.example.com" {
			t.Fatalf("%+v %v", got, err)
		}
	}
}

func TestParseTargetRejectsInvalidInput(t *testing.T) {
	for _, line := range []string{`null`, `[]`, `{}`, `{"ip":"example.com","port":"443"}`, `{"ip":"127.0.0.1","port":"0"}`, `{"ip":"127.0.0.1","port":65536}`, `{"ip":"127.0.0.1","port":443.5}`, `{"ip":"127.0.0.1","port":443,"host":"*.example.com"}`, `{"ip":"127.0.0.1","port":443,"host":"a\r\nEHLO evil.test"}`} {
		if _, err := ParseTarget([]byte(line)); err == nil {
			t.Fatalf("accepted %s", line)
		}
	}
}
