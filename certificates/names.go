package certificates

import (
	"crypto/x509"
	"net"
	"sort"
	"strings"

	"golang.org/x/net/idna"
)

// NormalizeName keeps wildcard patterns as evidence rather than inventing hosts.
// It lowercases, strips one trailing dot, and accepts single-label names
// (e.g. localhost), underscore labels (e.g. _dmarc.example.com), and
// internationalized names (converted label-by-label to Punycode via IDNA).
func NormalizeName(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	wildcard := strings.HasPrefix(value, "*.")
	base := strings.TrimPrefix(value, "*.")
	if len(value) > 253 || len(base) == 0 || net.ParseIP(base) != nil {
		return "", false
	}
	labels := strings.Split(base, ".")
	out := make([]string, 0, len(labels))
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		ascii := label
		if !isASCII(label) {
			converted, err := idna.ToASCII(label)
			if err != nil {
				return "", false
			}
			ascii = converted
		}
		if len(ascii) < 1 || len(ascii) > 63 || ascii[0] == '-' || ascii[len(ascii)-1] == '-' {
			return "", false
		}
		for _, ch := range ascii {
			if !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-' && ch != '_' {
				return "", false
			}
		}
		out = append(out, ascii)
	}
	result := strings.Join(out, ".")
	if wildcard {
		result = "*." + result
	}
	if len(result) > 253 {
		return "", false
	}
	return result, true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

func CertificateNames(cert *x509.Certificate) []string {
	seen := make(map[string]bool)
	for _, raw := range append(append([]string(nil), cert.DNSNames...), cert.Subject.CommonName) {
		if value, ok := NormalizeName(raw); ok {
			seen[value] = true
		}
	}
	names := make([]string, 0, len(seen))
	for value := range seen {
		names = append(names, value)
	}
	sort.Strings(names)
	return names
}
