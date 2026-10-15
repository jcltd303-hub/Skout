package certificates

import (
	"crypto/x509"
	"net"
	"sort"
	"strings"
)

// NormalizeName keeps wildcard patterns as evidence rather than inventing hosts.
func NormalizeName(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	base := strings.TrimPrefix(value, "*.")
	if len(value) > 253 || net.ParseIP(base) != nil {
		return "", false
	}
	labels := strings.Split(base, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-' {
				return "", false
			}
		}
	}
	return value, true
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
