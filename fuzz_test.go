package ip4scout

import "testing"

// FuzzParseExclusion checks that exclusion parsing never panics and that an
// accepted entry has an ordered range (first <= last) in its family.
func FuzzParseExclusion(f *testing.F) {
	for _, seed := range []string{
		"192.0.2.0/24",
		"10.0.0.1",
		"10.0.0.1-10.0.0.9",
		"::1/128",
		"2001:db8::/32",
		"2001:db8::1-2001:db8::9",
		"not an exclusion",
		"1.2.3.4/33",
		"5.5.5.5-1.1.1.1",
		"10.0.0.0/08",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := parseExclusion(s)
		if err != nil {
			return
		}
		if !got.isV6 && got.v4.first > got.v4.last {
			t.Fatalf("reversed IPv4 range from %q: %+v", s, got.v4)
		}
		if got.isV6 && got.v6.first.Compare(got.v6.last) > 0 {
			t.Fatalf("reversed IPv6 range from %q: %+v", s, got.v6)
		}
	})
}
