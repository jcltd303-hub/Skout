// Package portprofiles shares discovery selections and collector hints.
// Hints describe conventional port use, not confirmed software or vulnerabilities.
package portprofiles

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed exposure20.json
var document []byte

type Port struct {
	Number      int    `json:"port"`
	ServiceHint string `json:"service_hint"`
	Mode        string `json:"collector_mode"`
	ReviewOrder int    `json:"-"`
}

var catalog struct {
	Ports            []Port `json:"ports"`
	CertificatePorts []int  `json:"certificate_ports"`
}

func init() {
	if err := json.Unmarshal(document, &catalog); err != nil {
		panic(err)
	}
	seen := make(map[int]bool)
	if len(catalog.Ports) != 20 {
		panic("exposure20 must contain exactly 20 ports")
	}
	for i := range catalog.Ports {
		p := &catalog.Ports[i]
		if p.Number < 1 || p.Number > 65535 || seen[p.Number] || p.ServiceHint == "" || (p.Mode != "tcp" && p.Mode != "tls" && p.Mode != "ftp") {
			panic("invalid bundled exposure profile")
		}
		p.ReviewOrder = i + 1
		seen[p.Number] = true
	}
}

func Ports(name string) ([]int, error) {
	switch name {
	case "", "exposure20":
		ports := make([]int, len(catalog.Ports))
		for i, p := range catalog.Ports {
			ports[i] = p.Number
		}
		return ports, nil
	case "certificates":
		return append([]int(nil), catalog.CertificatePorts...), nil
	default:
		return nil, fmt.Errorf("unknown port profile %q; use exposure20 or certificates", name)
	}
}

func Lookup(port int) (Port, bool) {
	for _, p := range catalog.Ports {
		if p.Number == port {
			return p, true
		}
	}
	return Port{}, false
}
