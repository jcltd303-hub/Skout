// Package certificates collects TLS certificate evidence without application fuzzing.
package certificates

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type Target struct {
	IP   string
	Port int
	Host string
	Mode string
}

func ParseTarget(line []byte) (Target, error) {
	var raw struct {
		IP       string          `json:"ip"`
		Port     json.RawMessage `json:"port"`
		Host     string          `json:"host"`
		Protocol string          `json:"protocol"`
	}
	if err := json.Unmarshal(line, &raw); err != nil {
		return Target{}, fmt.Errorf("invalid endpoint JSON: %w", err)
	}
	var port int
	if len(raw.Port) > 0 && raw.Port[0] == '"' {
		var value string
		if err := json.Unmarshal(raw.Port, &value); err != nil {
			return Target{}, err
		}
		var err error
		port, err = strconv.Atoi(value)
		if err != nil {
			return Target{}, fmt.Errorf("invalid port: %w", err)
		}
	} else if err := json.Unmarshal(raw.Port, &port); err != nil {
		return Target{}, fmt.Errorf("invalid numeric port: %w", err)
	}
	target := Target{IP: raw.IP, Port: port, Host: raw.Host}
	switch raw.Protocol {
	case "smtp", "ftp", "imap", "pop3":
		target.Mode = raw.Protocol
	}
	return target.normalized()
}

func (t Target) normalized() (Target, error) {
	ip := net.ParseIP(t.IP)
	if ip == nil {
		return Target{}, fmt.Errorf("target must contain a literal IP address")
	}
	t.IP = ip.String()
	if t.Port < 1 || t.Port > 65535 {
		return Target{}, fmt.Errorf("port must be 1..65535")
	}
	if t.Host != "" {
		host, ok := NormalizeName(t.Host)
		if !ok || strings.HasPrefix(host, "*.") {
			return Target{}, fmt.Errorf("SNI must be a concrete DNS name")
		}
		t.Host = host
	}
	if !validMode(t.Mode) {
		return Target{}, fmt.Errorf("unsupported protocol %q", t.Mode)
	}
	return t, nil
}

func validMode(mode string) bool {
	switch mode {
	case "", "auto", "tls", "smtp", "ftp", "imap", "pop3":
		return true
	}
	return false
}

type Options struct {
	MaxThreads    int           `default:"100" help:"Maximum concurrent certificate workers"`
	QueueSize     int           `default:"200" help:"Maximum queued endpoints"`
	RateLimit     int           `default:"50" help:"Global TCP connection starts per second (includes retries and SNI)"`
	Timeout       time.Duration `default:"8s" help:"Total deadline per connection attempt"`
	Retries       int           `default:"1" help:"Additional attempts for timeouts only"`
	SNILimit      int           `default:"0" name:"sni-limit" help:"Maximum same-endpoint follow-ups using concrete certificate SANs"`
	DedupCapacity int           `default:"100000" help:"Maximum cached endpoint/SNI keys"`
	DedupTTL      time.Duration `default:"1h" help:"Endpoint duplicate suppression window"`
	Protocol      string        `default:"auto" help:"auto, tls, smtp, ftp, imap or pop3; overrides port detection"`
	limiter       *startLimiter
	seen          *seenCache
}

func DefaultOptions() Options {
	return Options{MaxThreads: 100, QueueSize: 200, RateLimit: 50, Timeout: 8 * time.Second, Retries: 1, DedupCapacity: 100000, DedupTTL: time.Hour}
}

func (o Options) Validate() error {
	switch {
	case o.MaxThreads < 1 || o.MaxThreads > 4096:
		return fmt.Errorf("max-threads must be 1..4096")
	case o.QueueSize < 0 || o.QueueSize > 1000000:
		return fmt.Errorf("queue-size must be 0..1000000")
	case o.RateLimit < 1 || o.RateLimit > 1000000:
		return fmt.Errorf("rate-limit must be 1..1000000 connection starts/second")
	case o.Timeout <= 0:
		return fmt.Errorf("timeout must be positive")
	case o.Retries < 0 || o.Retries > 10:
		return fmt.Errorf("retries must be 0..10")
	case o.SNILimit < 0 || o.SNILimit > 64:
		return fmt.Errorf("sni-limit must be 0..64")
	case o.DedupCapacity < 1:
		return fmt.Errorf("dedup-capacity must be positive")
	case o.DedupTTL <= 0:
		return fmt.Errorf("dedup-ttl must be positive")
	case !validMode(o.Protocol):
		return fmt.Errorf("protocol must be auto, tls, smtp, ftp, imap or pop3")
	}
	return nil
}

type Certificate struct {
	CommonName      string    `json:"cn"`
	Domains         []string  `json:"domain"`
	SANs            []string  `json:"san"`
	Fingerprint     string    `json:"fingerprint"`
	IssuerName      string    `json:"issuer_name"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	HostnameMatches bool      `json:"hostname_matches"`
	HostnameChecked bool      `json:"hostname_checked"`
	TimeValid       bool      `json:"time_valid"`
	ChainValidation string    `json:"chain_validation"`
}

type SSL struct {
	Enabled     bool        `json:"enabled"`
	Detected    bool        `json:"detected"`
	Version     string      `json:"version,omitempty"`
	CipherSuite string      `json:"cypher_suite,omitempty"`
	Certificate Certificate `json:"certificate"`
}

type Event struct {
	EventType   string    `json:"event_type"`
	EventSource string    `json:"event_source"`
	IP          string    `json:"ip"`
	Port        string    `json:"port"`
	Host        string    `json:"host,omitempty"`
	Protocol    string    `json:"protocol"`
	Transports  []string  `json:"transport,omitempty"`
	Time        time.Time `json:"time"`
	SSL         SSL       `json:"ssl"`
	Attempts    int       `json:"attempts"`
	Error       string    `json:"error,omitempty"`
	ErrorKind   string    `json:"error_kind,omitempty"`
	InputLine   int       `json:"input_line,omitempty"`
}
