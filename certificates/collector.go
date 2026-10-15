package certificates

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

func protocolFor(t Target, o Options) string {
	if o.Protocol != "" && o.Protocol != "auto" {
		return o.Protocol
	}
	if t.Mode != "" && t.Mode != "auto" {
		return t.Mode
	}
	switch t.Port {
	case 25, 587:
		return "smtp"
	case 21:
		return "ftp"
	case 143:
		return "imap"
	case 110:
		return "pop3"
	}
	return "tls"
}

func targetKey(target Target, o Options) string {
	return fmt.Sprintf("%s|%d|%s|%s", target.IP, target.Port, target.Host, protocolFor(target, o))
}

// Collect never resolves certificate names. SNI follow-ups use the original socket address.
func Collect(ctx context.Context, target Target, o Options) ([]Event, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	target, err := target.normalized()
	if err != nil {
		return nil, err
	}
	if o.limiter == nil {
		o.limiter = newStartLimiter(o.RateLimit)
	}
	if o.seen == nil {
		o.seen = newSeenCache(o.DedupCapacity, o.DedupTTL)
		o.seen.Seen(targetKey(target, o), time.Now())
	}
	first := collectOne(ctx, target, o)
	events := []Event{first}
	if !first.SSL.Enabled || o.SNILimit == 0 || ctx.Err() != nil {
		return events, nil
	}
	seen := map[string]bool{target.Host: true}
	followed := 0
	// Use concrete SANs, rather than legacy CNs or invented wildcard hosts.
	for _, raw := range first.SSL.Certificate.SANs {
		host, ok := NormalizeName(raw)
		if !ok || strings.HasPrefix(host, "*.") || seen[host] {
			continue
		}
		seen[host] = true
		followup := target
		followup.Host = host
		if o.seen.Seen(targetKey(followup, o), time.Now()) {
			continue
		}
		events = append(events, collectOne(ctx, followup, o))
		followed++
		if followed >= o.SNILimit || ctx.Err() != nil {
			break
		}
	}
	return events, nil
}

func collectOne(ctx context.Context, target Target, o Options) Event {
	mode := protocolFor(target, o)
	event := Event{EventType: "service", EventSource: "ip4scout/certs", IP: target.IP, Port: strconv.Itoa(target.Port), Host: target.Host, Protocol: mode, Time: time.Now().UTC()}
	var err error
	for attempt := 0; attempt <= o.Retries; attempt++ {
		if err = o.limiter.Wait(ctx); err != nil {
			break
		}
		event.Attempts++
		var state tls.ConnectionState
		state, err = handshake(ctx, target, mode, o.Timeout)
		if err == nil {
			if len(state.PeerCertificates) == 0 {
				err = errors.New("TLS peer provided no certificate")
				break
			}
			cert := state.PeerCertificates[0]
			fingerprint := sha256.Sum256(cert.Raw)
			now := time.Now()
			event.Transports = []string{"tcp", "tls"}
			event.SSL = SSL{Enabled: true, Detected: true, Version: tls.VersionName(state.Version), CipherSuite: tls.CipherSuiteName(state.CipherSuite), Certificate: Certificate{
				CommonName: cert.Subject.CommonName, Domains: CertificateNames(cert), SANs: append([]string{}, cert.DNSNames...), Fingerprint: hex.EncodeToString(fingerprint[:]), IssuerName: cert.Issuer.String(), NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(), HostnameMatches: target.Host != "" && cert.VerifyHostname(target.Host) == nil, HostnameChecked: target.Host != "", TimeValid: !now.Before(cert.NotBefore) && !now.After(cert.NotAfter), ChainValidation: "not_assessed",
			}}
			return event
		}
		if ctx.Err() != nil || !isTimeout(err) {
			break
		}
	}
	if err == nil {
		err = errors.New("certificate collection stopped")
	}
	event.Error = err.Error()
	event.ErrorKind = errorKind(err)
	return event
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}
func errorKind(err error) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if isTimeout(err) {
		return "timeout"
	}
	return "connection_or_protocol"
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func handshake(parent context.Context, target Target, mode string, timeout time.Duration) (tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(target.IP, strconv.Itoa(target.Port)))
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return tls.ConnectionState{}, err
	}
	transport := conn
	if mode != "tls" {
		reader := bufio.NewReader(conn)
		if err = upgrade(conn, reader, mode); err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			return tls.ConnectionState{}, err
		}
		transport = &bufferedConn{Conn: conn, reader: reader}
	}
	// Observation mode accepts self-signed/expired certificates and explicitly does not assess trust.
	tc := tls.Client(transport, &tls.Config{ServerName: target.Host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
	if err = tc.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	return tc.ConnectionState(), nil
}

type replyReader struct {
	reader *bufio.Reader
	bytes  int
	lines  int
}

func (r *replyReader) line() (string, error) {
	r.lines++
	if r.lines > 128 {
		return "", errors.New("protocol reply exceeded 128 lines")
	}
	var line []byte
	for {
		part, err := r.reader.ReadSlice('\n')
		r.bytes += len(part)
		if r.bytes > 65536 || len(line)+len(part) > 8192 {
			return "", errors.New("protocol reply exceeded size limit")
		}
		line = append(line, part...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return "", err
		}
		return strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"), nil
	}
}

// code reads SMTP/FTP multiline replies; FTP permits nonnumeric intermediate lines.
func (r *replyReader) code(expected int, ftp bool) ([]string, error) {
	code := strconv.Itoa(expected)
	var lines []string
	first, err := r.line()
	if err != nil {
		return nil, err
	}
	if len(first) < 3 || first[:3] != code || (len(first) > 3 && first[3] != ' ' && first[3] != '-') {
		return nil, fmt.Errorf("expected %s response, got %q", code, first)
	}
	lines = append(lines, first)
	if len(first) == 3 || first[3] == ' ' {
		return lines, nil
	}
	for {
		line, err := r.line()
		if err != nil {
			return nil, err
		}
		lines = append(lines, line)
		if strings.HasPrefix(line, code+" ") || line == code {
			return lines, nil
		}
		if !ftp && !strings.HasPrefix(line, code+"-") {
			return nil, fmt.Errorf("invalid multiline %s response", code)
		}
	}
}

func send(conn net.Conn, line string) error { _, err := io.WriteString(conn, line+"\r\n"); return err }
func upgrade(conn net.Conn, reader *bufio.Reader, mode string) error {
	r := &replyReader{reader: reader}
	switch mode {
	case "smtp":
		if _, err := r.code(220, false); err != nil {
			return err
		}
		if err := send(conn, "EHLO scout.invalid"); err != nil {
			return err
		}
		lines, err := r.code(250, false)
		if err != nil {
			return err
		}
		supported := false
		for _, line := range lines {
			if len(line) > 4 {
				fields := strings.Fields(line[4:])
				if len(fields) > 0 && strings.EqualFold(fields[0], "STARTTLS") {
					supported = true
				}
			}
		}
		if !supported {
			return errors.New("SMTP server did not advertise STARTTLS")
		}
		if err := send(conn, "STARTTLS"); err != nil {
			return err
		}
		_, err = r.code(220, false)
		return err
	case "ftp":
		if _, err := r.code(220, true); err != nil {
			return err
		}
		if err := send(conn, "AUTH TLS"); err != nil {
			return err
		}
		_, err := r.code(234, true)
		return err
	case "imap":
		line, err := r.line()
		if err != nil {
			return err
		}
		if !strings.HasPrefix(strings.ToUpper(line), "* OK ") && strings.ToUpper(line) != "* OK" {
			return fmt.Errorf("invalid IMAP greeting %q", line)
		}
		if err := send(conn, "a001 STARTTLS"); err != nil {
			return err
		}
		for {
			line, err = r.line()
			if err != nil {
				return err
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.EqualFold(fields[0], "a001") {
				if strings.EqualFold(fields[1], "OK") {
					return nil
				}
				return fmt.Errorf("IMAP STARTTLS refused: %q", line)
			}
			if len(fields) < 2 || fields[0] != "*" {
				return fmt.Errorf("invalid IMAP response %q", line)
			}
		}
	case "pop3":
		line, err := r.line()
		if err != nil {
			return err
		}
		if !positivePOP(line) {
			return fmt.Errorf("invalid POP3 greeting %q", line)
		}
		if err := send(conn, "STLS"); err != nil {
			return err
		}
		line, err = r.line()
		if err != nil {
			return err
		}
		if !positivePOP(line) {
			return fmt.Errorf("POP3 STLS refused: %q", line)
		}
		return nil
	}
	return fmt.Errorf("unsupported upgrade protocol %q", mode)
}
func positivePOP(line string) bool { return line == "+OK" || strings.HasPrefix(line, "+OK ") }
