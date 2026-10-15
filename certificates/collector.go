package certificates

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jcltd303-hub/Skout/portprofiles"
)

// protocolFor resolves the wire protocol. Explicit overrides win, then the
// well-known port table (which takes precedence over profile hints), then the
// port-profile hint, then direct TLS.
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
	case 389:
		return "ldap"
	case 5222:
		return "xmpp"
	case 5432:
		return "postgres"
	case 24:
		return "lmtp"
	}
	if hint, ok := portprofiles.Lookup(t.Port); ok {
		return hint.Mode
	}
	return "tls"
}

func targetKey(target Target, o Options) string {
	return fmt.Sprintf("%s|%d|%s|%s", target.IP, target.Port, target.Host, protocolFor(target, o))
}

// expiryDropped reports whether a collected certificate event is outside the
// configured expiry window. Error events (no certificate) always pass through.
func expiryDropped(event Event, o Options) bool {
	return o.ExpiryWithinDays > 0 && event.SSL.Enabled && event.SSL.Certificate.ExpiresInDays > o.ExpiryWithinDays
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
	var events []Event
	if !expiryDropped(first, o) {
		events = append(events, first)
	}
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
		event := collectOne(ctx, followup, o)
		if !expiryDropped(event, o) {
			events = append(events, event)
		}
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
	if hint, ok := portprofiles.Lookup(target.Port); ok {
		event.ServiceHint, event.PortReviewOrder = hint.ServiceHint, hint.ReviewOrder
	}
	var err error
	for attempt := 0; attempt <= o.Retries; attempt++ {
		if err = o.limiter.Wait(ctx); err != nil {
			break
		}
		event.Attempts++
		var state tls.ConnectionState
		var connected bool
		state, connected, err = handshake(ctx, target, mode, o)
		if connected {
			event.TCPConnected = true
			event.Transports = []string{"tcp"}
		}
		if err == nil {
			if mode == "tcp" {
				return event
			}
			if len(state.PeerCertificates) == 0 {
				err = errors.New("TLS peer provided no certificate")
				break
			}
			cert := state.PeerCertificates[0]
			fingerprint := sha256.Sum256(cert.Raw)
			now := time.Now()
			chain := make([]ChainCert, 0, len(state.PeerCertificates)-1)
			for _, c := range state.PeerCertificates[1:] {
				sum := sha256.Sum256(c.Raw)
				chain = append(chain, ChainCert{CommonName: c.Subject.CommonName, Fingerprint: hex.EncodeToString(sum[:]), IssuerName: c.Issuer.String(), NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC()})
			}
			chainValidation := "not_assessed"
			if o.VerifyChain {
				verifyOpts := x509.VerifyOptions{Roots: nil, DNSName: target.Host, CurrentTime: now}
				if len(state.PeerCertificates) > 1 {
					pool := x509.NewCertPool()
					for _, c := range state.PeerCertificates[1:] {
						pool.AddCert(c)
					}
					verifyOpts.Intermediates = pool
				}
				if _, verr := cert.Verify(verifyOpts); verr != nil {
					chainValidation = "invalid:" + verr.Error()
				} else {
					chainValidation = "valid"
				}
			}
			event.Transports = []string{"tcp", "tls"}
			event.SSL = SSL{Enabled: true, Detected: true, Version: tls.VersionName(state.Version), CipherSuite: tls.CipherSuiteName(state.CipherSuite), Certificate: Certificate{
				CommonName: cert.Subject.CommonName, Domains: CertificateNames(cert), SANs: append([]string{}, cert.DNSNames...), Fingerprint: hex.EncodeToString(fingerprint[:]), IssuerName: cert.Issuer.String(), NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(), HostnameMatches: target.Host != "" && cert.VerifyHostname(target.Host) == nil, HostnameChecked: target.Host != "", TimeValid: !now.Before(cert.NotBefore) && !now.After(cert.NotAfter), ChainValidation: chainValidation, Chain: chain, ChainLength: len(chain), ExpiresInDays: int(math.Floor(time.Until(cert.NotAfter).Hours() / 24)),
			}}
			if o.JARM && mode == "tls" {
				if fp, jerr := JARMFingerprint(ctx, target, o.Timeout); jerr == nil && fp != "" {
					event.JARM = fp
					event.SSL.JARM = fp
				}
			}
			if o.HTTPBanner && (target.Port == 443 || target.Port == 8443) {
				if banner, berr := fetchHTTPBanner(ctx, target, o); berr == nil && banner != nil {
					event.HTTPBanner = banner
				}
			}
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

// minTLSVersion maps the configured "1.0".."1.3" string to a crypto/tls
// constant. Empty or unknown values fall back to TLS 1.2; Validate rejects
// unknown values before collection starts.
func minTLSVersion(name string) uint16 {
	switch name {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

func handshake(parent context.Context, target Target, mode string, o Options) (tls.ConnectionState, bool, error) {
	ctx, cancel := context.WithTimeout(parent, o.Timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(target.IP, strconv.Itoa(target.Port)))
	if err != nil {
		return tls.ConnectionState{}, false, err
	}
	defer conn.Close()
	if mode == "tcp" {
		return tls.ConnectionState{}, true, nil
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return tls.ConnectionState{}, true, err
	}
	transport := conn
	if mode != "tls" {
		reader := bufio.NewReader(conn)
		if err = upgrade(conn, reader, mode); err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			return tls.ConnectionState{}, true, err
		}
		transport = &bufferedConn{Conn: conn, reader: reader}
	}
	// Observation mode accepts self-signed/expired certificates and explicitly does not assess trust.
	tc := tls.Client(transport, &tls.Config{ServerName: target.Host, InsecureSkipVerify: true, MinVersion: minTLSVersion(o.MinTLSVersion)})
	if err = tc.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, true, err
	}
	return tc.ConnectionState(), true, nil
}

// fetchHTTPBanner performs a best-effort HTTPS GET on a fresh connection and
// extracts the status code, Server header, and <title>. Any failure returns
// an error and the caller leaves the banner empty without failing the cert
// event.
func fetchHTTPBanner(parent context.Context, target Target, o Options) (*HTTPBanner, error) {
	timeout := 3 * time.Second
	if o.Timeout < timeout {
		timeout = o.Timeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(target.IP, strconv.Itoa(target.Port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: target.Host, InsecureSkipVerify: true, MinVersion: minTLSVersion(o.MinTLSVersion)})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	host := target.Host
	if host == "" {
		host = target.IP
	}
	if _, err := io.WriteString(tc, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(io.LimitReader(tc, 8192))
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	banner := &HTTPBanner{}
	if fields := strings.Fields(statusLine); len(fields) >= 2 {
		banner.Status, _ = strconv.Atoi(fields[1])
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(trimmed), "server:") {
			banner.Server = strings.TrimSpace(trimmed[len("server:"):])
		}
	}
	// Best-effort body read for the <title>; a server that never closes the
	// connection just hits the deadline and we parse what arrived.
	body, _ := io.ReadAll(io.LimitReader(reader, 2048))
	lower := strings.ToLower(string(body))
	if start := strings.Index(lower, "<title>"); start >= 0 {
		rest := string(body)[start+len("<title>"):]
		if end := strings.Index(strings.ToLower(rest), "</title>"); end >= 0 {
			banner.Title = strings.TrimSpace(rest[:end])
		}
	}
	return banner, nil
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

// readLDAPResult parses one LDAPMessage carrying an extended response and
// requires result code 0 (success).
func readLDAPResult(reader *bufio.Reader) error {
	tag, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if tag != 0x30 {
		return fmt.Errorf("invalid LDAP response tag %#x", tag)
	}
	length, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if length&0x80 != 0 {
		return fmt.Errorf("unexpected LDAP long-form length")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
	// payload: 02 <len> <messageID> 61 <len> 0a <len> <resultCode> ...
	if len(payload) < 8 || payload[0] != 0x02 || payload[3] != 0x61 || payload[5] != 0x0a {
		return fmt.Errorf("unexpected LDAP response shape")
	}
	if payload[7] != 0 {
		return fmt.Errorf("LDAP StartTLS failed with result code %d", payload[7])
	}
	return nil
}

func upgrade(conn net.Conn, reader *bufio.Reader, mode string) error {
	r := &replyReader{reader: reader}
	switch mode {
	case "smtp", "lmtp":
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
	case "ldap":
		// LDAP StartTLS extended request (RFC 4511), OID 1.3.6.1.4.1.1466.20037.
		// Lengths are fixed for this OID: message 29, extendedReq 24, name 22.
		oid := "1.3.6.1.4.1.1466.20037"
		req := []byte{0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, byte(len(oid))}
		req = append(req, oid...)
		if _, err := conn.Write(req); err != nil {
			return err
		}
		return readLDAPResult(reader)
	case "xmpp":
		if _, err := io.WriteString(conn, "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' to='scout.invalid'>"); err != nil {
			return err
		}
		if _, err := io.WriteString(conn, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"); err != nil {
			return err
		}
		var buf []byte
		tmp := make([]byte, 4096)
		for len(buf) < 65536 {
			n, err := reader.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				if strings.Contains(string(buf), "<proceed") {
					return nil
				}
				if strings.Contains(string(buf), "<failure") {
					return errors.New("XMPP STARTTLS refused")
				}
			}
			if err != nil {
				return fmt.Errorf("XMPP STARTTLS: %w", err)
			}
		}
		return errors.New("XMPP STARTTLS response exceeded size limit")
	case "postgres":
		// SSLRequest: length 8, code 80877103.
		if _, err := conn.Write([]byte{0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f}); err != nil {
			return err
		}
		b, err := reader.ReadByte()
		if err != nil {
			return err
		}
		switch b {
		case 'S':
			return nil
		case 'N':
			return errors.New("PostgreSQL server refused SSL")
		default:
			return fmt.Errorf("unexpected PostgreSQL SSL response %q", b)
		}
	}
	return fmt.Errorf("unsupported upgrade protocol %q", mode)
}
func positivePOP(line string) bool { return line == "+OK" || strings.HasPrefix(line, "+OK ") }
