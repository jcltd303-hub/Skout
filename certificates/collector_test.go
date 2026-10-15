package certificates

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func testCertificate(t *testing.T, cn string, sans ...string) tls.Certificate {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, DNSNames: sans, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func fixtureServer(t *testing.T, handler func(net.Conn)) Target {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				handler(c)
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; wg.Wait() })
	return Target{IP: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}
}

func fixtureTLS(t *testing.T, mode string, config *tls.Config) Target {
	t.Helper()
	target := fixtureServer(t, func(c net.Conn) {
		r := bufio.NewReader(c)
		read := func(want string) bool {
			line, err := r.ReadString('\n')
			return err == nil && strings.TrimSpace(line) == want
		}
		switch mode {
		case "smtp", "lmtp":
			_, _ = fmt.Fprint(c, "220-fixture ready\r\n220 ESMTP\r\n")
			if !read("EHLO scout.invalid") {
				return
			}
			// Fragment a multiline capability reply across writes.
			_, _ = fmt.Fprint(c, "250-fixt")
			_, _ = fmt.Fprint(c, "ure\r\n250-PIPELINING\r\n250 STARTTLS\r\n")
			if !read("STARTTLS") {
				return
			}
			_, _ = fmt.Fprint(c, "220 Ready\r\n")
		case "ftp":
			_, _ = fmt.Fprint(c, "220-Welcome\r\nSome information\r\n220 Ready\r\n")
			if !read("AUTH TLS") {
				return
			}
			_, _ = fmt.Fprint(c, "234 Proceed\r\n")
		case "imap":
			_, _ = fmt.Fprint(c, "* OK fixture ready\r\n")
			if !read("a001 STARTTLS") {
				return
			}
			_, _ = fmt.Fprint(c, "* CAPABILITY IMAP4rev1\r\na001 OK Start TLS\r\n")
		case "pop3":
			_, _ = fmt.Fprint(c, "+OK fixture ready\r\n")
			if !read("STLS") {
				return
			}
			_, _ = fmt.Fprint(c, "+OK Begin TLS\r\n")
		}
		tc := tls.Server(c, config)
		_ = tc.Handshake()
	})
	target.Mode = mode
	return target
}

func fastOptions() Options {
	o := DefaultOptions()
	o.RateLimit = 10000
	o.Timeout = time.Second
	o.Retries = 0
	return o
}

func TestTCPModeConnectsWithoutApplicationBytes(t *testing.T) {
	received := make(chan int, 1)
	target := fixtureServer(t, func(c net.Conn) { b := make([]byte, 1); n, _ := c.Read(b); received <- n })
	target.Mode = "tcp"
	events, err := Collect(context.Background(), target, fastOptions())
	if err != nil || len(events) != 1 {
		t.Fatalf("%v %+v", err, events)
	}
	e := events[0]
	if e.Error != "" || !e.TCPConnected || e.SSL.Enabled || e.Protocol != "tcp" || len(e.Transports) != 1 || e.Transports[0] != "tcp" {
		t.Fatalf("TCP reachability mislabeled: %+v", e)
	}
	if n := <-received; n != 0 {
		t.Fatalf("connect-only mode sent %d application bytes", n)
	}
}

func TestTLSFailureRetainsTCPReachability(t *testing.T) {
	target := fixtureServer(t, func(c net.Conn) { _, _ = c.Write([]byte("not TLS\r\n")) })
	target.Mode = "tls"
	events, err := Collect(context.Background(), target, fastOptions())
	if err != nil || len(events) != 1 || !events[0].TCPConnected || events[0].Error == "" || events[0].SSL.Enabled {
		t.Fatalf("lost TCP evidence on TLS failure: %+v (%v)", events, err)
	}
}

func TestAutoExposureModesAndExplicitOverride(t *testing.T) {
	for port, mode := range map[int]string{2375: "tcp", 22: "tcp", 3389: "tcp", 9200: "tcp", 443: "tls", 5986: "tls", 10250: "tls", 21: "ftp", 587: "smtp", 143: "imap", 110: "pop3"} {
		if got := protocolFor(Target{Port: port}, fastOptions()); got != mode {
			t.Fatalf("port %d: got %s, want %s", port, got, mode)
		}
	}
	o := fastOptions()
	o.Protocol = "tls"
	if got := protocolFor(Target{Port: 22, Mode: "tcp"}, o); got != "tls" {
		t.Fatal("explicit override ignored")
	}
	target, err := ParseTarget([]byte(`{"ip":"127.0.0.1","port":2375,"protocol":"tcp"}`))
	if err != nil || target.Mode != "tcp" {
		t.Fatalf("TCP endpoint mode lost: %+v %v", target, err)
	}
}

func TestCollectTLSAndFourUpgradeProtocols(t *testing.T) {
	for _, mode := range []string{"tls", "smtp", "ftp", "imap", "pop3"} {
		t.Run(mode, func(t *testing.T) {
			target := fixtureTLS(t, mode, &tls.Config{Certificates: []tls.Certificate{testCertificate(t, "legacy.example.test", "WWW.example.test", "*.example.test")}})
			target.Host = "www.example.test"
			events, err := Collect(context.Background(), target, fastOptions())
			if err != nil || len(events) != 1 {
				t.Fatalf("%v %+v", err, events)
			}
			e := events[0]
			if e.Error != "" || !e.SSL.Enabled || len(e.SSL.Certificate.Domains) != 3 || !e.SSL.Certificate.HostnameMatches || !e.SSL.Certificate.TimeValid || e.SSL.Certificate.ChainValidation != "not_assessed" || len(e.SSL.Certificate.Fingerprint) != 64 {
				t.Fatalf("bad certificate evidence: %+v", e)
			}
		})
	}
}

func TestCollectSNIStaysOnOriginalEndpoint(t *testing.T) {
	root := testCertificate(t, "default.example.test", "virtual.example.test")
	virtual := testCertificate(t, "virtual.example.test", "extra.example.test")
	target := fixtureTLS(t, "tls", &tls.Config{Certificates: []tls.Certificate{root}, GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h.ServerName == "virtual.example.test" {
			return &virtual, nil
		}
		return &root, nil
	}})
	o := fastOptions()
	o.SNILimit = 1
	events, err := Collect(context.Background(), target, o)
	if err != nil || len(events) != 2 {
		t.Fatalf("%v %+v", err, events)
	}
	if events[1].IP != target.IP || events[1].Port != fmt.Sprint(target.Port) || events[1].Host != "virtual.example.test" || events[0].SSL.Certificate.Fingerprint == events[1].SSL.Certificate.Fingerprint {
		t.Fatalf("bad SNI followup: %+v", events)
	}
}

func TestCNOnlyCertificateHasExplicitEmptySANArray(t *testing.T) {
	target := fixtureTLS(t, "tls", &tls.Config{Certificates: []tls.Certificate{testCertificate(t, "cn.example.test")}})
	events, err := Collect(context.Background(), target, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(events[0])
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		SSL struct {
			Certificate struct {
				SANs interface{} `json:"san"`
			} `json:"certificate"`
		} `json:"ssl"`
	}
	if err = json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	sans, ok := raw.SSL.Certificate.SANs.([]interface{})
	if !ok || len(sans) != 0 {
		t.Fatalf("no-SAN certificate serialized ambiguously: %s", data)
	}
}

func TestSMTPRefusalDoesNotClaimTLS(t *testing.T) {
	target := fixtureServer(t, func(c net.Conn) {
		r := bufio.NewReader(c)
		_, _ = fmt.Fprint(c, "220 Ready\r\n")
		_, _ = r.ReadString('\n')
		_, _ = fmt.Fprint(c, "250-Ready\r\n250 STARTTLS\r\n")
		_, _ = r.ReadString('\n')
		_, _ = fmt.Fprint(c, "454 TLS unavailable\r\n")
	})
	target.Mode = "smtp"
	events, err := Collect(context.Background(), target, fastOptions())
	if err != nil || len(events) != 1 || events[0].Error == "" || events[0].SSL.Enabled {
		t.Fatalf("refusal lost: %v %+v", err, events)
	}
}

func TestTimeoutRetryRecovers(t *testing.T) {
	cert := testCertificate(t, "retry.example.test", "retry.example.test")
	var mu sync.Mutex
	attempts := 0
	target := fixtureServer(t, func(c net.Conn) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n == 1 {
			time.Sleep(100 * time.Millisecond)
			return
		}
		_ = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
	})
	o := fastOptions()
	o.Timeout = 40 * time.Millisecond
	o.Retries = 1
	o.RateLimit = 10
	start := time.Now()
	events, err := Collect(context.Background(), target, o)
	if err != nil || len(events) != 1 || events[0].Error != "" || events[0].Attempts != 2 {
		t.Fatalf("retry failed: %v %+v", err, events)
	}
	if time.Since(start) < 90*time.Millisecond {
		t.Fatal("timeout retry bypassed connection-start cap")
	}
}

func TestProtocolReplyCannotGrowWithoutBound(t *testing.T) {
	target := fixtureServer(t, func(c net.Conn) {
		r := bufio.NewReader(c)
		_, _ = fmt.Fprint(c, "220 Ready\r\n")
		_, _ = r.ReadString('\n')
		_, _ = fmt.Fprint(c, strings.Repeat("250-STARTTLS\r\n", 200))
	})
	target.Mode = "smtp"
	events, err := Collect(context.Background(), target, fastOptions())
	if err != nil || len(events) != 1 || !strings.Contains(events[0].Error, "128 lines") || events[0].SSL.Enabled {
		t.Fatalf("unbounded response accepted: %v %+v", err, events)
	}
}

func testCertificateChain(t *testing.T) tls.Certificate {
	t.Helper()
	now := time.Now()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPub, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf.example.test"}, DNSNames: []string{"leaf.example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(50 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, leafPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPriv, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafPriv}))
	if err != nil {
		t.Fatal(err)
	}
	cert.Certificate = append(cert.Certificate, caDER)
	return cert
}

func TestCollectChainExpiryAndVerify(t *testing.T) {
	target := fixtureTLS(t, "tls", &tls.Config{Certificates: []tls.Certificate{testCertificateChain(t)}})
	target.Host = "leaf.example.test"
	events, err := Collect(context.Background(), target, fastOptions())
	if err != nil || len(events) != 1 || events[0].Error != "" {
		t.Fatalf("%v %+v", err, events)
	}
	cert := events[0].SSL.Certificate
	if cert.ChainLength != 1 || len(cert.Chain) != 1 || cert.Chain[0].CommonName != "Test CA" || len(cert.Chain[0].Fingerprint) != 64 {
		t.Fatalf("bad chain evidence: %+v", cert)
	}
	if cert.ExpiresInDays != 2 {
		t.Fatalf("ExpiresInDays = %d, want 2 (50h leaf)", cert.ExpiresInDays)
	}
	if cert.ChainValidation != "not_assessed" {
		t.Fatalf("ChainValidation = %q, want not_assessed without --verify-chain", cert.ChainValidation)
	}
	o := fastOptions()
	o.VerifyChain = true
	events, err = Collect(context.Background(), target, o)
	if err != nil || len(events) != 1 {
		t.Fatalf("%v %+v", err, events)
	}
	if got := events[0].SSL.Certificate.ChainValidation; !strings.HasPrefix(got, "invalid:") {
		t.Fatalf("self-signed chain reported %q, want invalid:...", got)
	}
}

func TestCollectExpiryFilterDropsLateCerts(t *testing.T) {
	target := fixtureTLS(t, "tls", &tls.Config{Certificates: []tls.Certificate{testCertificateChain(t)}})
	o := fastOptions()
	o.ExpiryWithinDays = 1
	events, err := Collect(context.Background(), target, o)
	if err != nil || len(events) != 0 {
		t.Fatalf("cert expiring in 2 days kept with 1-day window: %+v (%v)", events, err)
	}
	o.ExpiryWithinDays = 3
	events, err = Collect(context.Background(), target, o)
	if err != nil || len(events) != 1 {
		t.Fatalf("cert expiring in 2 days dropped with 3-day window: %+v (%v)", events, err)
	}
	// Error events pass through the expiry filter.
	o.ExpiryWithinDays = 1
	events, err = Collect(context.Background(), Target{IP: "127.0.0.1", Port: 1}, o)
	if err != nil || len(events) != 1 || events[0].Error == "" {
		t.Fatalf("error event lost to expiry filter: %+v (%v)", events, err)
	}
}

func TestCollectIPv6Loopback(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	cert := testCertificate(t, "v6.example.test", "v6.example.test")
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				_ = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; wg.Wait() })
	target := Target{IP: "::1", Port: listener.Addr().(*net.TCPAddr).Port}
	events, err := Collect(context.Background(), target, fastOptions())
	if err != nil || len(events) != 1 || events[0].Error != "" || !events[0].SSL.Enabled {
		t.Fatalf("IPv6 collection failed: %+v (%v)", events, err)
	}
}

func TestProtocolForNewModes(t *testing.T) {
	for port, mode := range map[int]string{389: "ldap", 5222: "xmpp", 5432: "postgres", 24: "lmtp"} {
		if got := protocolFor(Target{Port: port}, fastOptions()); got != mode {
			t.Fatalf("port %d: got %s, want %s", port, got, mode)
		}
	}
	o := fastOptions()
	o.Protocol = "tcp"
	if got := protocolFor(Target{Port: 5432}, o); got != "tcp" {
		t.Fatal("explicit override lost to port table")
	}
	if got := protocolFor(Target{Port: 5432, Mode: "tls"}, fastOptions()); got != "tls" {
		t.Fatal("endpoint mode lost to port table")
	}
}

func fixtureLDAP(t *testing.T) Target {
	t.Helper()
	target := fixtureServer(t, func(c net.Conn) {
		buf := make([]byte, 31)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		_, _ = c.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
		_ = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{testCertificate(t, "ldap.example.test", "ldap.example.test")}}).Handshake()
	})
	target.Mode = "ldap"
	return target
}

func fixturePostgres(t *testing.T) Target {
	t.Helper()
	target := fixtureServer(t, func(c net.Conn) {
		buf := make([]byte, 8)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		if buf[4] != 4 || buf[5] != 0xd2 || buf[6] != 0x16 || buf[7] != 0x2f {
			return
		}
		_, _ = c.Write([]byte{'S'})
		_ = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{testCertificate(t, "pg.example.test", "pg.example.test")}}).Handshake()
	})
	target.Mode = "postgres"
	return target
}

func fixtureXMPP(t *testing.T) Target {
	t.Helper()
	target := fixtureServer(t, func(c net.Conn) {
		var buf []byte
		tmp := make([]byte, 512)
		for !strings.Contains(string(buf), "starttls") {
			n, err := c.Read(tmp)
			if err != nil {
				return
			}
			buf = append(buf, tmp[:n]...)
			if len(buf) > 4096 {
				return
			}
		}
		_, _ = io.WriteString(c, "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>")
		_ = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{testCertificate(t, "xmpp.example.test", "xmpp.example.test")}}).Handshake()
	})
	target.Mode = "xmpp"
	return target
}

func TestCollectNewSTARTTLSProtocols(t *testing.T) {
	targets := map[string]Target{
		"ldap":     fixtureLDAP(t),
		"postgres": fixturePostgres(t),
		"xmpp":     fixtureXMPP(t),
		"lmtp":     fixtureTLS(t, "lmtp", &tls.Config{Certificates: []tls.Certificate{testCertificate(t, "lmtp.example.test", "lmtp.example.test")}}),
	}
	for name, target := range targets {
		t.Run(name, func(t *testing.T) {
			events, err := Collect(context.Background(), target, fastOptions())
			if err != nil || len(events) != 1 || events[0].Error != "" || !events[0].SSL.Enabled {
				t.Fatalf("bad %s collection: %+v (%v)", name, events, err)
			}
		})
	}
}

func TestMinTLSVersionEnforcedInHandshake(t *testing.T) {
	target := fixtureTLS(t, "tls", &tls.Config{Certificates: []tls.Certificate{testCertificate(t, "min.example.test", "min.example.test")}, MaxVersion: tls.VersionTLS12})
	o := fastOptions()
	o.MinTLSVersion = "1.3"
	events, err := Collect(context.Background(), target, o)
	if err != nil || len(events) != 1 || events[0].Error == "" || events[0].SSL.Enabled {
		t.Fatalf("TLS 1.2-only server accepted with min 1.3: %+v (%v)", events, err)
	}
}

func TestJARMProbeBuilderDeterministic(t *testing.T) {
	probes := jarmProbes()
	if len(probes) != 10 {
		t.Fatalf("got %d probes, want 10", len(probes))
	}
	a := buildClientHello(probes[0], "example.test")
	b := buildClientHello(probes[0], "example.test")
	if !bytes.Equal(a, b) {
		t.Fatal("same probe produced different ClientHello bytes")
	}
	if len(a) < 48 || a[0] != 0x16 || a[5] != 0x01 {
		t.Fatal("not a TLS handshake record")
	}
	if got := binary.BigEndian.Uint16(a[9:11]); got != probes[0].version {
		t.Fatalf("ClientHello version %#x, want %#x", got, probes[0].version)
	}
	if got := binary.BigEndian.Uint16(a[46:48]); got != probes[0].ciphers[0] {
		t.Fatalf("first cipher %#x, want %#x", got, probes[0].ciphers[0])
	}
	if !bytes.Contains(a, []byte("example.test")) {
		t.Fatal("SNI missing from ClientHello")
	}
	if probes[2].version != 0x0301 {
		t.Fatalf("probe 3 version %#x, want TLS 1.0 (0x0301)", probes[2].version)
	}
}

func TestJARMLoopbackBestEffort(t *testing.T) {
	target := fixtureTLS(t, "tls", &tls.Config{Certificates: []tls.Certificate{testCertificate(t, "jarm.example.test", "jarm.example.test")}})
	fp, err := JARMFingerprint(context.Background(), target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if fp == "" {
		return // server declined a probe: best-effort empty is valid
	}
	if len(fp) != 62 {
		t.Fatalf("JARM length %d, want 62", len(fp))
	}
	for _, ch := range fp {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			t.Fatalf("JARM not lowercase hex: %q", fp)
		}
	}
}

func TestHTTPBannerLoopback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:8443")
	if err != nil {
		t.Skip("port 8443 unavailable")
	}
	cert := testCertificate(t, "banner.example.test", "banner.example.test")
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
				if err := tc.Handshake(); err != nil {
					return
				}
				reader := bufio.NewReader(tc)
				for {
					line, err := reader.ReadString('\n')
					if err != nil || line == "\r\n" || line == "\n" {
						break
					}
				}
				body := "<html><head><title>Hello Banner</title></head><body>x</body></html>"
				_, _ = fmt.Fprintf(tc, "HTTP/1.1 200 OK\r\nServer: fixture/1.0\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; wg.Wait() })
	target := Target{IP: "127.0.0.1", Port: 8443}
	o := fastOptions()
	o.HTTPBanner = true
	events, err := Collect(context.Background(), target, o)
	if err != nil || len(events) != 1 || events[0].Error != "" {
		t.Fatalf("banner collection failed: %+v (%v)", events, err)
	}
	banner := events[0].HTTPBanner
	if banner == nil || banner.Server != "fixture/1.0" || banner.Title != "Hello Banner" || banner.Status != 200 {
		t.Fatalf("bad banner: %+v", banner)
	}
}

func TestCancellationInterruptsPlaintextGreeting(t *testing.T) {
	target := fixtureServer(t, func(c net.Conn) { b := make([]byte, 1); _, _ = c.Read(b) })
	target.Mode = "smtp"
	o := fastOptions()
	o.Timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _ = Collect(ctx, target, o)
	if time.Since(start) > 300*time.Millisecond {
		t.Fatal("cancellation waited for protocol deadline")
	}
}
