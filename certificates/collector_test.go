package certificates

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
		case "smtp":
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
