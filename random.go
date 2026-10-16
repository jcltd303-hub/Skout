package ip4scout

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	mathrand "math/rand"

	"github.com/LeakIX/gopacket/routing"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jcltd303-hub/Skout/portprofiles"
	"github.com/mostlygeek/arp"
	"go.uber.org/ratelimit"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

type RandomCommand struct {
	BlacklistFile      *os.File         `help:"Additional exclusions: IPv4, CIDR, or inclusive IPv4 ranges" short:"b" type:"existingFile"`
	ExcludeFile        *os.File         `name:"excludefile" help:"Additional masscan-format exclusion file" type:"existingFile"`
	SourcePort         layers.TCPPort   `help:"Source port, default is random" default:"0" short:"s"`
	Ports              string           `help:"list of target ports" short:"p"`
	PortProfile        string           `default:"exposure20" help:"Port profile: exposure20 or certificates; explicit --ports overrides selection"`
	ListPorts          bool             `help:"Print selected ports and exit before network setup"`
	RateLimit          int              `help:"Max pps" short:"r" default:"1000"`
	DisableRecommended bool             `help:"Disable bundled masscan exclusions (private/multicast exclusions remain)" short:"d"`
	CertificateProfile bool             `help:"Use certificate ports (443,587,21,465,993,995,8443) when --ports is omitted"`
	Seed               int64            `help:"RNG seed; 0 seeds from crypto/rand" default:"0"`
	Count              int              `help:"Send exactly this many packets, then exit; 0 scans forever (legacy)" default:"0"`
	WaitAfterSeconds   int              `help:"Seconds to wait after sending --count packets for SYN/ACK replies before exiting" name:"wait-after" default:"5"`
	Distinct           bool             `help:"With --count, resample until all target IPs are distinct" default:"true"`
	IPv6               bool             `name:"ipv6" help:"Generate IPv6 targets (RandomPublicIp returns v6 addresses); packet emission stays IPv4-framed, so v6 targets are skipped at send time" default:"false"`
	ports              []layers.TCPPort `kong:"-"`
	exclusions         *exclusionSet    `kong:"-"`
	rng                *mathrand.Rand   `kong:"-"`
	rngMu              sync.Mutex       `kong:"-"`
}

func (cmd *RandomCommand) Run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return cmd.RunContext(ctx)
}

// RunContext sends SYN probes until ctx is cancelled (legacy infinite mode)
// or until exactly Count packets have been attempted (finite mode).
func (cmd *RandomCommand) RunContext(ctx context.Context) error {
	if err := cmd.preparePorts(); err != nil {
		return err
	}
	if cmd.ListPorts {
		ports := make([]string, len(cmd.ports))
		for i, p := range cmd.ports {
			ports[i] = strconv.Itoa(int(p))
		}
		fmt.Println(strings.Join(ports, ","))
		return nil
	}
	if cmd.RateLimit < 1 {
		return fmt.Errorf("rate-limit must be positive")
	}
	if cmd.Count < 0 {
		return fmt.Errorf("count must be non-negative")
	}
	if cmd.WaitAfterSeconds < 0 {
		return fmt.Errorf("wait-after must be non-negative")
	}
	if len(cmd.ports) == 0 {
		return fmt.Errorf("no ports to scan")
	}
	cmd.ensureRNG()
	if cmd.SourcePort == 0 {
		cmd.SourcePort = layers.TCPPort(cmd.randIntN(29000)) + 1000
	}
	if err := cmd.prepareBlacklist(); err != nil {
		return err
	}
	for _, file := range []*os.File{cmd.BlacklistFile, cmd.ExcludeFile} {
		if file != nil {
			log.Printf("Loaded blacklist from %s", file.Name())
		}
	}
	log.Printf("%d merged exclusion ranges loaded (masscan default: %t)", len(cmd.exclusions.ranges), !cmd.DisableRecommended)
	log.Printf("Loaded %d ports to scan", len(cmd.ports))
	log.Printf("Using source port %d", cmd.SourcePort)
	// Compute routing settings for public packets
	router, err := routing.New()
	if err != nil {
		return err
	}
	iface, gw, src, err := router.Route(net.IP{1, 1, 1, 1})
	if err != nil {
		return err
	}

	// Open main interface handle for packets r/w
	handle, err := pcap.OpenLive(iface.Name, 1024*256, true, 100*time.Nanosecond)
	if err != nil {
		return fmt.Errorf("opening capture device for SYN scan: %w (SYN scan needs root/CAP_NET_RAW; without root use: python3 tools/random_targets.py | ./certscout service ...)", err)
	}
	defer handle.Close()
	// Define our BPFFilter to listen for ACK/SYN
	err = handle.SetBPFFilter(fmt.Sprintf("ip and port %d", cmd.SourcePort))
	if err != nil {
		return err
	}
	// Start the listening thread
	errCh := make(chan error, 1)
	go cmd.ListenForAck(handle, ctx, errCh)
	// Compute mac for our gateway
	gwMac, err := net.ParseMAC(arp.Search(gw.To4().String()))
	if err != nil {
		return err
	}
	rl := ratelimit.New(cmd.RateLimit, ratelimit.WithoutSlack)

	if cmd.Count > 0 {
		ips, err := cmd.RandomPublicIPs(cmd.Count)
		if err != nil {
			return err
		}
		consecutiveFailures := 0
		for _, ip := range ips {
			if err := ctx.Err(); err != nil {
				return err
			}
			rl.Take()
			port := cmd.pickPort()
			if err := cmd.SendPacket(handle, iface, src, gwMac, ip, port); err != nil {
				log.Printf("Failed sending packet for %s:%d: %v", ip.String(), port, err)
				consecutiveFailures++
				if consecutiveFailures >= 100 {
					return fmt.Errorf("too many consecutive send failures: %w", err)
				}
				continue
			}
			consecutiveFailures = 0
		}
		// Wait for SYN/ACK replies before exiting. Previously this
		// returned immediately after sending, so the listener
		// goroutine was killed before any reply could arrive and
		// --count scans always produced zero results.
		log.Printf("Waiting %ds for SYN/ACK replies...", cmd.WaitAfterSeconds)
		return waitForReplies(ctx, errCh, time.Duration(cmd.WaitAfterSeconds)*time.Second)
	}

	consecutiveFailures := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		rl.Take()
		port := cmd.pickPort()
		ip, err := cmd.RandomPublicIp()
		if err != nil {
			return err
		}
		if err := cmd.SendPacket(handle, iface, src, gwMac, ip, port); err != nil {
			log.Printf("Failed sending packet for %s:%d: %v", ip.String(), port, err)
			consecutiveFailures++
			if consecutiveFailures >= 100 {
				return fmt.Errorf("too many consecutive send failures: %w", err)
			}
			continue
		}
		consecutiveFailures = 0
	}
}

// waitForReplies blocks until the grace period elapses, ctx is cancelled,
// or the listener reports an error. A zero grace period checks errCh once
// without waiting, preserving the old fast-exit behaviour for callers that
// explicitly opt out with --wait-after 0.
func waitForReplies(ctx context.Context, errCh <-chan error, wait time.Duration) error {
	if wait <= 0 {
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (cmd *RandomCommand) pickPort() layers.TCPPort {
	port := cmd.ports[cmd.randIntN(len(cmd.ports))]
	if port == 0 {
		port = layers.TCPPort(cmd.randIntN(9000) + 1000)
	}
	return port
}

// ensureRNG initializes the instance RNG once. A nonzero Seed makes the
// sequence deterministic; a zero Seed draws entropy from crypto/rand.
func (cmd *RandomCommand) ensureRNG() {
	if cmd.rng != nil {
		return
	}
	var seed int64
	if cmd.Seed != 0 {
		seed = cmd.Seed
	} else {
		var entropy [8]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			seed = time.Now().UnixNano()
		} else {
			seed = int64(binary.LittleEndian.Uint64(entropy[:]))
		}
	}
	cmd.rng = mathrand.New(mathrand.NewSource(seed))
}

func (cmd *RandomCommand) randIntN(n int) int {
	cmd.rngMu.Lock()
	defer cmd.rngMu.Unlock()
	cmd.ensureRNG()
	return cmd.rng.Intn(n)
}

func (cmd *RandomCommand) randInt63n(n int64) int64 {
	cmd.rngMu.Lock()
	defer cmd.rngMu.Unlock()
	cmd.ensureRNG()
	return cmd.rng.Int63n(n)
}

func (cmd *RandomCommand) randBig(n *big.Int) *big.Int {
	cmd.rngMu.Lock()
	defer cmd.rngMu.Unlock()
	cmd.ensureRNG()
	var buf [16]byte
	_, _ = cmd.rng.Read(buf[:])
	value := new(big.Int).SetBytes(buf[:])
	return value.Mod(value, n)
}

func (cmd *RandomCommand) preparePorts() error {
	ports, err := portprofiles.Ports(cmd.PortProfile)
	if err != nil {
		return err
	}
	if cmd.CertificateProfile {
		ports, _ = portprofiles.Ports("certificates")
	}
	if cmd.Ports != "" {
		cmd.ports, err = ParsePortsList(cmd.Ports)
		return err
	}
	cmd.ports = make([]layers.TCPPort, len(ports))
	for i, port := range ports {
		cmd.ports[i] = layers.TCPPort(port)
	}
	return nil
}

// ListenForAck prints SYN/ACK discoveries as JSON until ctx is cancelled or
// the packet source closes. Encode errors go to errCh (buffered, non-blocking)
// and never panic.
func (cmd *RandomCommand) ListenForAck(handle *pcap.Handle, ctx context.Context, errCh chan<- error) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Println("Listening!")
	jsonEncoder := json.NewEncoder(os.Stdout)
	packets := packetSource.Packets()
	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			if event := synAckEvent(packet, cmd.SourcePort); event != nil && cmd.IsIpPublic(net.ParseIP(event.Ip)) {
				if err := jsonEncoder.Encode(event); err != nil {
					if errCh != nil {
						select {
						case errCh <- err:
						default:
						}
					}
				}
			}
		}
	}
}

func (cmd *RandomCommand) RandomPublicIp() (net.IP, error) {
	if cmd.exclusions == nil {
		if err := cmd.prepareBlacklist(); err != nil {
			return nil, err
		}
	}
	if cmd.IPv6 {
		rank := cmd.randBig(cmd.exclusions.availableV6)
		return cmd.exclusions.addressAtV6(rank), nil
	}
	rank := uint64(cmd.randInt63n(int64(cmd.exclusions.available)))
	return cmd.exclusions.addressAt(rank), nil
}

// RandomPublicIPs returns n sampled target addresses. When Distinct is set it
// resamples until all n are distinct, giving up after 100*n attempts.
func (cmd *RandomCommand) RandomPublicIPs(n int) ([]net.IP, error) {
	if n < 0 {
		return nil, fmt.Errorf("count must be non-negative")
	}
	if n == 0 {
		return []net.IP{}, nil
	}
	out := make([]net.IP, 0, n)
	if !cmd.Distinct {
		for i := 0; i < n; i++ {
			ip, err := cmd.RandomPublicIp()
			if err != nil {
				return nil, err
			}
			out = append(out, ip)
		}
		return out, nil
	}
	seen := make(map[string]bool, n)
	for attempts := 0; len(out) < n; attempts++ {
		if attempts >= 100*n {
			return nil, fmt.Errorf("could not sample %d distinct addresses after %d attempts", n, attempts)
		}
		ip, err := cmd.RandomPublicIp()
		if err != nil {
			return nil, err
		}
		if seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}
	return out, nil
}

func (cmd *RandomCommand) AddBLockToBlacklist(network string) error {
	_, parsed, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf("adding to blacklist: %w", err)
	}
	IPBlacklist = append(IPBlacklist, parsed)
	return nil
}

func (cmd *RandomCommand) IsIpPublic(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		for _, block := range IPBlacklist {
			if block != nil && block.Contains(ip) {
				return false
			}
		}
		if cmd.exclusions != nil {
			return !cmd.exclusions.contains(ip)
		}
		if !cmd.DisableRecommended {
			return masscanExclusionError == nil && !masscanExclusions.contains(ip)
		}
		return true
	}
	// IPv6: only considered when the IPv6 flag is set; the v4-only
	// IPBlacklist does not apply.
	if !cmd.IPv6 {
		return false
	}
	if ip.To16() == nil {
		return false
	}
	if cmd.exclusions != nil {
		return !cmd.exclusions.contains(ip)
	}
	return !mandatoryV6Exclusions.contains(ip)
}

func (cmd *RandomCommand) SendPacket(handle *pcap.Handle, iface *net.Interface, src net.IP, gwMac net.HardwareAddr, ip net.IP, dport layers.TCPPort) error {
	if ip.To4() == nil {
		return fmt.Errorf("IPv6 packet emission not implemented for %s", ip.String())
	}
	buff := gopacket.NewSerializeBuffer()
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       gwMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		Version:  4,
		TOS:      0,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    src,
		DstIP:    ip,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(cmd.SourcePort),
		DstPort: dport, // will be incremented during the scan
		SYN:     true,
	}
	if err := tcp.SetNetworkLayerForChecksum(&ip4); err != nil {
		return err
	}
	if err := gopacket.SerializeLayers(buff, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, &eth, &ip4, &tcp); err != nil {
		return err
	}
	if err := handle.WritePacketData(buff.Bytes()); err != nil {
		return fmt.Errorf("sending packet for %s:%d: %w", ip.String(), dport, err)
	}
	return nil
}

var IPBlacklist = []*net.IPNet{
	{
		IP:   net.IP{127, 0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{0, 0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{192, 168, 0, 0},
		Mask: net.IPMask{255, 255, 0, 0},
	},
	{
		IP:   net.IP{10, 0, 0, 0},
		Mask: net.IPMask{255, 0, 0, 0},
	},
	{
		IP:   net.IP{172, 16, 0, 0},
		Mask: net.IPMask{255, 240, 0, 0},
	},
	{
		IP:   net.IP{100, 64, 0, 0},
		Mask: net.IPMask{255, 192, 0, 0},
	},
	{
		IP:   net.IP{224, 0, 0, 0},
		Mask: net.IPMask{224, 0, 0, 0},
	},
}
