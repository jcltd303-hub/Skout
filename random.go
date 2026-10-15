package ip4scout

import (
	"encoding/json"
	"fmt"
	"github.com/LeakIX/gopacket/routing"
	"github.com/LeakIX/ip4scout/portprofiles"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mostlygeek/arp"
	"go.uber.org/ratelimit"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
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
	ports              []layers.TCPPort `kong:"-"`
	exclusions         *exclusionSet    `kong:"-"`
}

func (cmd *RandomCommand) Run() (err error) {
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
	rand.Seed(time.Now().UnixNano())
	if cmd.SourcePort == 0 {
		cmd.SourcePort = layers.TCPPort(rand.Int()%29000) + 1000
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
		log.Fatal(err)
	}
	iface, gw, src, err := router.Route(net.IP{1, 1, 1, 1})
	if err != nil {
		log.Fatal(err)
	}

	// Open main interface handle for packets r/w
	handle, err := pcap.OpenLive(iface.Name, 1024*256, true, 100*time.Nanosecond)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	// Define our BPFFilter to listen for ACK/SYN
	err = handle.SetBPFFilter(fmt.Sprintf("ip and port %d", cmd.SourcePort))
	if err != nil {
		log.Fatal(err)
	}
	// Start the listening thread
	go cmd.ListenForAck(handle)
	// Compute mac for our gateway
	gwMac, err := net.ParseMAC(arp.Search(gw.To4().String()))
	if err != nil {
		log.Fatal(err)
	}
	rl := ratelimit.New(cmd.RateLimit, ratelimit.WithoutSlack)
	var portToScan layers.TCPPort
	for {
		rl.Take()
		portToScan = cmd.ports[rand.Int()%len(cmd.ports)]
		if portToScan == 0 {
			portToScan = layers.TCPPort((rand.Int() % 9000) + 1000)
		}
		cmd.SendPacket(handle, iface, src, gwMac, cmd.RandomPublicIp(), portToScan)
	}
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

// I just listen for SYN/ACK on port 16655 and print things
func (cmd *RandomCommand) ListenForAck(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Println("Listening!")
	jsonEncoder := json.NewEncoder(os.Stdout)
	for packet := range packetSource.Packets() {
		if event := synAckEvent(packet, cmd.SourcePort); event != nil && cmd.IsIpPublic(net.ParseIP(event.Ip)) {
			err := jsonEncoder.Encode(event)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (cmd *RandomCommand) RandomPublicIp() net.IP {
	if cmd.exclusions == nil {
		if err := cmd.prepareBlacklist(); err != nil {
			panic(err)
		}
	}
	rank := uint64(rand.Int63n(int64(cmd.exclusions.available)))
	return cmd.exclusions.addressAt(rank)
}

func (cmd *RandomCommand) AddBLockToBlacklist(network string) {
	_, net, err := net.ParseCIDR(network)
	if err != nil {
		log.Fatal("Error adding to bl")
	}
	IPBlacklist = append(IPBlacklist, net)
}

func (cmd *RandomCommand) IsIpPublic(ip net.IP) bool {
	if ip.To4() == nil {
		return false
	}
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

func (cmd *RandomCommand) SendPacket(handle *pcap.Handle, iface *net.Interface, src net.IP, gwMac net.HardwareAddr, ip net.IP, dport layers.TCPPort) {
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
	err := tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		log.Fatal(err)
	}
	err = gopacket.SerializeLayers(buff, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, &eth, &ip4, &tcp)
	if err != nil {
		log.Fatal(err)
	}
	err = handle.WritePacketData(buff.Bytes())
	if err != nil {
		log.Printf("Failed sending packet for %s:%d sleeping 10 secs and resuming ...", ip.String(), dport)
		time.Sleep(10 * time.Second)
	}
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
