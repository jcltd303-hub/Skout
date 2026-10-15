package ip4scout

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"testing"
)

func fixturePacket(t *testing.T, tcp *layers.TCP) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.IPv4(192, 0, 2, 10), DstIP: net.IPv4(192, 0, 2, 1), Protocol: layers.IPProtocolTCP}
	b := gopacket.NewSerializeBuffer()
	var err error
	if tcp == nil {
		ip.Protocol = layers.IPProtocolICMPv4
		err = gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true}, ip, gopacket.Payload([]byte{8, 0, 0, 0, 0, 0, 0, 0}))
	} else {
		_ = tcp.SetNetworkLayerForChecksum(ip)
		err = gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp)
	}
	if err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(b.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func TestSYNACKRequiresTCPAndExpectedFlags(t *testing.T) {
	good := &layers.TCP{SrcPort: 443, DstPort: 16655, SYN: true, ACK: true, Ack: 1}
	if got := synAckEvent(fixturePacket(t, good), 16655); got == nil || got.Port != "443" || got.Ip != "192.0.2.10" {
		t.Fatalf("missing genuine discovery: %+v", got)
	}
	if got := synAckEvent(fixturePacket(t, nil), 16655); got != nil {
		t.Fatalf("non-TCP became discovery: %+v", got)
	}
	for _, tcp := range []*layers.TCP{{SrcPort: 443, DstPort: 16655, ACK: true, Ack: 1}, {SrcPort: 443, DstPort: 16655, SYN: true, ACK: true, RST: true, Ack: 1}, {SrcPort: 443, DstPort: 16654, SYN: true, ACK: true, Ack: 1}} {
		if got := synAckEvent(fixturePacket(t, tcp), 16655); got != nil {
			t.Fatalf("invalid flags became discovery: %+v", got)
		}
	}
}
