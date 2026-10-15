package ip4scout

import (
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func fixturePacket(t *testing.T, tcp *layers.TCP) gopacket.Packet {
	return fixturePacketWithSource(t, tcp, net.IPv4(192, 0, 2, 10))
}

func fixturePacketWithSource(t *testing.T, tcp *layers.TCP, source net.IP) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: source, DstIP: net.IPv4(192, 0, 2, 1), Protocol: layers.IPProtocolTCP}
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

func TestListenerDoesNotEmitExcludedEndpoints(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "replies-*.pcap")
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeRaw); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"153.11.1.1", "8.12.164.255", "8.8.8.8"} {
		packet := fixturePacketWithSource(t, &layers.TCP{SrcPort: 443, DstPort: 16655, SYN: true, ACK: true, Ack: 1}, net.ParseIP(source))
		data := packet.Data()
		if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(data), Length: len(data)}, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	handle, err := pcap.OpenOffline(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	output, err := os.CreateTemp(t.TempDir(), "endpoints-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	original := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = original }()
	cmd := RandomCommand{SourcePort: 16655}
	cmd.ListenForAck(handle)
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(output)
	var event struct {
		IP string `json:"ip"`
	}
	if err := decoder.Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.IP != "8.8.8.8" {
		t.Fatalf("emitted excluded endpoint %s", event.IP)
	}
	if err := decoder.Decode(&event); err != io.EOF {
		t.Fatalf("unexpected extra endpoint: %+v (%v)", event, err)
	}
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
