package ip4scout

import (
	"github.com/LeakIX/l9format"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strconv"
	"time"
)

func synAckEvent(packet gopacket.Packet, sourcePort layers.TCPPort) *l9format.L9Event {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if tcpLayer == nil || ipLayer == nil {
		return nil
	}
	tcp := tcpLayer.(*layers.TCP)
	if !tcp.SYN || !tcp.ACK || tcp.RST || tcp.DstPort != sourcePort || tcp.Ack != 1 || tcp.SrcPort == 0 {
		return nil
	}
	event := &l9format.L9Event{EventType: "synack", Ip: ipLayer.(*layers.IPv4).SrcIP.String(), Port: strconv.Itoa(int(tcp.SrcPort)), Time: time.Now()}
	event.AddSource("ip4scout")
	return event
}
