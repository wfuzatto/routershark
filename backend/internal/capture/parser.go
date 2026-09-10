package capture

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"routershark/backend/internal/model"
)

func ParseFrame(raw []byte, p *model.Packet) {
	packet := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	if ethL := packet.Layer(layers.LayerTypeEthernet); ethL != nil {
		eth := ethL.(*layers.Ethernet)
		p.SrcMAC, p.DstMAC = eth.SrcMAC.String(), eth.DstMAC.String()
		p.EtherType = eth.EthernetType.String()
	}
	if arpL := packet.Layer(layers.LayerTypeARP); arpL != nil {
		p.Protocol = "ARP"
		p.Info = "Address Resolution Protocol"
		return
	}
	if ip4L := packet.Layer(layers.LayerTypeIPv4); ip4L != nil {
		ip := ip4L.(*layers.IPv4)
		p.IPVersion, p.SrcIP, p.DstIP = 4, ip.SrcIP.String(), ip.DstIP.String()
		p.Protocol = strings.ToUpper(ip.Protocol.String())
	}
	if ip6L := packet.Layer(layers.LayerTypeIPv6); ip6L != nil {
		ip := ip6L.(*layers.IPv6)
		p.IPVersion, p.SrcIP, p.DstIP = 6, ip.SrcIP.String(), ip.DstIP.String()
		p.Protocol = strings.ToUpper(ip.NextHeader.String())
	}
	if tcpL := packet.Layer(layers.LayerTypeTCP); tcpL != nil {
		tcp := tcpL.(*layers.TCP)
		p.Protocol = "TCP"
		p.SrcPort, p.DstPort = int(tcp.SrcPort), int(tcp.DstPort)
		flags := make([]string, 0, 6)
		if tcp.SYN {
			flags = append(flags, "SYN")
		}
		if tcp.ACK {
			flags = append(flags, "ACK")
		}
		if tcp.FIN {
			flags = append(flags, "FIN")
		}
		if tcp.RST {
			flags = append(flags, "RST")
		}
		if tcp.PSH {
			flags = append(flags, "PSH")
		}
		if tcp.URG {
			flags = append(flags, "URG")
		}
		p.Info = fmt.Sprintf("%d → %d [%s] Seq=%d Ack=%d Len=%d", p.SrcPort, p.DstPort, strings.Join(flags, ","), tcp.Seq, tcp.Ack, len(tcp.Payload))
		return
	}
	if udpL := packet.Layer(layers.LayerTypeUDP); udpL != nil {
		udp := udpL.(*layers.UDP)
		p.Protocol = "UDP"
		p.SrcPort, p.DstPort = int(udp.SrcPort), int(udp.DstPort)
		p.Info = fmt.Sprintf("%d → %d Len=%d", p.SrcPort, p.DstPort, len(udp.Payload))
		return
	}
	if icmpL := packet.Layer(layers.LayerTypeICMPv4); icmpL != nil {
		p.Protocol = "ICMP"
		icmp := icmpL.(*layers.ICMPv4)
		p.Info = icmp.TypeCode.String()
		return
	}
	if icmp6L := packet.Layer(layers.LayerTypeICMPv6); icmp6L != nil {
		p.Protocol = "ICMPv6"
		icmp := icmp6L.(*layers.ICMPv6)
		p.Info = icmp.TypeCode.String()
		return
	}
	if p.Info == "" {
		p.Info = p.EtherType
	}
}
