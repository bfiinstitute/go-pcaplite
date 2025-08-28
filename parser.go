package pcaplite

import (
	"fmt"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parsePacket - processes packet
func parsePacket(packet gopacket.Packet) Packet {
	p := Packet{
		Timestamp: packet.Metadata().Timestamp,
		Length:    len(packet.Data()),
		Extra:     make(map[string]string),
	}

	// Ethernet
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		p.SrcMAC = eth.SrcMAC.String()
		p.DstMAC = eth.DstMAC.String()
	}

	// IP
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		src, dst := netLayer.NetworkFlow().Endpoints()
		p.SrcIP = src.String()
		p.DstIP = dst.String()
		p.Protocol = netLayer.LayerType().String()
	}

	// Transport
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		p.SrcPort = strconv.Itoa(int(tcp.SrcPort))
		p.DstPort = strconv.Itoa(int(tcp.DstPort))
		p.PayloadSize = len(tcp.Payload)
		p.Protocol = "TCP"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		p.SrcPort = strconv.Itoa(int(udp.SrcPort))
		p.DstPort = strconv.Itoa(int(udp.DstPort))
		p.PayloadSize = len(udp.Payload)
		p.Protocol = "UDP"
	}

	// ARP
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		p.Protocol = "ARP"
		p.Extra["ARP_SourceIP"] = fmt.Sprintf("%v", netIP(arp.SourceProtAddress))
		p.Extra["ARP_DestIP"] = fmt.Sprintf("%v", netIP(arp.DstProtAddress))
	}

	// ICMP
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		p.Protocol = "ICMPv4"
	}
	if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		p.Protocol = "ICMPv6"
	}

	// DNS
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		p.Protocol = "DNS"
		if len(dns.Questions) > 0 {
			p.Extra["DNS_Query"] = string(dns.Questions[0].Name)
		}
	}

	return p
}

// netIP - ]byte to IP
func netIP(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}
