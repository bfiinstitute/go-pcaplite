package pcaplite

import (
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildPacket(t *testing.T, layersList ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, opts, layersList...); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestPacketStruct(t *testing.T) {
	now := time.Now()
	p := Packet{
		Timestamp:   now,
		SrcIP:       "192.168.0.1",
		DstIP:       "192.168.0.2",
		SrcMAC:      "aa:bb:cc:dd:ee:ff",
		DstMAC:      "ff:ee:dd:cc:bb:aa",
		Protocol:    "TCP",
		SrcPort:     "443",
		DstPort:     "12345",
		Length:      1500,
		PayloadSize: 1400,
		Extra:       map[string]string{"info": "test"},
	}
	if p.Timestamp != now {
		t.Errorf("Timestamp mismatch: got %v, want %v", p.Timestamp, now)
	}
	if p.Extra["info"] != "test" {
		t.Errorf("Extra map mismatch, got %v", p.Extra)
	}
}

func TestParsePacket_VariousProtocols(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		layers    []gopacket.SerializableLayer
		wantProto string
		wantExtra string
	}{
		{
			name: "TCP Packet",
			layers: []gopacket.SerializableLayer{
				&layers.Ethernet{SrcMAC: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, DstMAC: []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}, EthernetType: layers.EthernetTypeIPv4},
				&layers.IPv4{SrcIP: []byte{192, 168, 0, 1}, DstIP: []byte{192, 168, 0, 2}, Protocol: layers.IPProtocolTCP},
				func() *layers.TCP {
					tcp := &layers.TCP{SrcPort: 1234, DstPort: 80}
					tcp.SetNetworkLayerForChecksum(&layers.IPv4{SrcIP: []byte{192, 168, 0, 1}, DstIP: []byte{192, 168, 0, 2}})
					return tcp
				}(),
			},
			wantProto: "TCP",
		},
		{
			name: "UDP Packet",
			layers: []gopacket.SerializableLayer{
				&layers.Ethernet{SrcMAC: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, DstMAC: []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}, EthernetType: layers.EthernetTypeIPv4},
				&layers.IPv4{SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}, Protocol: layers.IPProtocolUDP},
				func() *layers.UDP {
					udp := &layers.UDP{SrcPort: 53, DstPort: 33333}
					udp.SetNetworkLayerForChecksum(&layers.IPv4{SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}})
					return udp
				}(),
			},
			wantProto: "UDP",
		},
		{
			name: "ARP Packet",
			layers: []gopacket.SerializableLayer{
				&layers.Ethernet{SrcMAC: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, DstMAC: []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}, EthernetType: layers.EthernetTypeARP},
				&layers.ARP{SourceProtAddress: []byte{192, 168, 1, 1}, DstProtAddress: []byte{192, 168, 1, 2}},
			},
			wantProto: "ARP",
			wantExtra: "ARP_SourceIP",
		},
		{
			name: "ICMPv4 Packet",
			layers: []gopacket.SerializableLayer{
				&layers.Ethernet{SrcMAC: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, DstMAC: []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}, EthernetType: layers.EthernetTypeIPv4},
				&layers.IPv4{SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}, Protocol: layers.IPProtocolICMPv4},
				&layers.ICMPv4{TypeCode: layers.ICMPv4TypeEchoRequest},
			},
			wantProto: "ICMPv4",
		},
		{
			name: "DNS Packet",
			layers: []gopacket.SerializableLayer{
				&layers.Ethernet{SrcMAC: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, DstMAC: []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}, EthernetType: layers.EthernetTypeIPv4},
				&layers.IPv4{SrcIP: []byte{8, 8, 8, 8}, DstIP: []byte{1, 1, 1, 1}, Protocol: layers.IPProtocolUDP},
				func() *layers.UDP {
					udp := &layers.UDP{SrcPort: 53, DstPort: 5353}
					udp.SetNetworkLayerForChecksum(&layers.IPv4{SrcIP: []byte{8, 8, 8, 8}, DstIP: []byte{1, 1, 1, 1}})
					return udp
				}(),
				&layers.DNS{Questions: []layers.DNSQuestion{{Name: []byte("example.com")}}},
			},
			wantProto: "DNS",
			wantExtra: "DNS_Query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := buildPacket(t, tt.layers...)
			pkt.Metadata().Timestamp = now
			parsed := parsePacket(pkt)
			if parsed.Protocol != tt.wantProto {
				t.Errorf("expected protocol %s, got %s", tt.wantProto, parsed.Protocol)
			}
			if tt.wantExtra != "" {
				if _, ok := parsed.Extra[tt.wantExtra]; !ok {
					t.Errorf("expected extra field %q, not found", tt.wantExtra)
				}
			}
		})
	}
}

func TestNetIP(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte{192, 168, 0, 1}, "192.168.0.1"},
		{[]byte{8, 8, 8, 8}, "8.8.8.8"},
	}
	for _, tt := range tests {
		if got := netIP(tt.input); got != tt.expected {
			t.Errorf("netIP(%v) = %v; want %v", tt.input, got, tt.expected)
		}
	}
}
