package pcaplite

import (
	"fmt"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// CaptureOptions - sniffer options
type CaptureOptions struct {
	Filter    string // BPF filter (example: "tcp and port 80")
	SnapLen   int32  // Max package weight
	Promisc   bool   // Listennig mode
	TimeoutMs int    // Timeout ms
}

// Capture - start listenig interface
func Capture(iface string, opts CaptureOptions) (<-chan Packet, error) {
	if opts.SnapLen == 0 {
		opts.SnapLen = 65535
	}
	if opts.TimeoutMs == 0 {
		opts.TimeoutMs = 1000
	}

	handle, err := pcap.OpenLive(iface, opts.SnapLen, opts.Promisc, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("error opening interface: %w", err)
	}

	if opts.Filter != "" {
		if err := handle.SetBPFFilter(opts.Filter); err != nil {
			return nil, fmt.Errorf("error filter: %w", err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	out := make(chan Packet)

	go func() {
		defer handle.Close()
		defer close(out)
		for packet := range packetSource.Packets() {
			netLayer := packet.NetworkLayer()
			transLayer := packet.TransportLayer()

			p := Packet{
				Timestamp: packet.Metadata().Timestamp,
				Length:    len(packet.Data()),
			}

			if netLayer != nil {
				src, dst := netLayer.NetworkFlow().Endpoints()
				p.SrcIP = src.String()
				p.DstIP = dst.String()
				p.Protocol = netLayer.LayerType().String()
			}

			if tcp, ok := transLayer.(*layers.TCP); ok {
				p.SrcPort = strconv.Itoa(int(tcp.SrcPort))
				p.DstPort = strconv.Itoa(int(tcp.DstPort))
				p.PayloadSize = len(tcp.Payload)
			} else if udp, ok := transLayer.(*layers.UDP); ok {
				p.SrcPort = strconv.Itoa(int(udp.SrcPort))
				p.DstPort = strconv.Itoa(int(udp.DstPort))
				p.PayloadSize = len(udp.Payload)
			}

			out <- p
		}
	}()

	return out, nil
}
