package pcaplite

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type CaptureOptions struct {
	Filter    string
	SnapLen   int32
	Promisc   bool
	TimeoutMs int
}

func Capture(iface string, opts CaptureOptions) (<-chan Packet, error) {
	if opts.SnapLen == 0 {
		opts.SnapLen = 65535
	}
	if opts.TimeoutMs == 0 {
		opts.TimeoutMs = 1000
	}

	handle, err := pcap.OpenLive(iface, opts.SnapLen, opts.Promisc, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("interface error: %w", err)
	}

	if opts.Filter != "" {
		if err := handle.SetBPFFilter(opts.Filter); err != nil {
			return nil, fmt.Errorf("аfilter error: %w", err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	out := make(chan Packet)

	go func() {
		defer handle.Close()
		defer close(out)
		for packet := range packetSource.Packets() {
			out <- parsePacket(packet)
		}
	}()

	return out, nil
}
