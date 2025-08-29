package main

import (
	"fmt"
	"log"

	"github.com/alexcfv/go-pcaplite"
)

func main() {
	opts := pcaplite.CaptureOptions{
		Filter:  "tcp port 443 or udp or arp or icmp", // HTTPS + other protocols
		Promisc: true,
	}

	packets, err := pcaplite.Capture("eth0", opts) // For linux only
	if err != nil {
		log.Fatal(err)
	}

	for p := range packets {
		fmt.Printf("[%s] %s:%s -> %s:%s | %s | %d bytes\n",
			p.Timestamp.Format("15:04:05"),
			p.SrcIP, p.SrcPort,
			p.DstIP, p.DstPort,
			p.Protocol, p.Length)

		// print DNS or ARP inf
		for k, v := range p.Extra {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}
}
