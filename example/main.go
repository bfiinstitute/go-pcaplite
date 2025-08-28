package main

import (
	"fmt"
	"log"

	"github.com/alexcfv/go-pcaplite"
)

func main() {
	opts := pcaplite.CaptureOptions{
		Filter:  "ip", // all IP traffic
		Promisc: true,
	}

	packets, err := pcaplite.Capture("en0", opts)
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
