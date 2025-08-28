package main

import (
	"fmt"
	"log"

	"github.com/alexcfv/go-pcaplite"
)

func main() {
	opts := pcaplite.CaptureOptions{
		Filter:  "tcp and port 443", // only HTTPS
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
	}
}
