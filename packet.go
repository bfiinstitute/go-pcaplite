package pcaplite

import "time"

// Packet - main data
type Packet struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	SrcMAC      string
	DstMAC      string
	Protocol    string
	SrcPort     string
	DstPort     string
	Length      int
	PayloadSize int
	Extra       map[string]string
}
