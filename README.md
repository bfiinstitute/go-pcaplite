# 🕵️‍♂️ go-pcaplite – Lightweight Network Sniffer in Go

[![Go Reference](https://pkg.go.dev/badge/github.com/alexcfv/go-pcaplite.svg)](https://pkg.go.dev/github.com/alexcfv/go-pcaplite)
[![Go Report Card](https://goreportcard.com/badge/github.com/alexcfv/go-pcaplite)](https://goreportcard.com/report/github.com/alexcfv/go-pcaplite)
[![codecov](https://codecov.io/github/alexcfv/go-pcaplite/graph/badge.svg?token=ZHZMTJI4D7)](https://codecov.io/github/alexcfv/go-pcaplite)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-blue)
![Go Version](https://img.shields.io/github/go-mod/go-version/alexcfv/go-pcaplite)

---

## 🚀 Overview

`go-pcaplite` is a **lightweight Go library** for capturing and inspecting network traffic in real time.  
It wraps `gopacket` and simplifies packet sniffing with an easy-to-use API.  

---

## 🔥 Features

- 📡 **Live packet capture** from any interface  
- 🔍 Supports **BPF filters** (tcp, udp, icmp, arp, etc.)  
- 📝 Extracts **protocol metadata** (DNS, ARP, etc.)  
- 🖥️ Cross-platform: Linux, macOS, Windows  
- ⚡ Designed for simplicity and integration into other tools  

---

## 🛠️ Installation

```bash
go get github.com/alexcfv/go-pcaplite
```

---

## 🔑 Running on Different Operating Systems

| OS          | How to run                                                            |
| ----------- | --------------------------------------------------------------------- |
| **Linux**   | `sudo go run main.go`                                                 |
| **macOS**   | `sudo go run main.go` (or allow permissions in Security settings)     |
| **Windows** | Run as Administrator                                                  |

---

## 🌐 Common Network Interfaces

| OS          | Typical Interfaces                               |
| ----------- | ------------------------------------------------ |
| **Linux**   | `eth0`, `wlan0`, `lo`, `enp3s0`, `docker0`       |
| **macOS**   | `en0`, `en1`, `lo0`, `bridge0`, `utun0`          |
| **Windows** | `Ethernet`, `Wi-Fi`, `Loopback Pseudo-Interface` |

---

## 🔍 Example Filters (BPF Syntax)

| Filter                | Description                    |
| --------------------- | ------------------------------ |
| `tcp`                 | Capture only TCP packets       |
| `udp`                 | Capture only UDP packets       |
| `icmp`                | Capture ICMP (ping) traffic    |
| `arp`                 | Capture ARP requests/responses |
| `tcp port 443`        | Capture HTTPS traffic          |
| `udp or icmp`         | Capture UDP + ICMP packets     |
| `tcp and dst port 22` | Capture packets going to SSH   |

---

## 📦 Example

```golang
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

    packets, err := pcaplite.Capture("en0", opts) //en0 macOS interface
    if err != nil {
        log.Fatal(err)
    }

    for p := range packets {
        fmt.Printf("[%s] %s:%s -> %s:%s | %s | %d bytes\n",
            p.Timestamp.Format("15:04:05"),
            p.SrcIP, p.SrcPort,
            p.DstIP, p.DstPort,
            p.Protocol, p.Length,
        )

        // Print additional metadata (DNS, ARP, etc.)
        for k, v := range p.Extra {
            fmt.Printf("  %s: %s\n", k, v)
        }
    }
}
```

---

## 📦 Output:

```bash
[21:09:29] 192.168.0.30:49380 -> 17.248.213.71:443 | TCP | 66 bytes
[21:09:29] 17.248.213.71:443 -> 192.168.0.30:49380 | TCP | 78 bytes
[21:09:29] 17.248.213.71:443 -> 192.168.0.30:49380 | TCP | 66 bytes
[21:09:29] 17.248.213.71:443 -> 192.168.0.30:49380 | TCP | 66 bytes
[21:09:29] 192.168.0.30:49380 -> 17.248.213.71:443 | TCP | 90 bytes
[21:09:29] 192.168.0.30:49380 -> 17.248.213.71:443 | TCP | 66 bytes
[21:09:29] 17.248.213.71:443 -> 192.168.0.30:49380 | TCP | 78 bytes
[21:09:29] 192.168.0.30:49380 -> 17.248.213.71:443 | TCP | 54 bytes
[21:09:31] 192.168.0.31:5353 -> 224.0.0.251:5353 | UDP | 119 bytes
[21:09:31] fe80::8001:51ff:fe3b:55ce:5353 -> ff02::fb:5353 | UDP | 139 bytes
```

---

## ⚙️ Packet structure:

```golang
type Packet struct {
    Timestamp   time.Time          // The exact time when the packet was captured
    SrcIP       string             // Source IP address of the packet
    DstIP       string             // Destination IP address of the packet
    SrcMAC      string             // Source MAC address of the packet
    DstMAC      string             // Destination MAC address of the packet
    Protocol    string             // Network protocol used (e.g., TCP, UDP, ICMP)
    SrcPort     string             // Source port number (if applicable, e.g., TCP/UDP)
    DstPort     string             // Destination port number (if applicable, e.g., TCP/UDP)
    Length      int                // Total length of the entire packet in bytes
    PayloadSize int                // Size of the actual payload (data) in bytes
    Extra       map[string]string  // Additional parsed information or metadata
}
```

---

## ✍️ From the Author

Hi! I’m the author of **go-pcaplite**.  

I also have a **CLI utility** for deeper traffic analysis.  
You can check it out here: [CLI sniffer](https://github.com/alexcfv/go-sniffer)

---

## 📜 License  
MIT © 2025 [alexcfv](https://github.com/alexcfv)
