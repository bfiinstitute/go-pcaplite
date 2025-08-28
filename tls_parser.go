package pcaplite

import (
	"encoding/binary"
)

// ExtractSNI take SNI in TLS ClientHello
func extractSNI(payload []byte) string {
	if len(payload) < 5 {
		return ""
	}

	// Check TLS Handshake
	if payload[0] != 0x16 { // TLS Handshake Content Type
		return ""
	}

	// Min version check TLS
	if payload[1] != 0x03 {
		return ""
	}

	// Skip TLS record header (5 byte)
	handshake := payload[5:]
	if len(handshake) < 4 || handshake[0] != 0x01 { // ClientHello
		return ""
	}

	// Read lenght Handshake
	handshakeLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+handshakeLen {
		return ""
	}

	// Skip 4 byte header
	data := handshake[4:]

	// Skip version and Random (2 + 32)
	if len(data) < 34 {
		return ""
	}
	data = data[34:]

	// Session ID
	if len(data) < 1 {
		return ""
	}
	sessionIDLen := int(data[0])
	data = data[1:]
	if len(data) < sessionIDLen {
		return ""
	}
	data = data[sessionIDLen:]

	// Cipher Suites
	if len(data) < 2 {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < csLen {
		return ""
	}
	data = data[csLen:]

	// Compression
	if len(data) < 1 {
		return ""
	}
	compLen := int(data[0])
	data = data[1:]
	if len(data) < compLen {
		return ""
	}
	data = data[compLen:]

	// Extensions
	if len(data) < 2 {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < extLen {
		return ""
	}

	// Looking for SNI (0x00 0x00)
	for len(data) >= 4 {
		extType := binary.BigEndian.Uint16(data[:2])
		extDataLen := int(binary.BigEndian.Uint16(data[2:4]))
		data = data[4:]
		if len(data) < extDataLen {
			return ""
		}
		if extType == 0x00 { // SNI
			sniData := data[:extDataLen]
			// Skip list
			if len(sniData) < 5 {
				return ""
			}
			nameLen := int(binary.BigEndian.Uint16(sniData[3:5]))
			if len(sniData) < 5+nameLen {
				return ""
			}
			return string(sniData[5 : 5+nameLen])
		}
		data = data[extDataLen:]
	}

	return ""
}
