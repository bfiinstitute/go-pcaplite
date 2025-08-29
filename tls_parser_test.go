package pcaplite

import (
	"encoding/hex"
	"testing"
)

// TestExtractSNI tests the extractSNI function with valid and invalid TLS payloads.
func TestExtractSNI(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "Too short payload",
			payload: "1603",
			want:    "",
		},
		{
			name:    "Invalid TLS type",
			payload: "1503010000",
			want:    "",
		},
		{
			name: "No SNI extension",
			payload: "16030100100100000c0303" +
				"00000000000000000000000000000000" + // Random 16 bytes
				"00" + // SessionID len
				"0002" + // Cipher Suites len
				"0000" + // Cipher Suite
				"01" + // Compression len
				"00" + // Compression method
				"0000", // Extensions len = 0
			want: "",
		},
		{
			name: "SNI too short",
			payload: "1603010027010000230303" +
				"0000000000000000000000000000000000000000000000000000000000000000" +
				"00" +
				"0002" +
				"0000" +
				"01" +
				"00" +
				"0006" +
				"0000" +
				"0001" + // Extension length too short
				"00",
			want: "",
		},
		{
			name: "Invalid extension type",
			payload: "1603010027010000230303" +
				"0000000000000000000000000000000000000000000000000000000000000000" +
				"00" +
				"0002" +
				"0000" +
				"01" +
				"00" +
				"0004" +
				"0011" + // unknown extension type
				"0000",
			want: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			data, err := hex.DecodeString(tt.payload)
			if err != nil {
				t.Fatalf("failed to decode payload: %v", err)
			}
			got := extractSNI(data)
			if got != tt.want {
				t.Errorf("extractSNI() = %q, want %q", got, tt.want)
			}
		})
	}
}
