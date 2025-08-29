package pcaplite

import (
	"os"
	"runtime"
	"testing"
)

func TestCapture_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		iface     string
		opts      CaptureOptions
		wantErr   bool
		expectNil bool
	}{
		{
			name:      "Invalid interface",
			iface:     "invalid_iface",
			opts:      CaptureOptions{},
			wantErr:   true,
			expectNil: true,
		},
		{
			name:      "Valid interface without filter (skipped if no root)",
			iface:     "lo",
			opts:      CaptureOptions{},
			wantErr:   false,
			expectNil: false,
		},
		{
			name:  "Valid interface with TCP filter (skipped if no root)",
			iface: "lo",
			opts: CaptureOptions{
				Filter: "tcp",
			},
			wantErr:   false,
			expectNil: false,
		},
		{
			name:  "Valid interface with invalid filter (skipped if no root)",
			iface: "lo",
			opts: CaptureOptions{
				Filter: "invalid filter",
			},
			wantErr:   true,
			expectNil: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if (tt.iface == "lo" || tt.iface == "lo0") && os.Geteuid() != 0 {
				t.Skip("Skipping live interface test, requires root")
			}
			if runtime.GOOS == "darwin" && tt.iface == "lo" {
				tt.iface = "lo0"
			}

			ch, err := Capture(tt.iface, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("Capture() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (ch == nil) != tt.expectNil {
				t.Errorf("Capture() channel = %v, expectNil %v", ch, tt.expectNil)
			}

			if ch != nil {
				for range ch {
				}
			}
		})
	}
}
