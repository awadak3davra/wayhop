package speedtest

import (
	"io"
	"testing"
	"time"
)

func TestMbps(t *testing.T) {
	if got := Mbps(1_250_000, time.Second); got != 10 { // 1.25 MB/s = 10 Mbps
		t.Fatalf("Mbps=%v want 10", got)
	}
	if got := Mbps(12_500_000, time.Second); got != 100 { // 12.5 MB/s = 100 Mbps
		t.Fatalf("Mbps=%v want 100", got)
	}
	if got := Mbps(625_000, 500*time.Millisecond); got != 10 { // 0.625 MB in 0.5s = 10 Mbps
		t.Fatalf("Mbps=%v want 10", got)
	}
	if Mbps(100, 0) != 0 {
		t.Fatal("zero duration must yield 0")
	}
}

func TestZeroReader(t *testing.T) {
	n, err := io.Copy(io.Discard, &zeroReader{left: 2500})
	if err != nil || n != 2500 {
		t.Fatalf("copied %d (%v) want 2500", n, err)
	}
}
