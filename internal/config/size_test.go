package config

import (
	"fmt"
	"testing"
	"unsafe"
)

func TestConfigSize(t *testing.T) {
	cfg := Default()
	size := unsafe.Sizeof(*cfg)
	// Reference a default value (not just types) so the Default() result is actually
	// used — unsafe.Sizeof alone reads only the type, which trips staticcheck SA4006.
	fmt.Printf("\nConfig struct size: %d bytes (e.g. listen default %q)\n", size, cfg.Listen)
	fmt.Printf("Config fields breakdown:\n")
	fmt.Printf("  Listen (string): %d bytes\n", unsafe.Sizeof(cfg.Listen))
	fmt.Printf("  DataDir (string): %d bytes\n", unsafe.Sizeof(cfg.DataDir))
	fmt.Printf("  AllowedHosts ([]string): %d bytes\n", unsafe.Sizeof(cfg.AllowedHosts))
	fmt.Printf("  Ports (struct): %d bytes\n", unsafe.Sizeof(cfg.Ports))
	fmt.Printf("  Clash (struct): %d bytes\n", unsafe.Sizeof(cfg.Clash))
	fmt.Printf("  SingBox (struct): %d bytes\n", unsafe.Sizeof(cfg.SingBox))
	fmt.Printf("  Updater (struct): %d bytes\n", unsafe.Sizeof(cfg.Updater))
}
