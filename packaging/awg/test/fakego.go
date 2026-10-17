//go:build ignore

// fakego is the amneziawg-go of the package lifecycle gate (scripts/check-awg-install.sh). It is a
// real ELF, so a running copy shows up in /proc/PID/exe as the packaged binary, which is how
// install-awg.sh --uninstall finds an amneziawg-go it has to stop. `--version` prints a 3.1 version;
// anything else waits until it is stopped.
//
// Build: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o amneziawg-go ./packaging/awg/test/fakego.go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("amneziawg-go v3.1.20260828 (lifecycle fixture)")
		return
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
}
