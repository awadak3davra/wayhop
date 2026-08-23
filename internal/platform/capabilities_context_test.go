package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCapabilityProbeCommandRespectsParentContext(t *testing.T) {
	setCapabilityProbeHelper(t)

	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		started := time.Now()
		_, err := runCapabilityTestCommand(ctx, 5*time.Second, 8<<10, 100*time.Millisecond, "hang")
		if !errors.Is(err, errCapabilityProbeCanceled) {
			t.Fatalf("error = %v, want fixed cancellation sentinel", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("pre-canceled parent took %v", elapsed)
		}
	})

	t.Run("shorter parent deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		started := time.Now()
		_, err := runCapabilityTestCommand(ctx, 5*time.Second, 8<<10, 100*time.Millisecond, "hang")
		if !errors.Is(err, errCapabilityProbeTimeout) {
			t.Fatalf("error = %v, want fixed timeout sentinel", err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("parent deadline was not inherited: %v", elapsed)
		}
	})
}

func TestCapabilityProbeCommandBoundsInheritedPipes(t *testing.T) {
	setCapabilityProbeHelper(t)
	started := time.Now()
	_, err := runCapabilityTestCommand(
		context.Background(), 2*time.Second, 8<<10, 100*time.Millisecond, "descendant",
	)
	if !errors.Is(err, errCapabilityProbePipes) {
		t.Fatalf("error = %v, want fixed inherited-pipe sentinel", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("inherited stdout held Wait for %v", elapsed)
	}
}

func TestCapabilityProbeCommandBoundsOutputFlood(t *testing.T) {
	setCapabilityProbeHelper(t)
	const limit = 4 << 10
	_, err := runCapabilityTestCommand(
		context.Background(), 2*time.Second, limit, 100*time.Millisecond, "flood",
	)
	if !errors.Is(err, errCapabilityProbeOutput) {
		t.Fatalf("error = %v, want fixed output-limit sentinel", err)
	}
	if strings.Contains(err.Error(), "secret-flood-output") {
		t.Fatalf("command output was reflected in error: %q", err)
	}

	_, cancel := context.WithCancel(context.Background())
	output := newCapabilityProbeOutput(limit, cancel)
	defer cancel()
	chunk := []byte(strings.Repeat("x", limit*4))
	if n, writeErr := (capabilityProbeWriter{output: output, retain: true}).Write(chunk); writeErr != nil || n != len(chunk) {
		t.Fatalf("bounded writer = (%d, %v), want (%d, nil)", n, writeErr, len(chunk))
	}
	if got := len(output.stdoutString()); got != limit {
		t.Fatalf("retained output = %d bytes, want exactly capped %d", got, limit)
	}
}

func TestCapabilityProbeCommandDoesNotReflectExecFailure(t *testing.T) {
	const secretCommand = "wayhop-secret-capability-command-does-not-exist"
	_, err := runCapabilityCommandBounded(
		context.Background(), time.Second, 8<<10, 100*time.Millisecond, secretCommand,
	)
	if !errors.Is(err, errCapabilityProbeFailed) {
		t.Fatalf("error = %v, want fixed execution-failure sentinel", err)
	}
	if strings.Contains(err.Error(), secretCommand) {
		t.Fatalf("command name was reflected in error: %q", err)
	}
}

func runCapabilityTestCommand(
	ctx context.Context,
	timeout time.Duration,
	outputLimit int,
	waitDelay time.Duration,
	mode string,
) (string, error) {
	return runCapabilityCommandBounded(
		ctx, timeout, outputLimit, waitDelay,
		os.Args[0], "-test.run=^TestCapabilityProbeHelperProcess$", "--", mode,
	)
}

func setCapabilityProbeHelper(t *testing.T) {
	t.Helper()
	t.Setenv("WAYHOP_CAPABILITY_PROBE_HELPER", "1")
}

// TestCapabilityProbeHelperProcess supplies portable child behavior without a shell. In descendant
// mode the direct child succeeds while a grandchild keeps its inherited stdout/stderr pipes open.
func TestCapabilityProbeHelperProcess(t *testing.T) {
	if os.Getenv("WAYHOP_CAPABILITY_PROBE_HELPER") != "1" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "hang":
		time.Sleep(5 * time.Second)
		os.Exit(0)
	case "flood":
		_, _ = fmt.Fprint(os.Stdout, strings.Repeat("secret-flood-output", 32<<10))
		os.Exit(0)
	case "descendant":
		child := capabilityPipeHolderCommand()
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		_, _ = fmt.Fprintln(os.Stdout, "direct child exited")
		os.Exit(0)
	default:
		os.Exit(3)
	}
}

func capabilityPipeHolderCommand() *exec.Cmd {
	if runtime.GOOS == "windows" {
		// A system process, not this test executable: keeping platform.test.exe alive prevents the Go
		// tool from removing its build directory on Windows even after every assertion passed.
		return exec.Command("cmd.exe", "/d", "/c", "ping -n 3 127.0.0.1 >nul")
	}
	return exec.Command("sh", "-c", "sleep 2")
}
