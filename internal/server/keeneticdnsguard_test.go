package server

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type keeneticDNSGuardFake struct {
	calls       []string
	testErr     error
	restartErr  error
	restartSeen int
}

func (f *keeneticDNSGuardFake) run(_ context.Context, _ string, name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if name == executionToolDnsmasq {
		return "", f.testErr
	}
	if name == executionToolShell {
		f.restartSeen++
		if f.restartSeen == 1 {
			return "", f.restartErr
		}
	}
	return "", nil
}

func useKeeneticDNSGuardFakes(t *testing.T, healthy bool) {
	t.Helper()
	oldPresent, oldAlive, oldUpstream := keeneticDnsmasqServicePresent, fastDNSAlive, fastDNSUpstream
	oldWait, oldPoll := keeneticDNSGuardWait, keeneticDNSGuardPoll
	t.Cleanup(func() {
		keeneticDnsmasqServicePresent, fastDNSAlive, fastDNSUpstream = oldPresent, oldAlive, oldUpstream
		keeneticDNSGuardWait, keeneticDNSGuardPoll = oldWait, oldPoll
	})
	keeneticDnsmasqServicePresent = func() bool { return true }
	keeneticDNSGuardWait, keeneticDNSGuardPoll = 0, time.Millisecond
	fastDNSAlive = func(context.Context, bool) error {
		if healthy {
			return nil
		}
		return errors.New("dnsmasq pid or local answer missing")
	}
	fastDNSUpstream = func(context.Context) error {
		if healthy {
			return nil
		}
		return errors.New("external name did not resolve")
	}
}

func TestKeeneticDNSGuardSuccess(t *testing.T) {
	useKeeneticDNSGuardFakes(t, true)
	fake := &keeneticDNSGuardFake{}
	restored := 0
	if err := reloadKeeneticDnsmasqGuarded(context.Background(), fake.run, func() error { restored++; return nil }, true); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"dnsmasq --test -C /opt/etc/dnsmasq.conf",
		"sh /opt/etc/init.d/S56dnsmasq restart",
	}
	if !reflect.DeepEqual(fake.calls, want) || restored != 0 {
		t.Fatalf("calls = %v, restored = %d", fake.calls, restored)
	}
}

func TestKeeneticDNSGuardTestFailureRestoresWithoutRestart(t *testing.T) {
	useKeeneticDNSGuardFakes(t, true)
	fake := &keeneticDNSGuardFake{testErr: errors.New("bad ipset line")}
	restored := 0
	err := reloadKeeneticDnsmasqGuarded(context.Background(), fake.run, func() error { restored++; return nil }, true)
	if err == nil || restored != 1 || fake.restartSeen != 0 {
		t.Fatalf("err = %v, restored = %d, calls = %v", err, restored, fake.calls)
	}
}

func TestKeeneticDNSGuardRestartFailureRestartsPreviousPolicy(t *testing.T) {
	useKeeneticDNSGuardFakes(t, true)
	fake := &keeneticDNSGuardFake{restartErr: errors.New("restart failed")}
	restored := 0
	err := reloadKeeneticDnsmasqGuarded(context.Background(), fake.run, func() error { restored++; return nil }, true)
	if err == nil || restored != 1 || fake.restartSeen != 2 {
		t.Fatalf("err = %v, restored = %d, calls = %v", err, restored, fake.calls)
	}
}

func TestKeeneticDNSGuardHealthFailureRestartsPreviousPolicy(t *testing.T) {
	useKeeneticDNSGuardFakes(t, false)
	fake := &keeneticDNSGuardFake{}
	restored := 0
	err := reloadKeeneticDnsmasqGuarded(context.Background(), fake.run, func() error { restored++; return nil }, true)
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1:53") || restored != 1 || fake.restartSeen != 2 {
		t.Fatalf("err = %v, restored = %d, calls = %v", err, restored, fake.calls)
	}
}
