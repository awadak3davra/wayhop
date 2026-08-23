package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
)

func TestExactNativePlatformAdapterFailsClosedWithoutMatchingBackend(t *testing.T) {
	keenetic, _ := newExactKeeneticNativeAdapter(&exactKeeneticRecordRunner{})
	adapter, err := newExactNativePlatformAdapter(nil, keenetic)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.prepare(context.Background(), nativeplan.Plan{Platform: platform.OpenWrt}); !errors.Is(err, errExactNativePlatform) {
		t.Fatalf("missing OpenWrt backend error = %v", err)
	}
	if err := adapter.commit(context.Background(), nativeplan.Reconciliation{Platform: platform.OpenWrt, Target: &nativeplan.Plan{Platform: platform.OpenWrt}}); !errors.Is(err, errExactNativePlatform) {
		t.Fatalf("missing OpenWrt commit backend error = %v", err)
	}
}

func TestExactNativePlatformAdapterDispatchesKeeneticWithoutFallback(t *testing.T) {
	runner := &exactKeeneticRecordRunner{}
	keenetic, _ := newExactKeeneticNativeAdapter(runner)
	adapter, _ := newExactNativePlatformAdapter(nil, keenetic)
	target := exactKeeneticTestTarget()
	keenetic.readConfig = exactKeeneticConfigReader(
		exactKeeneticBaselineConfig,
		strings.Join(target.Keenetic.Interfaces[0], "\n"),
		exactKeeneticTargetRunningConfig(target),
		exactKeeneticTargetRunningConfig(target),
		exactKeeneticTargetRunningConfig(target),
	)
	if err := adapter.prepare(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if err := adapter.commit(context.Background(), exactKeeneticReconciliation(target, nil)); err != nil {
		t.Fatal(err)
	}
	if err := adapter.persist(context.Background(), exactKeeneticReconciliation(target, nil)); err != nil {
		t.Fatal(err)
	}
	if len(runner.batches) != 3 || runner.batches[2][0] != exactKeeneticSaveCommand {
		t.Fatalf("Keenetic batches = %#v", runner.batches)
	}
	if err := adapter.postcheck(context.Background(), nativeplan.Reconciliation{
		Platform: platform.Keenetic, Target: &target,
	}); err != nil {
		t.Fatalf("Keenetic postcheck: %v", err)
	}
}
