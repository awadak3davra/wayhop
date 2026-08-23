package updater

import "testing"

// The real sing-box v1.13.19 asset list for arm64, in the order GitHub returns it. The glibc build
// comes first, which is how it was chosen: every non-arm asset used to score the same, so the first
// match won. Installed on a live Keenetic it refused to run — "fork/exec
// /opt/bin/sing-box.new: no such file or directory" for a file that was there — because a glibc
// binary needs an ELF interpreter that a musl router does not have.
func TestPickAssetPrefersMuslOverGlibc(t *testing.T) {
	assets := []Asset{
		{Name: "sing-box-1.13.19-linux-arm64-glibc.tar.gz", Size: 22694304},
		{Name: "sing-box-1.13.19-linux-arm64.tar.gz", Size: 21600000},
		{Name: "sing-box-1.13.19-linux-amd64.tar.gz", Size: 23000000},
	}
	got := pickAsset(assets, "arm64")
	if got == nil || got.Name != "sing-box-1.13.19-linux-arm64.tar.gz" {
		t.Fatalf("picked %v, want the unlabelled (musl) arm64 build", got)
	}

	// Order must not decide it: the same list with the musl build first picks the same asset.
	reordered := []Asset{assets[1], assets[0], assets[2]}
	if got := pickAsset(reordered, "arm64"); got == nil || got.Name != "sing-box-1.13.19-linux-arm64.tar.gz" {
		t.Fatalf("picked %v after reordering", got)
	}
}

// A glibc build is still installable when it is the only one: refusing outright would turn "this
// probably will not run" into "you cannot try", and the install path already sanity-runs the binary
// before swapping it in, so a wrong guess costs nothing.
func TestPickAssetFallsBackToGlibcWhenAlone(t *testing.T) {
	assets := []Asset{{Name: "tool-1.0-linux-arm64-glibc.tar.gz"}}
	if got := pickAsset(assets, "arm64"); got == nil || got.Name != assets[0].Name {
		t.Fatalf("picked %v, want the only asset there is", got)
	}
}

// Explicitly-labelled builds rank above the unlabelled one, and a static build above musl: a static
// binary needs no interpreter on either kind of host.
func TestPickAssetRanksStaticAndMuslLabels(t *testing.T) {
	assets := []Asset{
		{Name: "tool-1.0-linux-arm64.tar.gz"},
		{Name: "tool-1.0-linux-arm64-musl.tar.gz"},
		{Name: "tool-1.0-linux-arm64-static.tar.gz"},
	}
	if got := pickAsset(assets, "arm64"); got == nil || got.Name != "tool-1.0-linux-arm64-static.tar.gz" {
		t.Fatalf("picked %v, want the static build", got)
	}
	if got := pickAsset(assets[:2], "arm64"); got == nil || got.Name != "tool-1.0-linux-arm64-musl.tar.gz" {
		t.Fatalf("picked %v, want the musl build over the unlabelled one", got)
	}
	// Rust-style triples name glibc as "gnu" and must lose the same way.
	rust := []Asset{
		{Name: "tool-1.0-aarch64-unknown-linux-gnu.tar.gz"},
		{Name: "tool-1.0-aarch64-unknown-linux-musl.tar.gz"},
	}
	if got := pickAsset(rust, "arm64"); got == nil || got.Name != "tool-1.0-aarch64-unknown-linux-musl.tar.gz" {
		t.Fatalf("picked %v, want the musl triple", got)
	}
}

// The 32-bit ARM ordering this score already had must survive the new dimension: among binaries that
// load, the instruction-set variant still decides.
func TestPickAssetKeepsArmVariantOrder(t *testing.T) {
	assets := []Asset{
		{Name: "tool-1.0-linux-armv5.tar.gz"},
		{Name: "tool-1.0-linux-armv7.tar.gz"},
		{Name: "tool-1.0-linux-arm.tar.gz"},
	}
	if got := pickAsset(assets, "arm"); got == nil || got.Name != "tool-1.0-linux-armv7.tar.gz" {
		t.Fatalf("picked %v, want armv7", got)
	}
	// libc still dominates: a glibc armv7 loses to a musl bare-arm build.
	mixed := []Asset{
		{Name: "tool-1.0-linux-armv7-glibc.tar.gz"},
		{Name: "tool-1.0-linux-arm-musl.tar.gz"},
	}
	if got := pickAsset(mixed, "arm"); got == nil || got.Name != "tool-1.0-linux-arm-musl.tar.gz" {
		t.Fatalf("picked %v, want the musl build even at a worse ARM variant", got)
	}
}
