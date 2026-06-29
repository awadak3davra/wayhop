# build.ps1 - cross-compile velinx for every router arch and package per-arch tarballs.
# Windows-friendly (the Makefile covers Unix build hosts).
# Output: dist\velinx-<ver>-<arch>.tar.gz          (Entware /opt sysvinit)
#         dist\velinx-<ver>-<arch>-openwrt.tar.gz  (OpenWrt native procd)
$ErrorActionPreference = "Stop"

$go = (Get-Command go -ErrorAction SilentlyContinue).Source
if (-not $go) { $go = "$env:USERPROFILE\go-toolchain\go\bin\go.exe" }
if (-not (Test-Path $go)) { throw "Go toolchain not found (install Go or unzip it to ~\go-toolchain)" }
$env:GOTOOLCHAIN = "local"; $env:CGO_ENABLED = "0"

$root = $PSScriptRoot
Set-Location $root
$ver = "0.1.0"
$ld = "-s -w -X velinx/internal/version.Version=$ver"
$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force $dist | Out-Null

$targets = @(
  @{ n = "mipsle"; arch = "mipsle"; mips = "softfloat" },
  @{ n = "mips";   arch = "mips";   mips = "softfloat" },
  @{ n = "arm";    arch = "arm";    arm  = "7" },
  @{ n = "arm64";  arch = "arm64" },
  @{ n = "amd64";  arch = "amd64" }
)

# Copy a file converting CRLF -> LF (busybox sh chokes on CR).
function CopyLF($src, $dst) {
  $t = [System.IO.File]::ReadAllText($src) -replace "`r`n", "`n"
  [System.IO.File]::WriteAllText($dst, $t)
}

foreach ($t in $targets) {
  $env:GOOS = "linux"; $env:GOARCH = $t.arch
  $env:GOMIPS = $(if ($t.mips) { $t.mips } else { "" })
  $env:GOARM  = $(if ($t.arm)  { $t.arm }  else { "" })

  $stage = Join-Path $dist "velinx-$($t.n)-pkg"
  Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force $stage | Out-Null

  $bin = Join-Path $stage "velinx-$($t.n)"
  & $go build -ldflags $ld -o $bin ./cmd/velinx
  if ($LASTEXITCODE -ne 0) { throw "build $($t.n) failed" }

  # --- Entware tarball: binary + install/uninstall + sysvinit S99 script ---
  CopyLF (Join-Path $root "packaging\install.sh")   (Join-Path $stage "install.sh")
  CopyLF (Join-Path $root "packaging\uninstall.sh") (Join-Path $stage "uninstall.sh")
  CopyLF (Join-Path $root "packaging\S99velinx")        (Join-Path $stage "S99velinx")

  $tar = Join-Path $dist "velinx-$ver-$($t.n).tar.gz"
  tar -C $stage -czf $tar .
  Write-Output ("packaged {0}  ({1} KB)" -f (Split-Path $tar -Leaf), [math]::Round((Get-Item $tar).Length / 1KB))

  # --- OpenWrt tarball: same binary + native procd install/uninstall + procd init ---
  $owstage = Join-Path $dist "velinx-$($t.n)-openwrt-pkg"
  Remove-Item -Recurse -Force $owstage -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force $owstage | Out-Null
  Copy-Item $bin (Join-Path $owstage "velinx-$($t.n)")
  CopyLF (Join-Path $root "packaging\openwrt\install.sh")    (Join-Path $owstage "install.sh")
  CopyLF (Join-Path $root "packaging\openwrt\uninstall.sh")  (Join-Path $owstage "uninstall.sh")
  CopyLF (Join-Path $root "packaging\openwrt\velinx.init") (Join-Path $owstage "velinx.init")

  $owtar = Join-Path $dist "velinx-$ver-$($t.n)-openwrt.tar.gz"
  tar -C $owstage -czf $owtar .
  Remove-Item -Recurse -Force $owstage
  Write-Output ("packaged {0}  ({1} KB)" -f (Split-Path $owtar -Leaf), [math]::Round((Get-Item $owtar).Length / 1KB))

  Remove-Item -Recurse -Force $stage
}
Write-Output "done -> $dist"
