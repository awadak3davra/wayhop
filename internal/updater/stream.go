package updater

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// This file holds the STREAMING install path. The original updater downloaded the whole compressed
// asset into a []byte and then decompressed it into a second []byte, so its peak RAM was
// (compressed + decompressed) — which OOM-killed low-RAM routers on a large core (sing-box ~38 MB).
// streamAssetToFile instead pipes the HTTP body straight through gunzip/untar into the output file
// while hashing the compressed bytes, so neither the archive nor the binary is ever held whole in
// RAM. The []byte helpers in updater.go (fromGz/fromTarGz/fromZip/extractBinary/verifyDigest) now
// delegate to the primitives here, so there is a single extraction implementation.

// maxBin bounds a decompressed binary, matching the old per-extract LimitReader ceiling so a
// hostile archive can't inflate without bound on a small router.
const maxBin = 256 << 20

// --- streaming extraction primitives (io.Reader/Writer, no []byte buffering) ---

func fromGzStream(r io.Reader, w io.Writer) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer zr.Close()
	_, err = io.Copy(w, io.LimitReader(zr, maxBin))
	return err
}

func fromTarGzStream(r io.Reader, binName string, w io.Writer) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if h.Typeflag == tar.TypeReg && filepath.Base(h.Name) == binName {
			_, err = io.Copy(w, io.LimitReader(tr, maxBin))
			return err
		}
	}
	return fmt.Errorf("binary %q not found in archive", binName)
}

func fromZipStream(ra io.ReaderAt, size int64, binName string, w io.Writer) error {
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) == binName {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()
			_, err = io.Copy(w, io.LimitReader(rc, maxBin))
			return err
		}
	}
	return fmt.Errorf("binary %q not found in zip", binName)
}

// extractStreamTo dispatches by asset extension and streams the wanted binary into w. zip needs
// random access, so the caller passes a ReaderAt + size for it; the gz/tar.gz/raw paths only read
// forward from r. (For zip the streaming install stages the archive to a temp file first.)
func extractStreamTo(assetName string, r io.Reader, ra io.ReaderAt, size int64, binName string, w io.Writer) error {
	n := strings.ToLower(assetName)
	switch {
	case strings.HasSuffix(n, ".tar.gz") || strings.HasSuffix(n, ".tgz"):
		return fromTarGzStream(r, binName, w)
	case strings.HasSuffix(n, ".zip"):
		return fromZipStream(ra, size, binName, w)
	case strings.HasSuffix(n, ".gz"):
		return fromGzStream(r, w)
	default:
		_, err := io.Copy(w, io.LimitReader(r, maxBin)) // raw, non-archive binary
		return err
	}
}

// --- digest ---------------------------------------------------------------

// verifyDigestSum compares an already-computed "sha256:<hex>" sum against the asset's declared
// digest. mandatory=true (self-update) refuses when the asset declares no/!sha256 digest; otherwise
// a missing digest is best-effort skip, so an engine release that lacks one still installs.
func verifyDigestSum(sum, digest string, mandatory bool) error {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 || parts[0] != "sha256" || parts[1] == "" {
		if mandatory {
			return fmt.Errorf("self-update refused: release asset has no sha256 digest to verify against (an unverified binary would run as root)")
		}
		return nil
	}
	if !strings.EqualFold(strings.TrimPrefix(sum, "sha256:"), parts[1]) {
		return fmt.Errorf("sha256 mismatch: refusing to install")
	}
	return nil
}

// --- streaming download + install -----------------------------------------

// peakInstallDisk estimates the worst-case bytes the streaming install writes to the TARGET
// filesystem for an asset of assetSize bytes. A COMPRESSED archive (.tar.gz/.gz/.zip) decompresses
// ~2-3x on the way to disk, so it's sized 3x; a BARE binary asset (e.g. olcrtc-linux-arm64, which
// the release ships uncompressed) writes ~its own size, so a flat 3x would wrongly refuse installs
// that actually fit — it's sized 1x. Plus a margin. withBackup doubles it (self-update keeps a .bak
// on the same fs). A zip additionally stages the archive, but that temp is bounded by assetSize and
// freed immediately, so the binary estimate dominates.
func peakInstallDisk(assetSize int64, assetName string, withBackup bool) uint64 {
	bin := unpackedBytes(assetSize, assetName)
	if withBackup {
		bin *= 2
	}
	return bin + (4 << 20)
}

// unpackedBytes is the size of the final on-disk binary for an asset of assetSize bytes: a bare
// binary is already unpacked (1x); a compressed archive (.tar.gz/.gz/.zip) inflates ~2-3x on the
// way out, bounded at 3x. Shared by the disk pre-flight and the update memory-lock.
func unpackedBytes(assetSize int64, assetName string) uint64 {
	if isBareBinaryAsset(assetName) {
		return uint64(assetSize)
	}
	return uint64(assetSize) * 3
}

// isBareBinaryAsset reports whether an asset is a raw (already-unpacked) binary rather than a
// compressed archive — mirroring extractStreamTo's dispatch, whose default (non-archive) case
// copies the asset through verbatim.
func isBareBinaryAsset(name string) bool {
	n := strings.ToLower(name)
	return !(strings.HasSuffix(n, ".tar.gz") || strings.HasSuffix(n, ".tgz") ||
		strings.HasSuffix(n, ".gz") || strings.HasSuffix(n, ".zip"))
}

// enoughFlashFor reports whether `avail` free bytes on the target filesystem can hold the streamed
// install (see peakInstallDisk). Unknown avail (off-Linux build) or unknown assetSize never blocks.
// Once the download streams straight to disk this is the BINDING constraint: a ~38 MB core cannot
// fit a ~20 MB overlay no matter the install method, so we refuse early with an actionable message
// (free space / mount external storage / install over SSH) instead of failing mid-write.
func enoughFlashFor(avail uint64, known bool, assetSize int64, assetName string, withBackup bool) bool {
	if !known || assetSize <= 0 {
		return true
	}
	return avail >= peakInstallDisk(assetSize, assetName, withBackup)
}

// streamAssetToFile downloads `asset` (trying each mirror in turn), extracts `binName`, and writes
// the verified binary to dstPath — streaming throughout, so neither the compressed archive nor the
// decompressed binary is ever buffered whole in RAM. The sha256 of the COMPRESSED asset is computed
// as it streams and checked against asset.Digest before success (mandatory when requireDigest, e.g.
// self-update, where the binary runs as root). On any failure dstPath is removed; on success the
// binary is at dstPath with mode 0755.
func (u *Updater) streamAssetToFile(ctx context.Context, asset Asset, binName, dstPath string, requireDigest bool) error {
	var lastErr error
	for _, m := range u.Mirrors {
		url := asset.URL
		if m != "" {
			url = strings.TrimRight(m, "/") + "/" + asset.URL
		}
		if err := u.streamOne(ctx, url, asset, binName, dstPath, requireDigest); err == nil {
			return nil
		} else {
			lastErr = err
			_ = os.Remove(dstPath) // discard any partial write before trying the next mirror
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no mirrors configured")
	}
	return lastErr
}

func (u *Updater) streamOne(ctx context.Context, url string, asset Asset, binName, dstPath string, requireDigest bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "wayhop-updater")
	resp, err := u.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}

	// Hash the COMPRESSED bytes as they stream so the digest covers exactly what the release
	// published; cap the body like the in-memory path so a misbehaving mirror can't stream forever.
	h := sha256.New()
	br := bufio.NewReader(io.TeeReader(io.LimitReader(resp.Body, dlCap(asset.Size)), h))

	// Peek the first bytes to reject an HTML interstitial/captcha a censored mirror may answer with
	// a 200, before we treat the stream as an archive. bufio keeps the peeked bytes buffered, so the
	// extractor below still sees the full stream.
	head, _ := br.Peek(512)
	if looksLikeHTML(resp.Header.Get("Content-Type"), head) {
		return fmt.Errorf("%s: response looks like an HTML/error page, not a binary asset", url)
	}

	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer out.Close() // safety net for the error paths; success closes explicitly before the digest check

	if strings.HasSuffix(strings.ToLower(asset.Name), ".zip") {
		// zip needs random access → stage the (size-capped, hashed) archive to a temp file on the
		// SAME filesystem as the target, then extract. Still no whole-archive RAM buffer.
		tmp := dstPath + ".zip"
		zf, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		defer os.Remove(tmp)
		defer zf.Close()
		size, err := io.Copy(zf, br) // br tees into h, so the whole zip is hashed here
		if err != nil {
			return err
		}
		if err := fromZipStream(zf, size, binName, out); err != nil {
			return err
		}
	} else {
		if err := extractStreamTo(asset.Name, br, nil, 0, binName, out); err != nil {
			return err
		}
		// Drain any trailing archive bytes through the hash: tar stops at the target entry, so the
		// tail (other files, padding) would otherwise go unread and the digest would be incomplete.
		_, _ = io.Copy(io.Discard, br)
	}

	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}

	return verifyDigestSum("sha256:"+hex.EncodeToString(h.Sum(nil)), asset.Digest, requireDigest)
}

// LatestStable returns the newest non-prerelease tag from rels (GitHub returns them newest-first),
// falling back to the newest tag when every release is a prerelease. This keeps an alpha/beta/rc
// (e.g. a sing-box 1.14.0-alpha that outranks the 1.12.x line the panel targets) from being
// surfaced as the recommended "latest".
func LatestStable(rels []Release) string {
	for _, r := range rels {
		if !r.Prerelease {
			return r.Tag
		}
	}
	if len(rels) > 0 {
		return rels[0].Tag
	}
	return ""
}
