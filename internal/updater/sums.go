package updater

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
)

// sums.go cross-checks an asset against the checksum list its release publishes (Engine.SumsAsset).
//
// Install already refuses an asset whose bytes do not match the sha256 GitHub reports for it over the
// direct API, and that digest stays the anchor: GitHub computes it over the uploaded file, and a
// mirror cannot forge it. The release's SHA256SUMS is what the upstream maintainer wrote about the
// same files. Requiring the two to agree catches the case the digest alone cannot: an asset replaced
// on the release after the build that published the list (a re-upload by hand, a compromised
// account), where GitHub faithfully digests whatever is there now. The list itself may come through
// a mirror - it is only ever compared with the direct digest, so a forged list can refuse an install
// but never let one through.

// maxSumsBytes bounds the list read into memory: v2.5.8's is 2.4 KB for 23 assets.
const maxSumsBytes = 256 << 10

// checkReleaseSums fetches rel's checksum list and requires its line for asset to equal asset.Digest.
func (u *Updater) checkReleaseSums(ctx context.Context, e Engine, rel Release, asset Asset) error {
	var list *Asset
	for i := range rel.Assets {
		if rel.Assets[i].Name == e.SumsAsset {
			list = &rel.Assets[i]
			break
		}
	}
	if list == nil {
		return fmt.Errorf("the release publishes no %s to check %s against", e.SumsAsset, asset.Name)
	}
	limit := int64(maxSumsBytes)
	if list.Size > 0 && list.Size < limit {
		limit = list.Size + 1024
	}
	body, err := u.download(ctx, list.URL, limit)
	if err != nil {
		return fmt.Errorf("download %s: %w", e.SumsAsset, err)
	}
	return sumsAgree(body, e.SumsAsset, asset)
}

// sumsAgree is the comparison, on a list already read.
func sumsAgree(list []byte, listName string, asset Asset) error {
	want, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(asset.Digest)), "sha256:")
	if !ok || want == "" {
		// Install would refuse it a moment later for the same reason; saying it here names the cause.
		return fmt.Errorf("GitHub reports no sha256 digest for %s, so its %s line has nothing to be checked against", asset.Name, listName)
	}
	got, found := sumsLine(list, asset.Name)
	if !found {
		return fmt.Errorf("%s has no line for %s", listName, asset.Name)
	}
	if got != want {
		return errors.New(listName + " says " + asset.Name + " is sha256 " + got + ", but GitHub's digest of the file on the release is " + want +
			": the asset was replaced after the list was published, so it is not installed")
	}
	return nil
}

// sumsLine reads a sha256sum listing ("<hex>  <name>", or "<hex> *<name>" in binary mode) for name.
func sumsLine(list []byte, name string) (string, bool) {
	sc := bufio.NewScanner(bytes.NewReader(list))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 || len(f[0]) != 64 {
			continue
		}
		if strings.TrimPrefix(f[1], "*") == name {
			return strings.ToLower(f[0]), true
		}
	}
	return "", false
}
