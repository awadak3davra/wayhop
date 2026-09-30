package qr

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// The Reed-Solomon known answer: "HELLO WORLD" as 1-M (alphanumeric), the worked example every QR
// tutorial uses. Its 16 data codewords take these 10 error-correction codewords.
func TestReedSolomonKnownAnswer(t *testing.T) {
	data := []byte{32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17}
	want := []byte{196, 35, 39, 119, 235, 215, 231, 226, 93, 23}
	if got := rsRemainder(data, 10); !bytes.Equal(got, want) {
		t.Fatalf("EC %v, want %v", got, want)
	}
}

// ISO/IEC 18004 table C.1: the format words of level M.
func TestFormatWords(t *testing.T) {
	want := []string{"101010000010010", "101000100100101", "101111001111100", "101101101001011",
		"100010111111001", "100000011001110", "100111110010111", "100101010100000"}
	for mask, w := range want {
		if got := fmt.Sprintf("%015b", formatBits(mask)); got != w {
			t.Errorf("mask %d: %s, want %s", mask, got, w)
		}
	}
}

func TestVersionChoice(t *testing.T) {
	for _, c := range []struct {
		n, version int
	}{{1, 1}, {14, 1}, {15, 2}, {26, 2}, {42, 3}, {60, 4}, {62, 4}, {84, 5}, {106, 6}} {
		code, err := Encode(strings.Repeat("a", c.n))
		if err != nil || code.Version != c.version || code.Size != 17+4*c.version {
			t.Errorf("%d bytes: version %d size %d err %v, want version %d", c.n, code.Version, code.Size, err, c.version)
		}
	}
	if _, err := Encode(strings.Repeat("a", 107)); err != ErrTooLong {
		t.Fatalf("107 bytes: %v", err)
	}
}

// decode reads a symbol back the way a scanner would: it rebuilds the function-pattern map from the
// version alone, reads the format word, removes the mask, collects the bits in the zigzag order,
// de-interleaves the blocks, checks every block's Reed-Solomon syndromes, and parses the byte-mode
// segment. It shares no drawing code with the encoder.
func decode(t *testing.T, c *Code) string {
	t.Helper()
	n := c.Size
	version := (n - 17) / 4
	fn := func(x, y int) bool {
		switch {
		case x <= 8 && y <= 8, x >= n-8 && y <= 8, x <= 8 && y >= n-8: // finders, separators, format
			return true
		case x == 6 || y == 6: // timing
			return true
		}
		if a := alignCenter[version]; a > 0 && abs(x-a) <= 2 && abs(y-a) <= 2 {
			return true
		}
		return false
	}
	// Format word, first copy, read in the order it was written.
	word := 0
	read := func(x, y, i int) {
		if c.Modules[y][x] {
			word |= 1 << uint(i)
		}
	}
	for i := 0; i <= 5; i++ {
		read(8, i, i)
	}
	read(8, 7, 6)
	read(8, 8, 7)
	read(7, 8, 8)
	for i := 9; i < 15; i++ {
		read(14-i, 8, i)
	}
	mask := -1
	for m := 0; m < 8; m++ {
		if formatBits(m) == word {
			mask = m
		}
	}
	if mask != c.Mask {
		t.Fatalf("format word %015b decodes to mask %d, the code says %d", word, mask, c.Mask)
	}
	if !c.Modules[n-8][8] {
		t.Fatal("the dark module is light")
	}
	// Bits in reading order: column pairs from the right, alternating up and down, skipping column 6.
	var bits []bool
	col, up := n-1, true
	for col > 0 {
		if col == 6 {
			col--
		}
		for k := 0; k < n; k++ {
			y := k
			if up {
				y = n - 1 - k
			}
			for _, x := range []int{col, col - 1} {
				if fn(x, y) {
					continue
				}
				bits = append(bits, c.Modules[y][x] != maskBit(mask, x, y))
			}
		}
		col -= 2
		up = !up
	}
	m := levelM[version]
	total := m.blocks * (m.data + m.ec)
	if len(bits) < total*8 {
		t.Fatalf("%d data modules for %d codewords", len(bits), total)
	}
	cw := make([]byte, total)
	for i := range cw {
		for b := 0; b < 8; b++ {
			if bits[i*8+b] {
				cw[i] |= 0x80 >> uint(b)
			}
		}
	}
	blocks := make([][]byte, m.blocks)
	for i := 0; i < m.data; i++ {
		for b := range blocks {
			blocks[b] = append(blocks[b], cw[i*m.blocks+b])
		}
	}
	for i := 0; i < m.ec; i++ {
		for b := range blocks {
			blocks[b] = append(blocks[b], cw[m.blocks*m.data+i*m.blocks+b])
		}
	}
	var data []byte
	for b, block := range blocks {
		// A valid codeword evaluates to zero at α^0..α^(ec-1).
		for i := 0; i < m.ec; i++ {
			var s byte
			for _, v := range block {
				s = gfMul(s, gfExp[i]) ^ v
			}
			if s != 0 {
				t.Fatalf("block %d syndrome %d is %d", b, i, s)
			}
		}
		data = append(data, block[:m.data]...)
	}
	// Byte mode: 0100, an 8-bit count, the bytes.
	all := ""
	for _, d := range data {
		all += fmt.Sprintf("%08b", d)
	}
	if all[:4] != "0100" {
		t.Fatalf("mode %s", all[:4])
	}
	count, _ := strconv.ParseUint(all[4:12], 2, 8)
	out := make([]byte, count)
	for i := range out {
		v, _ := strconv.ParseUint(all[12+8*i:20+8*i], 2, 8)
		out[i] = byte(v)
	}
	return string(out)
}

func TestRoundTrip(t *testing.T) {
	for _, s := range []string{
		"A",
		"https://t.me/wayhop_sim_bot?start=DJDPNMFQ",
		"https://t.me/a_very_long_bot_username_32_chars_x?start=ABCDEFGH",
		"Привет, WayHop",
		strings.Repeat("0123456789", 10),
	} {
		c, err := Encode(s)
		if err != nil {
			t.Fatal(err)
		}
		if got := decode(t, c); got != s {
			t.Fatalf("version %d mask %d: decoded %q, want %q", c.Version, c.Mask, got, s)
		}
	}
}

// Every mask must produce a readable symbol, not only the one the penalty picks.
func TestEveryMaskDecodes(t *testing.T) {
	text := "https://t.me/home_wayhop_bot?start=QKXJS9UA"
	version := 4
	cw := interleave(version, dataCodewords(version, []byte(text)))
	for mask := 0; mask < 8; mask++ {
		s := newCode(version)
		s.drawCodewords(cw)
		s.applyMask(mask)
		s.drawFormat(mask)
		if got := decode(t, s.snapshot(mask)); got != text {
			t.Fatalf("mask %d: %q", mask, got)
		}
	}
}

func TestFinderPatternsAndTiming(t *testing.T) {
	c, _ := Encode("https://t.me/home_wayhop_bot?start=QKXJS9UA")
	n := c.Size
	finder := []string{"1111111", "1000001", "1011101", "1011101", "1011101", "1000001", "1111111"}
	for _, o := range [][2]int{{0, 0}, {n - 7, 0}, {0, n - 7}} {
		for dy, row := range finder {
			for dx, ch := range row {
				if c.Modules[o[1]+dy][o[0]+dx] != (ch == '1') {
					t.Fatalf("finder at %v wrong at (%d,%d)", o, dx, dy)
				}
			}
		}
	}
	for i := 8; i < n-8; i++ {
		if c.Modules[6][i] != (i%2 == 0) || c.Modules[i][6] != (i%2 == 0) {
			t.Fatalf("timing wrong at %d", i)
		}
	}
}

func TestSVG(t *testing.T) {
	c, _ := Encode("https://t.me/x?start=ABCDEFGH")
	svg := c.SVG()
	n := c.Size + 8
	if !strings.HasPrefix(svg, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 `+strconv.Itoa(n)+" "+strconv.Itoa(n)+`"`) ||
		!strings.Contains(svg, `fill="#fff"`) || !strings.HasSuffix(svg, "</svg>") {
		t.Fatalf("svg %q", svg[:120])
	}
	dark := 0
	for _, row := range c.Modules {
		for _, v := range row {
			if v {
				dark++
			}
		}
	}
	if got := strings.Count(svg, "h1v1h-1z"); got != dark {
		t.Fatalf("%d squares for %d dark modules", got, dark)
	}
}
