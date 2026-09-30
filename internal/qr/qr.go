// Package qr draws a QR code: byte mode, error-correction level M, versions 1 to 6 (up to 106
// bytes). That is enough for what the panel shows as a code, a t.me pairing link, and small enough to
// read in one sitting against ISO/IEC 18004. It renders to SVG, dark on light whatever the theme,
// because a scanner needs the contrast.
package qr

import (
	"errors"
	"fmt"
	"strings"
)

// Code is a finished symbol: Size×Size modules, true = dark.
type Code struct {
	Size    int
	Version int
	Mask    int
	Modules [][]bool
}

// ErrTooLong is returned for text that does not fit version 6-M.
var ErrTooLong = errors.New("qr: text too long for a small code")

// ecM describes error-correction level M for one version: EC codewords per block, and the data
// codewords of each block. Every block of these versions has the same length.
type ecM struct {
	ec     int
	blocks int
	data   int // data codewords per block
}

// levelM is ISO/IEC 18004 table 9, level M, versions 1 to 6.
var levelM = [7]ecM{
	1: {ec: 10, blocks: 1, data: 16},
	2: {ec: 16, blocks: 1, data: 28},
	3: {ec: 26, blocks: 1, data: 44},
	4: {ec: 18, blocks: 2, data: 32},
	5: {ec: 24, blocks: 2, data: 43},
	6: {ec: 16, blocks: 4, data: 27},
}

// alignCenter is the single alignment-pattern centre of versions 2 to 6 (both coordinates).
var alignCenter = [7]int{2: 18, 3: 22, 4: 26, 5: 30, 6: 34}

// formatLevelM is level M's two format bits (L=01, M=00, Q=11, H=10).
const formatLevelM = 0

// Encode draws text as the smallest code that holds it, with the mask that scores best.
func Encode(text string) (*Code, error) {
	data := []byte(text)
	version := 0
	for v := 1; v <= 6; v++ {
		// 4 bits of mode, 8 bits of count (versions 1-9), 8 per byte.
		if 4+8+8*len(data) <= levelM[v].blocks*levelM[v].data*8 {
			version = v
			break
		}
	}
	if version == 0 {
		return nil, ErrTooLong
	}
	codewords := interleave(version, dataCodewords(version, data))
	var best *Code
	bestScore := -1
	for mask := 0; mask < 8; mask++ {
		c := newCode(version)
		c.drawCodewords(codewords)
		c.applyMask(mask)
		c.drawFormat(mask)
		if score := c.penalty(); best == nil || score < bestScore {
			best, bestScore = c.snapshot(mask), score
		}
	}
	return best, nil
}

// bitWriter packs bits MSB first.
type bitWriter struct {
	buf []byte
	n   int
}

func (w *bitWriter) put(v uint, bits int) {
	for i := bits - 1; i >= 0; i-- {
		if w.n%8 == 0 {
			w.buf = append(w.buf, 0)
		}
		if v>>uint(i)&1 == 1 {
			w.buf[w.n/8] |= 0x80 >> uint(w.n%8)
		}
		w.n++
	}
}

// dataCodewords is the byte-mode segment, the terminator, and the pad bytes, for version.
func dataCodewords(version int, data []byte) []byte {
	capacity := levelM[version].blocks * levelM[version].data
	w := &bitWriter{}
	w.put(0b0100, 4)
	w.put(uint(len(data)), 8)
	for _, b := range data {
		w.put(uint(b), 8)
	}
	if room := capacity*8 - w.n; room > 0 {
		t := room
		if t > 4 {
			t = 4
		}
		w.put(0, t) // terminator
	}
	if w.n%8 != 0 {
		w.put(0, 8-w.n%8)
	}
	for pad := byte(0xEC); len(w.buf) < capacity; pad ^= 0xEC ^ 0x11 {
		w.buf = append(w.buf, pad)
	}
	return w.buf
}

// interleave splits data into blocks, adds each block's error correction, and interleaves them.
func interleave(version int, data []byte) []byte {
	m := levelM[version]
	var blocks, ecs [][]byte
	for b := 0; b < m.blocks; b++ {
		block := data[b*m.data : (b+1)*m.data]
		blocks = append(blocks, block)
		ecs = append(ecs, rsRemainder(block, m.ec))
	}
	out := make([]byte, 0, m.blocks*(m.data+m.ec))
	for i := 0; i < m.data; i++ {
		for _, b := range blocks {
			out = append(out, b[i])
		}
	}
	for i := 0; i < m.ec; i++ {
		for _, e := range ecs {
			out = append(out, e[i])
		}
	}
	return out
}

// GF(256) with the QR primitive polynomial x^8+x^4+x^3+x^2+1.
var gfExp, gfLog = func() ([512]byte, [256]byte) {
	var exp [512]byte
	var log [256]byte
	x := 1
	for i := 0; i < 255; i++ {
		exp[i] = byte(x)
		log[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		exp[i] = exp[i-255]
	}
	return exp, log
}()

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// rsGenerator is the product of (x - α^i), i = 0..degree-1, highest power first, leading 1 omitted.
func rsGenerator(degree int) []byte {
	g := []byte{1}
	for i := 0; i < degree; i++ {
		next := make([]byte, len(g)+1)
		for j, c := range g {
			next[j] ^= c
			next[j+1] ^= gfMul(c, gfExp[i])
		}
		g = next
	}
	return g[1:]
}

// rsRemainder is the Reed-Solomon error correction of data: data(x)·x^n mod g(x).
func rsRemainder(data []byte, n int) []byte {
	g := rsGenerator(n)
	rem := make([]byte, n)
	for _, d := range data {
		factor := d ^ rem[0]
		copy(rem, rem[1:])
		rem[n-1] = 0
		for i := range rem {
			rem[i] ^= gfMul(g[i], factor)
		}
	}
	return rem
}

// symbol is a code being drawn: modules, and which of them are function patterns.
type symbol struct {
	size     int
	version  int
	modules  [][]bool
	function [][]bool
}

func newCode(version int) *symbol {
	size := 17 + 4*version
	s := &symbol{size: size, version: version, modules: grid(size), function: grid(size)}
	s.drawFinder(3, 3)
	s.drawFinder(size-4, 3)
	s.drawFinder(3, size-4)
	for i := 0; i < size; i++ {
		if !s.function[6][i] {
			s.set(i, 6, i%2 == 0) // timing, row 6
		}
		if !s.function[i][6] {
			s.set(6, i, i%2 == 0) // timing, column 6
		}
	}
	if c := alignCenter[version]; c > 0 {
		for dy := -2; dy <= 2; dy++ {
			for dx := -2; dx <= 2; dx++ {
				ring := max(abs(dx), abs(dy))
				s.set(c+dx, c+dy, ring != 1)
			}
		}
	}
	s.drawFormat(0) // reserve the format areas and place the dark module; redrawn with the real mask
	return s
}

func grid(n int) [][]bool {
	g := make([][]bool, n)
	for i := range g {
		g[i] = make([]bool, n)
	}
	return g
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// set marks a function module at column x, row y.
func (s *symbol) set(x, y int, dark bool) {
	s.modules[y][x] = dark
	s.function[y][x] = true
}

// drawFinder draws a finder pattern centred at (x, y) with its light separator.
func (s *symbol) drawFinder(x, y int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			xx, yy := x+dx, y+dy
			if xx < 0 || yy < 0 || xx >= s.size || yy >= s.size {
				continue
			}
			ring := max(abs(dx), abs(dy))
			s.set(xx, yy, ring != 2 && ring != 4)
		}
	}
}

// drawFormat writes the 15 format bits (level M, mask) in both copies, and the dark module.
func (s *symbol) drawFormat(mask int) {
	bits := formatBits(mask)
	bit := func(i int) bool { return bits>>uint(i)&1 == 1 }
	for i := 0; i <= 5; i++ {
		s.set(8, i, bit(i))
	}
	s.set(8, 7, bit(6))
	s.set(8, 8, bit(7))
	s.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		s.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		s.set(s.size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		s.set(8, s.size-15+i, bit(i))
	}
	s.set(8, s.size-8, true)
}

// formatBits is the BCH(15,5) format word for level M and mask, XOR-masked with 101010000010010.
func formatBits(mask int) int {
	data := formatLevelM<<3 | mask
	rem := data
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	return (data<<10 | rem) ^ 0x5412
}

// drawCodewords places the codewords in the zigzag order, two columns at a time from the bottom
// right, skipping the vertical timing column and every function module.
func (s *symbol) drawCodewords(data []byte) {
	i := 0
	for right := s.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		upward := (right+1)&2 == 0
		for vert := 0; vert < s.size; vert++ {
			y := vert
			if upward {
				y = s.size - 1 - vert
			}
			for j := 0; j < 2; j++ {
				x := right - j
				if s.function[y][x] || i >= len(data)*8 {
					continue
				}
				s.modules[y][x] = data[i/8]>>uint(7-i%8)&1 == 1
				i++
			}
		}
	}
}

// maskBit is ISO/IEC 18004 table 10, for column x and row y.
func maskBit(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	default:
		return ((x+y)%2+x*y%3)%2 == 0
	}
}

func (s *symbol) applyMask(mask int) {
	for y := 0; y < s.size; y++ {
		for x := 0; x < s.size; x++ {
			if !s.function[y][x] && maskBit(mask, x, y) {
				s.modules[y][x] = !s.modules[y][x]
			}
		}
	}
}

// penalty scores a finished symbol by the four rules of ISO/IEC 18004 7.8.3; lower reads better.
func (s *symbol) penalty() int {
	n := s.size
	score := 0
	line := func(get func(i int) bool) {
		run := 1
		for i := 1; i < n; i++ {
			if get(i) == get(i-1) {
				run++
				continue
			}
			if run >= 5 {
				score += 3 + run - 5
			}
			run = 1
		}
		if run >= 5 {
			score += 3 + run - 5
		}
		// Finder-like 1:1:3:1:1 with four light modules on one side.
		var b strings.Builder
		for i := 0; i < n; i++ {
			if get(i) {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
		row := b.String()
		score += 40 * (strings.Count(row, "10111010000") + strings.Count(row, "00001011101"))
	}
	for y := 0; y < n; y++ {
		line(func(i int) bool { return s.modules[y][i] })
	}
	for x := 0; x < n; x++ {
		line(func(i int) bool { return s.modules[i][x] })
	}
	dark := 0
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if s.modules[y][x] {
				dark++
			}
			if x < n-1 && y < n-1 {
				c := s.modules[y][x]
				if s.modules[y][x+1] == c && s.modules[y+1][x] == c && s.modules[y+1][x+1] == c {
					score += 3
				}
			}
		}
	}
	total := n * n
	k := (abs(dark*20-total*10)+total-1)/total - 1
	if k > 0 {
		score += 10 * k
	}
	return score
}

func (s *symbol) snapshot(mask int) *Code {
	out := grid(s.size)
	for y := range out {
		copy(out[y], s.modules[y])
	}
	return &Code{Size: s.size, Version: s.version, Mask: mask, Modules: out}
}

// SVG renders the code with a four-module quiet zone, scaled by the viewer: dark on light,
// whatever the page theme, so a phone camera always has the contrast it needs.
func (c *Code) SVG() string {
	const quiet = 4
	n := c.Size + 2*quiet
	var path strings.Builder
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Modules[y][x] {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`+
		`<rect width="%d" height="%d" fill="#fff"/><path d="%s" fill="#000"/></svg>`, n, n, n, n, path.String())
}
