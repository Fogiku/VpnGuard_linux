// Кодировщик QR-кода (ISO/IEC 18004): байтовый режим, уровни коррекции L/M/Q/H.
// Перенос qr.cs Windows-версии (тот же алгоритм, что в библиотеке Project Nayuki). Нужен для QR входа в MeduzaVPN
// и конфигураций клиентов WG-Server; внешних библиотек не требует.
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

var qrFormatBits = [4]int{1, 0, 3, 2}
var qrEccPerBlock = [4][41]int{
	{-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	{-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},
	{-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	{-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30}}
var qrNumBlocks = [4][41]int{
	{-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},
	{-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},
	{-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},
	{-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81}}

type qrGrid struct {
	n     int
	m, fn [][]bool // m[y][x]: true — тёмный модуль; fn — служебный модуль (маска его не трогает)
}

// qrEncode: текст → матрица модулей. ecl: 0=L 1=M 2=Q 3=H; mask -1 — выбрать лучшую.
func qrEncode(text string, ecl, mask int) (*qrGrid, error) {
	data := []byte(text)
	ver := 1
	for ; ; ver++ {
		if ver > 40 {
			return nil, errors.New("слишком длинный текст для QR-кода")
		}
		lenBits := 8
		if ver > 9 {
			lenBits = 16
		}
		if 4+lenBits+len(data)*8 <= qrDataCodewords(ver, ecl)*8 {
			break
		}
	}
	var bits []bool
	add := func(v, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, (v>>i)&1 != 0)
		}
	}
	add(4, 4)
	if ver <= 9 {
		add(len(data), 8)
	} else {
		add(len(data), 16)
	}
	for _, b := range data {
		add(int(b), 8)
	}
	capBits := qrDataCodewords(ver, ecl) * 8
	add(0, min(4, capBits-len(bits)))
	add(0, (8-len(bits)%8)%8)
	for pad := 0xEC; len(bits) < capBits; pad ^= 0xEC ^ 0x11 {
		add(pad, 8)
	}
	cw := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b {
			cw[i>>3] |= 1 << (7 - i&7)
		}
	}
	all := qrEccInterleave(cw, ver, ecl)
	g := &qrGrid{n: ver*4 + 17}
	g.m, g.fn = make([][]bool, g.n), make([][]bool, g.n)
	for i := range g.m {
		g.m[i], g.fn[i] = make([]bool, g.n), make([]bool, g.n)
	}
	g.functionPatterns(ver, ecl)
	g.codewords(all)
	if mask < 0 {
		best := int(^uint(0) >> 1)
		for k := 0; k < 8; k++ {
			g.applyMask(k)
			g.formatBits(ecl, k)
			if p := g.penalty(); p < best {
				best, mask = p, k
			}
			g.applyMask(k) // XOR — снять
		}
	}
	g.applyMask(mask)
	g.formatBits(ecl, mask)
	return g, nil
}
func qrRawModules(ver int) int {
	r := (16*ver+128)*ver + 64
	if ver >= 2 {
		na := ver/7 + 2
		r -= (25*na-10)*na - 55
		if ver >= 7 {
			r -= 36
		}
	}
	return r
}
func qrDataCodewords(ver, ecl int) int {
	return qrRawModules(ver)/8 - qrEccPerBlock[ecl][ver]*qrNumBlocks[ecl][ver]
}
func qrEccInterleave(data []byte, ver, ecl int) []byte {
	nb, eccLen := qrNumBlocks[ecl][ver], qrEccPerBlock[ecl][ver]
	raw := qrRawModules(ver) / 8
	numShort, shortLen := nb-raw%nb, raw/nb
	div := qrRsDivisor(eccLen)
	var blocks [][]byte
	for i, k := 0, 0; i < nb; i++ {
		n := shortLen - eccLen
		if i >= numShort {
			n++
		}
		dat := data[k : k+n]
		k += n
		block := make([]byte, shortLen+1)
		copy(block, dat)
		copy(block[len(block)-eccLen:], qrRsRemainder(dat, div))
		blocks = append(blocks, block)
	}
	var res []byte
	for i := 0; i < shortLen+1; i++ {
		for j := 0; j < nb; j++ {
			if i != shortLen-eccLen || j >= numShort {
				res = append(res, blocks[j][i])
			}
		}
	}
	return res
}
func qrGfMul(x, y int) int {
	z := 0
	for i := 7; i >= 0; i-- {
		z = (z << 1) ^ ((z >> 7) * 0x11D)
		z ^= ((y >> i) & 1) * x
	}
	return z & 0xFF
}
func qrRsDivisor(deg int) []byte {
	r := make([]byte, deg)
	r[deg-1] = 1
	root := 1
	for i := 0; i < deg; i++ {
		for j := range r {
			r[j] = byte(qrGfMul(int(r[j]), root))
			if j+1 < len(r) {
				r[j] ^= r[j+1]
			}
		}
		root = qrGfMul(root, 2)
	}
	return r
}
func qrRsRemainder(data, div []byte) []byte {
	r := make([]byte, len(div))
	for _, b := range data {
		f := int(b ^ r[0])
		copy(r, r[1:])
		r[len(r)-1] = 0
		for i := range r {
			r[i] ^= byte(qrGfMul(int(div[i]), f))
		}
	}
	return r
}
func (g *qrGrid) set(x, y int, dark bool) { g.m[y][x], g.fn[y][x] = dark, true }
func (g *qrGrid) functionPatterns(ver, ecl int) {
	for i := 0; i < g.n; i++ {
		g.set(6, i, i%2 == 0)
		g.set(i, 6, i%2 == 0)
	}
	g.finder(3, 3)
	g.finder(g.n-4, 3)
	g.finder(3, g.n-4)
	al := qrAlign(ver, g.n)
	n := len(al)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if (i == 0 && j == 0) || (i == 0 && j == n-1) || (i == n-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					g.set(al[i]+dx, al[j]+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	g.formatBits(ecl, 0) // место под формат (перезапишется)
	if ver >= 7 {
		rem := ver
		for i := 0; i < 12; i++ {
			rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
		}
		b := ver<<12 | rem
		for i := 0; i < 18; i++ {
			bit := (b>>i)&1 != 0
			a, c := g.n-11+i%3, i/3
			g.set(a, c, bit)
			g.set(c, a, bit)
		}
	}
}
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
func (g *qrGrid) finder(x, y int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			d, xx, yy := max(abs(dx), abs(dy)), x+dx, y+dy
			if xx >= 0 && xx < g.n && yy >= 0 && yy < g.n {
				g.set(xx, yy, d != 2 && d != 4)
			}
		}
	}
}
func qrAlign(ver, size int) []int {
	if ver == 1 {
		return nil
	}
	na := ver/7 + 2
	step := 26
	if ver != 32 {
		step = (ver*4 + 4 + na*2 - 3) / (na*2 - 2) * 2 // ceil((ver*4+4)/(na*2-2))*2
	}
	r := make([]int, na)
	r[0] = 6
	for i, pos := na-1, size-7; i >= 1; i, pos = i-1, pos-step {
		r[i] = pos
	}
	return r
}
func (g *qrGrid) formatBits(ecl, mask int) {
	data := qrFormatBits[ecl]<<3 | mask
	rem := data
	for i := 0; i < 10; i++ {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	b := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return (b>>i)&1 != 0 }
	for i := 0; i <= 5; i++ {
		g.set(8, i, bit(i))
	}
	g.set(8, 7, bit(6))
	g.set(8, 8, bit(7))
	g.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		g.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		g.set(g.n-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		g.set(8, g.n-15+i, bit(i))
	}
	g.set(8, g.n-8, true)
}
func (g *qrGrid) codewords(data []byte) {
	i := 0
	for right := g.n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < g.n; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = g.n - 1 - vert
				}
				if !g.fn[y][x] && i < len(data)*8 {
					g.m[y][x] = (data[i>>3]>>(7-i&7))&1 != 0
					i++
				}
			}
		}
	}
}
func (g *qrGrid) applyMask(mask int) {
	for y := 0; y < g.n; y++ {
		for x := 0; x < g.n; x++ {
			var inv bool
			switch mask {
			case 0:
				inv = (x+y)%2 == 0
			case 1:
				inv = y%2 == 0
			case 2:
				inv = x%3 == 0
			case 3:
				inv = (x+y)%3 == 0
			case 4:
				inv = (x/3+y/2)%2 == 0
			case 5:
				inv = x*y%2+x*y%3 == 0
			case 6:
				inv = (x*y%2+x*y%3)%2 == 0
			default:
				inv = ((x+y)%2+x*y%3)%2 == 0
			}
			if !g.fn[y][x] && inv {
				g.m[y][x] = !g.m[y][x]
			}
		}
	}
}

// penalty — штраф маски по правилам стандарта (правило 3 — шаблон 1:1:3:1:1 с белым полем), как в qr.cs.
func (g *qrGrid) penalty() int {
	r, n := 0, g.n
	pat := []bool{true, false, true, true, true, false, true}
	for pass := 0; pass < 2; pass++ {
		at := func(a, b int) bool {
			if pass == 0 {
				return g.m[a][b]
			}
			return g.m[b][a]
		}
		for a := 0; a < n; a++ {
			run := 1
			for b := 1; b < n; b++ {
				if at(a, b) == at(a, b-1) {
					run++
					if run == 5 {
						r += 3
					} else if run > 5 {
						r++
					}
				} else {
					run = 1
				}
			}
			for b := 0; b+10 < n; b++ {
				p1, p2, w1, w2 := true, true, true, true
				for k := 0; k < 7; k++ {
					if at(a, b+k) != pat[k] {
						p1 = false
					}
					if at(a, b+4+k) != pat[k] {
						p2 = false
					}
				}
				for k := 0; k < 4; k++ {
					if at(a, b+7+k) {
						w1 = false
					}
					if at(a, b+k) {
						w2 = false
					}
				}
				if p1 && w1 {
					r += 40
				}
				if p2 && w2 {
					r += 40
				}
			}
		}
	}
	dark := 0
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if g.m[y][x] {
				dark++
			}
			if x+1 < n && y+1 < n {
				c := g.m[y][x]
				if c == g.m[y][x+1] && c == g.m[y+1][x] && c == g.m[y+1][x+1] {
					r += 3
				}
			}
		}
	}
	total := n * n
	if k := (abs(dark*20-total*10)+total-1)/total - 1; k > 0 {
		r += k * 10
	}
	return r
}

// qrImage — QR-код картинкой (SVG в data: URI) для поля Table.Img. Пустая строка — текст не поместился.
func qrImage(text string) string {
	g, err := qrEncode(text, 1, -1)
	if err != nil {
		if g, err = qrEncode(text, 0, -1); err != nil {
			return ""
		}
	}
	const q = 4 // тихая зона
	var p strings.Builder
	for y := 0; y < g.n; y++ {
		for x := 0; x < g.n; x++ {
			if g.m[y][x] {
				fmt.Fprintf(&p, "M%d %dh1v1h-1z", x+q, y+q)
			}
		}
	}
	s := g.n + 2*q
	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path d="%s" fill="#000"/></svg>`, s, s, s, s, p.String())
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg))
}
