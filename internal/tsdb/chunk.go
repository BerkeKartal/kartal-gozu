package tsdb

import (
	"errors"
	"math"
	"math/bits"
)

// A chunk holds up to maxChunkSamples samples of one series, compressed the
// way Gorilla (Facebook's time series database, and Prometheus after it)
// does: timestamps as the difference of their differences, values as the
// XOR with the previous value. Scraped metrics come at a steady pace and
// change little, so a sample takes one or two bytes instead of sixteen.
const maxChunkSamples = 120

var errChunk = errors.New("tsdb: corrupt chunk")

// bitWriter appends bits to a byte slice.
type bitWriter struct {
	b    []byte
	free uint8 // unused bits in the last byte
}

func (w *bitWriter) writeBit(bit bool) {
	if w.free == 0 {
		w.b = append(w.b, 0)
		w.free = 8
	}
	if bit {
		w.b[len(w.b)-1] |= 1 << (w.free - 1)
	}
	w.free--
}

// writeBits writes the n lowest bits of u, the highest of them first.
func (w *bitWriter) writeBits(u uint64, n int) {
	for n > 0 {
		if w.free == 0 {
			w.b = append(w.b, 0)
			w.free = 8
		}
		take := min(int(w.free), n)
		part := byte(u>>(n-take)) & byte(1<<take-1)
		w.b[len(w.b)-1] |= part << (int(w.free) - take)
		w.free -= uint8(take)
		n -= take
	}
}

// bitReader reads what bitWriter wrote.
type bitReader struct {
	b   []byte
	pos int // in bits
}

func (r *bitReader) readBit() (bool, error) {
	if r.pos >= len(r.b)*8 {
		return false, errChunk
	}
	bit := r.b[r.pos/8]&(1<<(7-r.pos%8)) != 0
	r.pos++
	return bit, nil
}

func (r *bitReader) readBits(n int) (uint64, error) {
	if r.pos+n > len(r.b)*8 {
		return 0, errChunk
	}
	var u uint64
	for n > 0 {
		off := r.pos % 8
		take := min(8-off, n)
		part := uint64(r.b[r.pos/8]>>(8-off-take)) & (1<<take - 1)
		u = u<<take | part
		r.pos += take
		n -= take
	}
	return u, nil
}

// encoder builds a chunk sample by sample.
type encoder struct {
	w         bitWriter
	n         int
	minT      int64
	t, tDelta int64
	v         uint64
	leading   uint8
	trailing  uint8
}

// add appends a sample; timestamps must not go backwards.
func (e *encoder) add(t int64, v float64) {
	vb := math.Float64bits(v)
	if e.n == 0 {
		e.w.writeBits(uint64(t), 64)
		e.w.writeBits(vb, 64)
		e.minT, e.t, e.v, e.leading = t, t, vb, 0xff
		e.n = 1
		return
	}
	delta := t - e.t
	e.writeDoD(delta - e.tDelta)
	e.writeXOR(vb)
	e.t, e.tDelta, e.v = t, delta, vb
	e.n++
}

// Buckets for the difference of differences: most are zero (a steady
// scrape interval), the rest small (jitter).
func (e *encoder) writeDoD(dod int64) {
	switch {
	case dod == 0:
		e.w.writeBit(false)
	case dod >= -64 && dod <= 63:
		e.w.writeBits(0b10, 2)
		e.w.writeBits(uint64(dod), 7)
	case dod >= -256 && dod <= 255:
		e.w.writeBits(0b110, 3)
		e.w.writeBits(uint64(dod), 9)
	case dod >= -2048 && dod <= 2047:
		e.w.writeBits(0b1110, 4)
		e.w.writeBits(uint64(dod), 12)
	default:
		e.w.writeBits(0b1111, 4)
		e.w.writeBits(uint64(dod), 64)
	}
}

func (e *encoder) writeXOR(vb uint64) {
	x := vb ^ e.v
	if x == 0 {
		e.w.writeBit(false)
		return
	}
	e.w.writeBit(true)
	leading := uint8(min(bits.LeadingZeros64(x), 31))
	trailing := uint8(bits.TrailingZeros64(x))
	if e.leading != 0xff && leading >= e.leading && trailing >= e.trailing {
		// The meaningful bits fit in the previous window.
		e.w.writeBit(false)
		e.w.writeBits(x>>e.trailing, 64-int(e.leading)-int(e.trailing))
		return
	}
	e.leading, e.trailing = leading, trailing
	e.w.writeBit(true)
	e.w.writeBits(uint64(leading), 5)
	sig := 64 - int(leading) - int(trailing)
	e.w.writeBits(uint64(sig&63), 6) // 64 meaningful bits travel as 0
	e.w.writeBits(x>>trailing, sig)
}

// bytes returns the chunk's encoded samples.
func (e *encoder) bytes() []byte { return e.w.b }

// Point is a sample: milliseconds since the Unix epoch, and a value.
type Point struct {
	T int64   `json:"t"`
	V float64 `json:"v"`
}

// decode reads n samples from a chunk, appending them to out.
func decode(b []byte, n int, out []Point) ([]Point, error) {
	if n == 0 {
		return out, nil
	}
	r := bitReader{b: b}
	tu, err := r.readBits(64)
	if err != nil {
		return out, err
	}
	vb, err := r.readBits(64)
	if err != nil {
		return out, err
	}
	t := int64(tu)
	out = append(out, Point{t, math.Float64frombits(vb)})
	var tDelta int64
	leading, trailing := uint8(0), uint8(0)
	for i := 1; i < n; i++ {
		dod, err := readDoD(&r)
		if err != nil {
			return out, err
		}
		tDelta += dod
		t += tDelta
		bit, err := r.readBit()
		if err != nil {
			return out, err
		}
		if bit {
			fresh, err := r.readBit()
			if err != nil {
				return out, err
			}
			if fresh {
				l, err := r.readBits(5)
				if err != nil {
					return out, err
				}
				s, err := r.readBits(6)
				if err != nil {
					return out, err
				}
				if s == 0 {
					s = 64
				}
				leading, trailing = uint8(l), uint8(64-int(l)-int(s))
			}
			sig := 64 - int(leading) - int(trailing)
			x, err := r.readBits(sig)
			if err != nil {
				return out, err
			}
			vb ^= x << trailing
		}
		out = append(out, Point{t, math.Float64frombits(vb)})
	}
	return out, nil
}

func readDoD(r *bitReader) (int64, error) {
	prefix := 0
	for prefix < 4 {
		bit, err := r.readBit()
		if err != nil {
			return 0, err
		}
		if !bit {
			break
		}
		prefix++
	}
	width := [...]int{0, 7, 9, 12, 64}[prefix]
	if width == 0 {
		return 0, nil
	}
	u, err := r.readBits(width)
	if err != nil {
		return 0, err
	}
	if width == 64 {
		return int64(u), nil
	}
	// Sign-extend the width-bit two's complement number.
	shift := 64 - width
	return int64(u<<shift) >> shift, nil
}
