package tsdb

import (
	"testing"
)

// FuzzDecode checks that a damaged chunk gives an error, never a crash.
func FuzzDecode(f *testing.F) {
	var e encoder
	for i := int64(0); i < 50; i++ {
		e.add(1_700_000_000_000+i*30_000, float64(i*i))
	}
	f.Add(e.bytes(), 50)
	f.Add([]byte{0xff, 0x00, 0x13}, 3)
	f.Fuzz(func(t *testing.T, b []byte, n int) {
		if n < 0 || n > 1000 {
			return
		}
		decode(b, n, nil)
	})
}
