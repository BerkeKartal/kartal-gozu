package tsdb

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// A day of samples lives in a directory named after it (UTC):
//
//	series  one line per series that has samples that day:
//	        <id> TAB <type> TAB <labels as JSON>
//	chunks  records of a header and a chunk's encoded samples
//	index   once the day is over: where each series' chunks are
//
// Days are independent: a query reads only the days it covers, and
// deleting a range removes or rewrites whole days. Pod names change with
// every rollout, so the series of a year would not fit in memory; a day's
// labels do, and its chunks are found through the index.

const (
	seriesFile = "series"
	chunksFile = "chunks"
	indexFile  = "index"
	dayLayout  = "2006-01-02"

	recordMagic  = 0x474b // "KG"
	recordHeader = 32

	indexMagic  = "KGI1"
	indexHeader = 12
	refSize     = 30
)

// record header, little endian:
//
//	0  magic   uint16
//	2  series  uint32
//	6  minT    int64
//	14 maxT    int64
//	22 count   uint16
//	24 length  uint32
//	28 crc32   uint32 (of the chunk bytes)
type chunkRef struct {
	off        int64 // of the chunk bytes
	length     uint32
	minT, maxT int64
	count      uint16
}

// index, little endian:
//
//	0  magic   "KGI1"
//	4  series  uint32 (n)
//	8  crc32   uint32 (of the offsets)
//	12 offsets (n+1) uint64: where each series' refs start, and the last end
//	   refs    30 bytes each: off int64, length uint32, minT int64,
//	           maxT int64, count uint16
func putRef(b []byte, r chunkRef) {
	binary.LittleEndian.PutUint64(b[0:], uint64(r.off))
	binary.LittleEndian.PutUint32(b[8:], r.length)
	binary.LittleEndian.PutUint64(b[12:], uint64(r.minT))
	binary.LittleEndian.PutUint64(b[20:], uint64(r.maxT))
	binary.LittleEndian.PutUint16(b[28:], r.count)
}

func getRef(b []byte) chunkRef {
	return chunkRef{
		off:    int64(binary.LittleEndian.Uint64(b[0:])),
		length: binary.LittleEndian.Uint32(b[8:]),
		minT:   int64(binary.LittleEndian.Uint64(b[12:])),
		maxT:   int64(binary.LittleEndian.Uint64(b[20:])),
		count:  binary.LittleEndian.Uint16(b[28:]),
	}
}

type blockSeries struct {
	labels Labels
	typ    string
	// chunks are today's; a closed day's are in its index.
	chunks []chunkRef
}

// lazyFile is read at offsets, opened on the first read; closing it lets
// the next read open it again.
type lazyFile struct {
	path string
	mu   sync.Mutex
	f    *os.File
}

func (l *lazyFile) readAt(buf []byte, off int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		f, err := os.Open(l.path)
		if err != nil {
			return err
		}
		l.f = f
	}
	_, err := l.f.ReadAt(buf, off)
	return err
}

func (l *lazyFile) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
}

// dayData reads a day's samples: through its index once it is over, or
// through refs held in memory.
type dayData struct {
	day    string
	chunks lazyFile
	index  lazyFile
	refAt  []int64 // nil: the refs are in the series
}

func (d *dayData) close() {
	d.chunks.close()
	d.index.close()
}

// refsAt reads a series' refs from the index.
func (d *dayData) refsAt(id int) ([]chunkRef, error) {
	start, end := d.refAt[id], d.refAt[id+1]
	if end < start || (end-start)%refSize != 0 {
		return nil, fmt.Errorf("%s: %w", d.day, errIndex)
	}
	buf := make([]byte, end-start)
	if err := d.index.readAt(buf, start); err != nil {
		return nil, err
	}
	out := make([]chunkRef, len(buf)/refSize)
	for i := range out {
		out[i] = getRef(buf[i*refSize:])
	}
	return out, nil
}

// points reads the samples within [from, to] of the chunks refs point at.
func (d *dayData) points(refs []chunkRef, from, to int64, out []Point) ([]Point, error) {
	for _, ref := range refs {
		if ref.maxT < from || ref.minT > to {
			continue
		}
		start := len(out)
		var err error
		if out, err = d.read(ref, out); err != nil {
			return out[:start], err
		}
		out = clip(out, start, from, to)
	}
	return out, nil
}

// read decodes a chunk; the record's magic and checksum must match.
func (d *dayData) read(ref chunkRef, out []Point) ([]Point, error) {
	buf := make([]byte, recordHeader+int(ref.length))
	if err := d.chunks.readAt(buf, ref.off-recordHeader); err != nil {
		return out, err
	}
	data := buf[recordHeader:]
	if binary.LittleEndian.Uint16(buf) != recordMagic || crc32.ChecksumIEEE(data) != binary.LittleEndian.Uint32(buf[28:]) {
		return out, fmt.Errorf("%s: %w", d.day, errChunk)
	}
	return decode(data, int(ref.count), out)
}

var errIndex = errors.New("tsdb: corrupt index")

// block is a day's series and where their samples are.
type block struct {
	day    string
	dir    string
	series []blockSeries
	data   *dayData
}

func newBlock(dir, day string, series []blockSeries, refAt []int64) *block {
	return &block{day: day, dir: dir, series: series, data: &dayData{
		day:    day,
		chunks: lazyFile{path: filepath.Join(dir, chunksFile)},
		index:  lazyFile{path: filepath.Join(dir, indexFile)},
		refAt:  refAt,
	}}
}

// refs are a series' chunks.
func (b *block) refs(id int) ([]chunkRef, error) {
	if b.data.refAt == nil {
		return b.series[id].chunks, nil
	}
	return b.data.refsAt(id)
}

// points returns a series' samples within [from, to].
func (b *block) points(id int, from, to int64, out []Point) ([]Point, error) {
	refs, err := b.refs(id)
	if err != nil {
		return out, err
	}
	return b.data.points(refs, from, to, out)
}

func (b *block) close() { b.data.close() }

func writeRecord(w io.Writer, id uint32, minT, maxT int64, count int, data []byte) error {
	var h [recordHeader]byte
	binary.LittleEndian.PutUint16(h[0:], recordMagic)
	binary.LittleEndian.PutUint32(h[2:], id)
	binary.LittleEndian.PutUint64(h[6:], uint64(minT))
	binary.LittleEndian.PutUint64(h[14:], uint64(maxT))
	binary.LittleEndian.PutUint16(h[22:], uint16(count))
	binary.LittleEndian.PutUint32(h[24:], uint32(len(data)))
	binary.LittleEndian.PutUint32(h[28:], crc32.ChecksumIEEE(data))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// readSeries reads a day's series file. A half-written last line, left
// by a crash, is dropped. The same names and values, which most series
// share, are kept once.
func readSeries(path string) ([]blockSeries, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	strs := map[string]string{}
	intern := func(s string) string {
		if v, ok := strs[s]; ok {
			return v
		}
		strs[s] = s
		return s
	}
	var out []blockSeries
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "\t", 3)
		if len(parts) != 3 {
			break
		}
		id, err := strconv.Atoi(parts[0])
		if err != nil || id != len(out) {
			break
		}
		ls, err := unmarshalLabels([]byte(parts[2]))
		if err != nil {
			break
		}
		for i := range ls {
			ls[i] = Label{intern(ls[i].Name), intern(ls[i].Value)}
		}
		out = append(out, blockSeries{labels: ls, typ: intern(parts[1])})
	}
	return out, sc.Err()
}

// scanChunks finds the chunks in a day's chunks file and returns how much
// of it is whole; a record cut short by a crash ends the scan.
func scanChunks(path string, series []blockSeries) (int64, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<16)
	var off int64
	var h [recordHeader]byte
	for {
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return off, nil
		}
		if binary.LittleEndian.Uint16(h[0:]) != recordMagic {
			return off, nil
		}
		id := binary.LittleEndian.Uint32(h[2:])
		length := binary.LittleEndian.Uint32(h[24:])
		if _, err := r.Discard(int(length)); err != nil {
			return off, nil
		}
		if int(id) < len(series) {
			series[id].chunks = append(series[id].chunks, chunkRef{
				off:    off + recordHeader,
				length: length,
				minT:   int64(binary.LittleEndian.Uint64(h[6:])),
				maxT:   int64(binary.LittleEndian.Uint64(h[14:])),
				count:  binary.LittleEndian.Uint16(h[22:]),
			})
		}
		off += recordHeader + int64(length)
	}
}

// writeIndex writes where a closed day's chunks are, from the refs its
// series hold, and returns where each series' refs start.
func writeIndex(dir string, series []blockSeries) ([]int64, error) {
	n := len(series)
	refAt := make([]int64, n+1)
	pos := int64(indexHeader + 8*(n+1))
	for i, s := range series {
		refAt[i] = pos
		pos += int64(len(s.chunks)) * refSize
	}
	refAt[n] = pos
	offs := make([]byte, 8*(n+1))
	for i, v := range refAt {
		binary.LittleEndian.PutUint64(offs[8*i:], uint64(v))
	}
	var h [indexHeader]byte
	copy(h[:], indexMagic)
	binary.LittleEndian.PutUint32(h[4:], uint32(n))
	binary.LittleEndian.PutUint32(h[8:], crc32.ChecksumIEEE(offs))
	// Written aside and renamed: two queries may write it at once.
	tmp, err := os.CreateTemp(dir, ".index-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	w := &syncedWriter{f: tmp, w: bufio.NewWriterSize(tmp, 1<<16)}
	w.w.Write(h[:])
	w.w.Write(offs)
	var rb [refSize]byte
	for _, s := range series {
		for _, r := range s.chunks {
			putRef(rb[:], r)
			w.w.Write(rb[:])
		}
	}
	if err := w.close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, indexFile)); err != nil {
		return nil, err
	}
	return refAt, nil
}

// readIndex reads where each of a day's n series' refs are, if the day has
// an index made for those series.
func readIndex(dir string, n int) ([]int64, error) {
	f, err := os.Open(filepath.Join(dir, indexFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	r := bufio.NewReader(f)
	var h [indexHeader]byte
	if _, err := io.ReadFull(r, h[:]); err != nil || string(h[:4]) != indexMagic || int(binary.LittleEndian.Uint32(h[4:])) != n {
		return nil, errIndex
	}
	offs := make([]byte, 8*(n+1))
	if _, err := io.ReadFull(r, offs); err != nil || crc32.ChecksumIEEE(offs) != binary.LittleEndian.Uint32(h[8:]) {
		return nil, errIndex
	}
	refAt := make([]int64, n+1)
	prev := int64(indexHeader + 8*(n+1))
	for i := range refAt {
		v := int64(binary.LittleEndian.Uint64(offs[8*i:]))
		if v < prev || (v-prev)%refSize != 0 {
			return nil, errIndex
		}
		refAt[i], prev = v, v
	}
	if refAt[n] != st.Size() {
		return nil, errIndex
	}
	return refAt, nil
}

// loadBlock reads a closed day. A day without a fitting index, such as one
// a crash or a deletion left, gets one made from its chunks; where that
// cannot be written, the refs stay in memory.
func loadBlock(dir, day string) (*block, error) {
	series, err := readSeries(filepath.Join(dir, seriesFile))
	if err != nil {
		return nil, err
	}
	if refAt, err := readIndex(dir, len(series)); err == nil {
		return newBlock(dir, day, series, refAt), nil
	}
	if _, err := scanChunks(filepath.Join(dir, chunksFile), series); err != nil {
		return nil, err
	}
	refAt, err := writeIndex(dir, series)
	if err != nil {
		return newBlock(dir, day, series, nil), nil
	}
	for i := range series {
		series[i].chunks = nil
	}
	return newBlock(dir, day, series, refAt), nil
}

func fileSize(path string) int64 {
	if st, err := os.Stat(path); err == nil {
		return st.Size()
	}
	return 0
}

// daySize is what a day takes on disk.
func daySize(dir string) int64 {
	return fileSize(filepath.Join(dir, seriesFile)) + fileSize(filepath.Join(dir, chunksFile)) + fileSize(filepath.Join(dir, indexFile))
}

// clip keeps out[:start] and the points of out[start:] within [from, to].
func clip(out []Point, start int, from, to int64) []Point {
	keep := out[:start]
	for _, p := range out[start:] {
		if p.T >= from && p.T <= to {
			keep = append(keep, p)
		}
	}
	return keep
}

// rewriteDay writes a day's samples outside [from, to] into a new
// directory and swaps it in. It returns false when nothing is left. The
// new day has no index yet; it gets one when it is next read.
func rewriteDay(dir string, b *block, from, to int64) (bool, error) {
	tmp := dir + ".tmp"
	os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return false, err
	}
	// The new day is written as it is made: a day can be large.
	sf, err := newSyncedWriter(filepath.Join(tmp, seriesFile))
	if err != nil {
		os.RemoveAll(tmp)
		return false, err
	}
	cf, err := newSyncedWriter(filepath.Join(tmp, chunksFile))
	if err != nil {
		sf.abort()
		os.RemoveAll(tmp)
		return false, err
	}
	fail := func(err error) (bool, error) {
		sf.abort()
		cf.abort()
		os.RemoveAll(tmp)
		return false, err
	}
	kept := 0
	var pts, left []Point
	for id, s := range b.series {
		refs, err := b.refs(id)
		if err != nil {
			return fail(err)
		}
		pts = pts[:0]
		for _, ref := range refs {
			if pts, err = b.data.read(ref, pts); err != nil {
				return fail(err)
			}
		}
		left = left[:0]
		for _, p := range pts {
			if p.T < from || p.T > to {
				left = append(left, p)
			}
		}
		if len(left) == 0 {
			continue
		}
		nid := uint32(kept)
		if _, err := fmt.Fprintf(sf.w, "%d\t%s\t%s\n", nid, s.typ, s.labels.marshal()); err != nil {
			return fail(err)
		}
		for i := 0; i < len(left); i += maxChunkSamples {
			var e encoder
			part := left[i:min(i+maxChunkSamples, len(left))]
			for _, p := range part {
				e.add(p.T, p.V)
			}
			if err := writeRecord(cf.w, nid, part[0].T, part[len(part)-1].T, len(part), e.bytes()); err != nil {
				return fail(err)
			}
		}
		kept++
	}
	b.close()
	if kept == 0 {
		sf.abort()
		cf.abort()
		os.RemoveAll(tmp)
		return false, os.RemoveAll(dir)
	}
	for _, w := range []*syncedWriter{sf, cf} {
		if err := w.close(); err != nil {
			return fail(err)
		}
	}
	old := dir + ".old"
	os.RemoveAll(old)
	if err := os.Rename(dir, old); err != nil {
		os.RemoveAll(tmp)
		return false, err
	}
	if err := os.Rename(tmp, dir); err != nil {
		os.Rename(old, dir)
		return false, err
	}
	return true, os.RemoveAll(old)
}

// syncedWriter writes a new file through a buffer and syncs it on close.
type syncedWriter struct {
	f *os.File
	w *bufio.Writer
}

func newSyncedWriter(path string) (*syncedWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &syncedWriter{f: f, w: bufio.NewWriterSize(f, 1<<16)}, nil
}

func (s *syncedWriter) close() error {
	if err := s.w.Flush(); err != nil {
		s.f.Close()
		return err
	}
	if err := s.f.Sync(); err != nil {
		s.f.Close()
		return err
	}
	return s.f.Close()
}

// abort closes the file without caring for what is in it.
func (s *syncedWriter) abort() { s.f.Close() }
