// Package tsdb keeps time series on disk, with nothing but the standard
// library: a directory per day, chunks compressed as in Gorilla, samples
// kept until someone deletes a range. Today's chunks fill up in memory and
// reach the disk when full and every few minutes, so a crash loses at most
// those minutes.
package tsdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Sample is one value to store.
type Sample struct {
	Labels Labels
	Type   string
	Value  float64
}

// Series is a series found by a query, with its points in time order.
type Series struct {
	Labels Labels
	Type   string
	Points []Point
}

// A query stops before it holds more than this; the caller should narrow
// it down.
const (
	MaxSeries = 20000
	MaxPoints = 10_000_000
)

// ErrTooMuch says a query matched more than MaxSeries or MaxPoints.
var ErrTooMuch = errors.New("the query matches too much data; narrow it down with label filters or a shorter time range")

// MaxDaySeries bounds the series of one day: past it, new series are not
// stored that day, so that an app that puts, say, request IDs in its
// labels cannot fill the server's memory. A series in today's block takes
// a kilobyte or two of memory.
const MaxDaySeries = 100_000

// ErrDaySeries says some samples were not stored, as today has MaxDaySeries
// series already.
var ErrDaySeries = fmt.Errorf("today already has %d series, the most a day may have; new series are not stored until tomorrow", MaxDaySeries)

// daySeries is MaxDaySeries, lower in tests.
var daySeries = MaxDaySeries

// MaxLabelBytes bounds a series' labels, written out: a page may hold
// lines of a megabyte, and a series file must stay readable.
const MaxLabelBytes = 16 << 10

// ErrLabelsTooLong says some samples were not stored, as their labels were
// longer than MaxLabelBytes.
var ErrLabelsTooLong = fmt.Errorf("some series have labels longer than %d KiB; they are not stored", MaxLabelBytes>>10)

// cachedBlocks is how many closed days stay loaded for queries.
const cachedBlocks = 8

// farFuture is the last millisecond of the year 9999, the end of "all".
const farFuture = 253402300799999

// head is today: a block whose last chunks are still being filled.
type head struct {
	*block
	byKey   map[string]uint32
	open    []*encoder
	lastT   []int64
	seriesW *os.File
	chunksW *os.File
	end     int64 // of the whole records in the chunks file
}

func openHead(root, day string) (*head, error) {
	dir := filepath.Join(root, day)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	sp, cp := filepath.Join(dir, seriesFile), filepath.Join(dir, chunksFile)
	// Today changes; an index made for it before, when the clock was
	// ahead, would not fit any more.
	os.Remove(filepath.Join(dir, indexFile))
	if err := trimPartialLine(sp); err != nil {
		return nil, err
	}
	series, err := readSeries(sp)
	if err != nil {
		return nil, err
	}
	end, err := scanChunks(cp, series)
	if err != nil {
		return nil, err
	}
	// A record a crash cut short would sit between the old and new ones.
	if fileSize(cp) > end {
		if err := os.Truncate(cp, end); err != nil {
			return nil, err
		}
	}
	h := &head{
		block: newBlock(dir, day, series, nil),
		byKey: make(map[string]uint32, len(series)),
		open:  make([]*encoder, len(series)),
		lastT: make([]int64, len(series)),
		end:   end,
	}
	for i, s := range series {
		h.byKey[s.labels.key()] = uint32(i)
		h.lastT[i] = math.MinInt64
		for _, c := range s.chunks {
			h.lastT[i] = max(h.lastT[i], c.maxT)
		}
	}
	if h.seriesW, err = os.OpenFile(sp, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
		return nil, err
	}
	if h.chunksW, err = os.OpenFile(cp, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
		h.seriesW.Close()
		return nil, err
	}
	return h, nil
}

// trimPartialLine drops a series line that a crash left half written.
func trimPartialLine(path string) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) || len(b) == 0 || b[len(b)-1] == '\n' {
		return nil
	}
	if err != nil {
		return err
	}
	return os.Truncate(path, int64(bytes.LastIndexByte(b, '\n')+1))
}

func (h *head) append(s Sample, t int64) error {
	key := s.Labels.key()
	id, ok := h.byKey[key]
	if !ok {
		if len(h.series) >= daySeries {
			return ErrDaySeries
		}
		labels := s.Labels.marshal()
		if len(labels) > MaxLabelBytes {
			return ErrLabelsTooLong
		}
		// The type ends up between tabs, on a line of its own.
		if strings.ContainsAny(s.Type, "\t\r\n") {
			s.Type = "untyped"
		}
		id = uint32(len(h.series))
		if _, err := fmt.Fprintf(h.seriesW, "%d\t%s\t%s\n", id, s.Type, labels); err != nil {
			return err
		}
		h.series = append(h.series, blockSeries{labels: s.Labels, typ: s.Type})
		h.byKey[key] = id
		h.open = append(h.open, nil)
		h.lastT = append(h.lastT, math.MinInt64)
	}
	if t <= h.lastT[id] {
		return nil // already have this moment
	}
	e := h.open[id]
	if e == nil {
		e = &encoder{}
		h.open[id] = e
	}
	e.add(t, s.Value)
	h.lastT[id] = t
	if e.n >= maxChunkSamples {
		return h.cut(id)
	}
	return nil
}

// cut writes a series' open chunk to the day's file.
func (h *head) cut(id uint32) error {
	e := h.open[id]
	var buf bytes.Buffer
	if err := writeRecord(&buf, id, e.minT, e.t, e.n, e.bytes()); err != nil {
		return err
	}
	if _, err := h.chunksW.Write(buf.Bytes()); err != nil {
		return err
	}
	h.series[id].chunks = append(h.series[id].chunks, chunkRef{
		off: h.end + recordHeader, length: uint32(len(e.bytes())), minT: e.minT, maxT: e.t, count: uint16(e.n),
	})
	h.end += int64(buf.Len())
	h.open[id] = nil
	return nil
}

// flush writes every open chunk and syncs the files.
func (h *head) flush() error {
	for id, e := range h.open {
		if e != nil && e.n > 0 {
			if err := h.cut(uint32(id)); err != nil {
				return err
			}
		}
	}
	if err := h.seriesW.Sync(); err != nil {
		return err
	}
	return h.chunksW.Sync()
}

func (h *head) closeWriters() error {
	err := h.flush()
	h.seriesW.Close()
	h.chunksW.Close()
	return err
}

// points returns a series' samples within [from, to], open chunk included.
func (h *head) points(id int, from, to int64) ([]Point, error) {
	out, err := h.block.points(id, from, to, nil)
	if err != nil {
		return out, err
	}
	if e := h.open[id]; e != nil && e.n > 0 && e.t >= from && e.minT <= to {
		start := len(out)
		if out, err = decode(e.bytes(), e.n, out); err != nil {
			return out[:start], err
		}
		out = clip(out, start, from, to)
	}
	return out, nil
}

// DB is the store.
type DB struct {
	root string

	mu   sync.RWMutex // held exclusively to change days: rollover, delete, close
	hmu  sync.Mutex   // guards the head's contents
	head *head

	cmu   sync.Mutex
	cache map[string]*block
	order []string
}

// Open opens or creates a store in dir.
func Open(dir string) (*DB, error) { return openAt(dir, time.Now()) }

// OpenAt opens the store as if it were the day of now: samples from then
// on can be appended, in time order, such as history being imported.
func OpenAt(dir string, now time.Time) (*DB, error) { return openAt(dir, now) }

// openAt opens the store with now as today.
func openAt(dir string, now time.Time) (*DB, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	cleanLeftovers(dir)
	h, err := openHead(dir, dayOf(now.UnixMilli()))
	if err != nil {
		return nil, err
	}
	return &DB{root: dir, head: h, cache: map[string]*block{}}, nil
}

// cleanLeftovers finishes or undoes a rewrite that a crash interrupted.
func cleanLeftovers(root string) {
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".tmp"):
			os.RemoveAll(filepath.Join(root, name))
		case strings.HasSuffix(name, ".old"):
			day := strings.TrimSuffix(name, ".old")
			if _, err := os.Stat(filepath.Join(root, day)); errors.Is(err, os.ErrNotExist) {
				os.Rename(filepath.Join(root, name), filepath.Join(root, day))
			} else {
				os.RemoveAll(filepath.Join(root, name))
			}
		}
	}
}

func dayOf(ms int64) string { return time.UnixMilli(ms).UTC().Format(dayLayout) }

// dayBounds is a day's first and last millisecond.
func dayBounds(day string) (int64, int64) {
	t, _ := time.Parse(dayLayout, day)
	return t.UnixMilli(), t.Add(24*time.Hour).UnixMilli() - 1
}

// Append stores samples taken at the given moment. A series' samples must
// come in time order; one for a moment it already has is ignored.
func (db *DB) Append(at time.Time, samples []Sample) error {
	t := at.UnixMilli()
	day := dayOf(t)
	db.mu.RLock()
	if day > db.head.day {
		db.mu.RUnlock()
		if err := db.rollover(day); err != nil {
			return err
		}
		db.mu.RLock()
	}
	defer db.mu.RUnlock()
	if day < db.head.day {
		return nil // the clock went back past midnight
	}
	db.hmu.Lock()
	defer db.hmu.Unlock()
	skipped := map[error]int{}
	for _, s := range samples {
		err := db.head.append(s, t)
		if err == ErrDaySeries || err == ErrLabelsTooLong {
			skipped[err]++
			continue
		}
		if err != nil {
			return err
		}
	}
	for _, e := range []error{ErrDaySeries, ErrLabelsTooLong} {
		if n := skipped[e]; n > 0 {
			return fmt.Errorf("%w (%d samples left out)", e, n)
		}
	}
	return nil
}

func (db *DB) rollover(day string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if day <= db.head.day {
		return nil
	}
	db.hmu.Lock()
	defer db.hmu.Unlock()
	old := db.head
	err := old.closeWriters()
	old.block.close()
	// The day is over: its index lets queries find its chunks without
	// holding them all in memory. Should it fail, the day gets one when
	// it is next read.
	writeIndex(old.dir, old.series)
	h, herr := openHead(db.root, day)
	if herr != nil {
		return herr
	}
	db.head = h
	return err
}

// Flush writes today's open chunks to disk.
func (db *DB) Flush() error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	db.hmu.Lock()
	defer db.hmu.Unlock()
	return db.head.flush()
}

// Run flushes every so often until ctx ends; closing the store is left to
// the caller, once nothing writes to it any more.
func (db *DB) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			db.Flush()
		}
	}
}

// Close flushes and closes the store.
func (db *DB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.hmu.Lock()
	defer db.hmu.Unlock()
	err := db.head.closeWriters()
	db.head.block.close()
	db.cmu.Lock()
	for _, b := range db.cache {
		b.close()
	}
	db.cache, db.order = map[string]*block{}, nil
	db.cmu.Unlock()
	return err
}

func (db *DB) cachePut(b *block) {
	db.cmu.Lock()
	defer db.cmu.Unlock()
	if _, ok := db.cache[b.day]; !ok {
		db.order = append(db.order, b.day)
	}
	db.cache[b.day] = b
	for len(db.order) > cachedBlocks {
		old := db.order[0]
		db.order = db.order[1:]
		if c := db.cache[old]; c != nil {
			c.close()
		}
		delete(db.cache, old)
	}
}

func (db *DB) cacheDrop(day string) {
	db.cmu.Lock()
	defer db.cmu.Unlock()
	if b := db.cache[day]; b != nil {
		b.close()
		delete(db.cache, day)
		for i, d := range db.order {
			if d == day {
				db.order = append(db.order[:i], db.order[i+1:]...)
				break
			}
		}
	}
}

// blockFor returns a closed day, loading it if needed.
func (db *DB) blockFor(day string) (*block, error) {
	db.cmu.Lock()
	b := db.cache[day]
	db.cmu.Unlock()
	if b != nil {
		return b, nil
	}
	b, err := loadBlock(filepath.Join(db.root, day), day)
	if err != nil {
		return nil, err
	}
	db.cachePut(b)
	return b, nil
}

// days lists the stored days within [from, to], oldest first.
func (db *DB) days(from, to int64) []string {
	entries, _ := os.ReadDir(db.root)
	first, last := dayOf(from), dayOf(to)
	var out []string
	for _, e := range entries {
		if _, err := time.Parse(dayLayout, e.Name()); err != nil || !e.IsDir() {
			continue
		}
		if e.Name() >= first && e.Name() <= last {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// eachSeries calls f for every series of the days within [from, to] that
// sel picks, with a reader for its points; the head's lock is
// held while f runs for today's series.
func (db *DB) eachSeries(from, to int64, sel Selector, f func(ls Labels, typ string, points func() ([]Point, error)) error) error {
	for _, day := range db.days(from, to) {
		if day == db.head.day {
			db.hmu.Lock()
			h := db.head
			for id, s := range h.series {
				if !sel.match(s.labels) {
					continue
				}
				if err := f(s.labels, s.typ, func() ([]Point, error) { return h.points(id, from, to) }); err != nil {
					db.hmu.Unlock()
					return err
				}
			}
			db.hmu.Unlock()
			continue
		}
		b, err := db.blockFor(day)
		if err != nil {
			return err
		}
		for id, s := range b.series {
			if !sel.match(s.labels) {
				continue
			}
			if err := f(s.labels, s.typ, func() ([]Point, error) { return b.points(id, from, to, nil) }); err != nil {
				return err
			}
		}
	}
	return nil
}

// Select returns the series sel picks, with their points within
// [from, to] (milliseconds), sorted by labels.
func (db *DB) Select(from, to int64, sel Selector) ([]Series, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	byKey := map[string]*Series{}
	total := 0
	err := db.eachSeries(from, to, sel, func(ls Labels, typ string, points func() ([]Point, error)) error {
		pts, err := points()
		if err != nil {
			return err
		}
		if len(pts) == 0 {
			return nil
		}
		key := ls.key()
		s := byKey[key]
		if s == nil {
			if len(byKey) >= MaxSeries {
				return ErrTooMuch
			}
			s = &Series{Labels: ls, Type: typ}
			byKey[key] = s
		}
		s.Points = append(s.Points, pts...)
		if total += len(pts); total > MaxPoints {
			return ErrTooMuch
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]Series, 0, len(byKey))
	for _, s := range byKey {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Labels.String() < out[j].Labels.String() })
	return out, nil
}

// MaxEachSeries bounds the series one Each goes through: their labels are
// held for its whole run.
const MaxEachSeries = 200_000

// Each calls f with every series sel picks that has samples within
// [from, to], one at a time, sorted by labels: however long the range,
// only one series' points are held at once. The points are only good
// until f returns.
func (db *DB) Each(from, to int64, sel Selector, f func(Series) error) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	// A part is a series' share of one day: today's by its id, a closed
	// day's by where its refs are. Parts hold no day's labels, so the days
	// already gone through can leave memory.
	type part struct {
		d    *dayData // nil for today
		id   int
		refs []chunkRef // a closed day's, when it has no index
	}
	type entry struct {
		labels Labels
		typ    string
		sort   string
		parts  []part
	}
	byKey := map[string]*entry{}
	var entries []*entry
	add := func(s blockSeries, p part) error {
		k := s.labels.key()
		e := byKey[k]
		if e == nil {
			if len(entries) >= MaxEachSeries {
				return ErrTooMuch
			}
			e = &entry{labels: s.labels, typ: s.typ, sort: s.labels.String()}
			byKey[k] = e
			entries = append(entries, e)
		}
		e.parts = append(e.parts, p)
		return nil
	}
	for _, day := range db.days(from, to) {
		if day == db.head.day {
			db.hmu.Lock()
			for id, s := range db.head.series {
				if sel.match(s.labels) {
					if err := add(s, part{id: id}); err != nil {
						db.hmu.Unlock()
						return err
					}
				}
			}
			db.hmu.Unlock()
			continue
		}
		b, err := db.blockFor(day)
		if err != nil {
			return err
		}
		for id, s := range b.series {
			if !sel.match(s.labels) {
				continue
			}
			p := part{d: b.data, id: id}
			if b.data.refAt == nil {
				p.refs = s.chunks
			}
			if err := add(s, p); err != nil {
				return err
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].sort < entries[j].sort })
	var buf []Point
	for _, e := range entries {
		pts := buf[:0]
		for _, p := range e.parts {
			var err error
			switch {
			case p.d == nil:
				db.hmu.Lock()
				var got []Point
				got, err = db.head.points(p.id, from, to)
				db.hmu.Unlock()
				pts = append(pts, got...)
			case p.d.refAt == nil:
				pts, err = p.d.points(p.refs, from, to, pts)
			default:
				var refs []chunkRef
				if refs, err = p.d.refsAt(p.id); err == nil {
					pts, err = p.d.points(refs, from, to, pts)
				}
			}
			if err != nil {
				return err
			}
		}
		if len(pts) == 0 {
			continue
		}
		if err := f(Series{Labels: e.labels, Type: e.typ, Points: pts}); err != nil {
			return err
		}
		buf = pts
	}
	return nil
}

// MetricInfo describes a stored metric.
type MetricInfo struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Series int    `json:"series"`
}

// Metrics lists the metrics stored within [from, to] among the series sel
// picks, without reading their samples.
func (db *DB) Metrics(from, to int64, sel Selector) ([]MetricInfo, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	byName := map[string]*MetricInfo{}
	seen := map[string]bool{}
	err := db.eachSeries(from, to, sel, func(ls Labels, typ string, _ func() ([]Point, error)) error {
		key := ls.key()
		if seen[key] {
			return nil
		}
		seen[key] = true
		name := ls.Get(MetricName)
		m := byName[name]
		if m == nil {
			m = &MetricInfo{Name: name, Type: typ}
			byName[name] = m
		}
		m.Series++
		return nil
	})
	out := make([]MetricInfo, 0, len(byName))
	for _, m := range byName {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// LabelValues lists a label's values among the series sel picks within
// [from, to].
func (db *DB) LabelValues(name string, from, to int64, sel Selector) ([]string, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	set := map[string]bool{}
	err := db.eachSeries(from, to, sel, func(ls Labels, _ string, _ func() ([]Point, error)) error {
		if v := ls.Get(name); v != "" {
			set[v] = true
		}
		return nil
	})
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out, err
}

// DayInfo is a stored day and its size on disk.
type DayInfo struct {
	Day   string `json:"day"`
	Bytes int64  `json:"bytes"`
}

// Days lists the stored days, oldest first.
func (db *DB) Days() []DayInfo {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var out []DayInfo
	for _, day := range db.days(0, farFuture) {
		dir := filepath.Join(db.root, day)
		out = append(out, DayInfo{Day: day, Bytes: daySize(dir)})
	}
	return out
}

// HeadSeries is how many series have samples today.
func (db *DB) HeadSeries() int {
	db.hmu.Lock()
	defer db.hmu.Unlock()
	return len(db.head.series)
}

// DeleteResult says what a deletion did.
type DeleteResult struct {
	Removed   []string `json:"removed"`   // whole days
	Rewritten []string `json:"rewritten"` // days that kept samples outside the range
	Freed     int64    `json:"freed"`     // bytes
}

// Delete removes the samples within [from, to] (milliseconds): days the
// range covers go whole, the days at its ends are rewritten.
func (db *DB) Delete(from, to int64) (DeleteResult, error) {
	var res DeleteResult
	if from > to {
		return res, errors.New("the range ends before it starts")
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	db.hmu.Lock()
	defer db.hmu.Unlock()
	before := db.bytes()
	headDay := db.head.day
	reopened := true
	// Whatever happens below, today must be writable again afterwards.
	defer func() {
		if !reopened {
			if h, err := openHead(db.root, headDay); err == nil {
				db.head = h
			}
		}
	}()
	for _, day := range db.days(from, to) {
		start, end := dayBounds(day)
		dir := filepath.Join(db.root, day)
		isHead := day == headDay
		var b *block
		if isHead {
			reopened = false
			if err := db.head.closeWriters(); err != nil {
				return res, err
			}
			db.head.block.close()
			b = db.head.block
		} else {
			db.cacheDrop(day)
		}
		if from <= start && to >= end {
			if err := os.RemoveAll(dir); err != nil {
				return res, err
			}
			res.Removed = append(res.Removed, day)
		} else {
			if b == nil {
				var err error
				if b, err = loadBlock(dir, day); err != nil {
					return res, err
				}
			}
			left, err := rewriteDay(dir, b, from, to)
			if err != nil {
				return res, err
			}
			if left {
				res.Rewritten = append(res.Rewritten, day)
			} else {
				res.Removed = append(res.Removed, day)
			}
		}
		if isHead {
			h, err := openHead(db.root, day)
			if err != nil {
				return res, err
			}
			db.head = h
			reopened = true
		}
	}
	res.Freed = before - db.bytes()
	return res, nil
}

func (db *DB) bytes() int64 {
	var n int64
	for _, day := range db.days(0, farFuture) {
		dir := filepath.Join(db.root, day)
		n += daySize(dir)
	}
	return n
}

// LabelNames lists the label names of the series sel picks within
// [from, to], the metric's name left out.
func (db *DB) LabelNames(from, to int64, sel Selector) ([]string, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	set := map[string]bool{}
	err := db.eachSeries(from, to, sel, func(ls Labels, _ string, _ func() ([]Point, error)) error {
		for _, l := range ls {
			if l.Name != MetricName {
				set[l.Name] = true
			}
		}
		return nil
	})
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, err
}

// SeriesLabels lists the series sel picks within [from, to], by labels.
func (db *DB) SeriesLabels(from, to int64, sel Selector) ([]Labels, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	seen := map[string]bool{}
	var out []Labels
	err := db.eachSeries(from, to, sel, func(ls Labels, _ string, _ func() ([]Point, error)) error {
		if k := ls.key(); !seen[k] {
			if len(out) >= MaxSeries {
				return ErrTooMuch
			}
			seen[k] = true
			out = append(out, ls)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, err
}
