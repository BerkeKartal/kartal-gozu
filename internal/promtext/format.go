package promtext

import (
	"io"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// Format writes families in the text format, without help texts: what
// Parse read can travel on compactly and be parsed again on the other side.
func Format(w io.Writer, fams []protocol.MetricFamily) error {
	var b strings.Builder
	for _, f := range fams {
		if f.Type != "" {
			b.WriteString("# TYPE ")
			b.WriteString(f.Name)
			b.WriteByte(' ')
			b.WriteString(f.Type)
			b.WriteByte('\n')
		}
		for _, s := range f.Samples {
			b.WriteString(s.Name)
			if len(s.Labels) > 0 {
				names := make([]string, 0, len(s.Labels))
				for k := range s.Labels {
					names = append(names, k)
				}
				sort.Strings(names)
				b.WriteByte('{')
				for i, k := range names {
					if i > 0 {
						b.WriteByte(',')
					}
					b.WriteString(k)
					b.WriteString(`="`)
					b.WriteString(escape(s.Labels[k]))
					b.WriteByte('"')
				}
				b.WriteByte('}')
			}
			b.WriteByte(' ')
			b.WriteString(value(float64(s.Value)))
			b.WriteByte('\n')
		}
		if b.Len() > 64<<10 {
			if _, err := io.WriteString(w, b.String()); err != nil {
				return err
			}
			b.Reset()
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func escape(s string) string { return labelEscaper.Replace(s) }

func value(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}
