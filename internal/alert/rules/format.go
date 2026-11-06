package rules

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

// FormatValue renders v according to unit, for human-readable summaries.
func FormatValue(u Unit, v float64) string {
	switch u {
	case UnitRatio:
		return fmt.Sprintf("%.1f%%", v*100)
	case UnitBytes:
		return FormatBytes(v)
	case UnitSeconds:
		return formatSeconds(v)
	case UnitFlag:
		if v >= 1 {
			return "up"
		}
		return "down"
	default:
		if v == math.Trunc(v) && math.Abs(v) < 1e15 {
			return fmt.Sprintf("%.0f", v)
		}
		return fmt.Sprintf("%.2f", v)
	}
}

// FormatBytes renders a byte count with binary units.
func FormatBytes(b float64) string {
	neg := b < 0
	b = math.Abs(b)
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	s := fmt.Sprintf("%.1f %s", b, units[i])
	if i == 0 {
		s = fmt.Sprintf("%.0f %s", b, units[i])
	}
	if neg {
		s = "-" + s
	}
	return s
}

func formatSeconds(v float64) string {
	if v < 1 {
		return fmt.Sprintf("%.0f ms", v*1000)
	}
	d := time.Duration(v * float64(time.Second)).Round(time.Second)
	return d.String()
}

func summarize(r Rule, ev model.Event, note string) string {
	var b strings.Builder
	switch ev.State {
	case model.StateResolved:
		b.WriteString("RESOLVED: ")
	case model.StateReminder:
		b.WriteString("STILL ACTIVE: ")
	}
	b.WriteString(r.Description)
	b.WriteString(" on ")
	b.WriteString(ev.Target)
	if len(ev.Labels) > 0 {
		keys := make([]string, 0, len(ev.Labels))
		for k := range ev.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString(" [")
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(k + "=" + ev.Labels[k])
		}
		b.WriteString("]")
	}
	b.WriteString(": ")
	b.WriteString(FormatValue(r.Unit, ev.Value))
	if ev.State != model.StateResolved && r.Unit != UnitFlag {
		op := ">"
		if r.Op == Below {
			op = "<"
		}
		fmt.Fprintf(&b, " (%s %s)", op, FormatValue(r.Unit, ev.Threshold))
	}
	if note != "" {
		b.WriteString(" — " + note)
	}
	return b.String()
}
