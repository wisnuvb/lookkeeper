package prom

import (
	"bytes"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ContentType is the media type of the text exposition format, version 0.0.4.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Exported names that sample metric names must not collide with.
const (
	namePrefix        = "lockkeeper_"
	nameAlertActive   = "lockkeeper_alert_active"
	nameLastSuccess   = "lockkeeper_collection_last_success_timestamp_seconds"
	labelTarget       = "target"
	labelRule         = "rule"
	labelSeverity     = "severity"
	reservedLabelPref = "exported_"
)

// MetricName maps a Lockkeeper metric id such as "pg.connections.used_ratio" to
// its exposition name "lockkeeper_pg_connections_used_ratio": every character
// outside [a-zA-Z0-9_] becomes an underscore (colons are reserved for recording
// rules).
func MetricName(metric string) string {
	var b strings.Builder
	b.WriteString(namePrefix)
	for _, r := range metric {
		if isNameChar(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func isNameChar(r rune) bool {
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// labelName makes a valid label name from a collector label key: invalid
// characters become underscores, a leading digit gets a leading underscore, and
// the "__" prefix Prometheus reserves for itself is collapsed.
func labelName(k string) string {
	var b strings.Builder
	for _, r := range k {
		if isNameChar(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	s := b.String()
	for strings.HasPrefix(s, "__") {
		s = s[1:]
	}
	if s == "" {
		return "_"
	}
	if s[0] >= '0' && s[0] <= '9' {
		s = "_" + s
	}
	return s
}

type label struct{ name, value string }

// buildLabels turns a label map into sorted exposition labels. Keys that collide
// with a reserved label (target, and for alerts rule and severity) are renamed
// with an "exported_" prefix, as Prometheus does; if two keys still end up with
// the same name the one that sorts first wins, so the output stays deterministic.
func buildLabels(in map[string]string, reserved map[string]string) []label {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	used := map[string]bool{}
	out := make([]label, 0, len(in)+len(reserved))
	for k, v := range reserved {
		out = append(out, label{k, v})
		used[k] = true
	}
	for _, k := range keys {
		n := labelName(k)
		if used[n] {
			n = reservedLabelPref + n
		}
		if used[n] {
			continue
		}
		used[n] = true
		out = append(out, label{n, in[k]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// escapeLabelValue escapes backslash, double quote and line feed, and replaces
// invalid UTF-8 (the format requires valid UTF-8).
func escapeLabelValue(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// escapeHelp escapes backslash and line feed in HELP text.
func escapeHelp(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func unixSeconds(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

// family collects the lines of one metric name.
type family struct {
	name  string
	help  string
	lines map[string]float64 // rendered label set -> value
}

func (f *family) add(labels []label, v float64) {
	var b strings.Builder
	b.WriteByte('{')
	for i, l := range labels {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(l.name)
		b.WriteString(`="`)
		b.WriteString(escapeLabelValue(l.value))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	key := b.String()
	if _, dup := f.lines[key]; !dup { // first one wins; callers add in a fixed order
		f.lines[key] = v
	}
}

// Render returns the current state in the text exposition format. The order is
// deterministic: families by name, series by their rendered label set. Every
// family is a gauge.
func (r *Registry) Render() []byte {
	var buf bytes.Buffer
	_ = r.WriteText(&buf)
	return buf.Bytes()
}

// WriteText writes the current state in the text exposition format.
func (r *Registry) WriteText(w io.Writer) error {
	fams := r.collect()
	names := make([]string, 0, len(fams))
	for n := range fams {
		names = append(names, n)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	for _, n := range names {
		f := fams[n]
		buf.WriteString("# HELP " + f.name + " " + escapeHelp(f.help) + "\n")
		buf.WriteString("# TYPE " + f.name + " gauge\n")
		keys := make([]string, 0, len(f.lines))
		for k := range f.lines {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			buf.WriteString(f.name + k + " " + formatValue(f.lines[k]) + "\n")
		}
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// collect snapshots the registry into families.
func (r *Registry) collect() map[string]*family {
	fams := map[string]*family{}
	get := func(name, help string) *family {
		f := fams[name]
		if f == nil {
			f = &family{name: name, help: help, lines: map[string]float64{}}
			fams[name] = f
		}
		return f
	}
	if r == nil {
		return fams
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	targets := make([]string, 0, len(r.targets))
	for t := range r.targets {
		targets = append(targets, t)
	}
	sort.Strings(targets)

	for _, target := range targets {
		td := r.targets[target]
		// Fixed processing order (metric id, then series key) makes the winner of a
		// name collision deterministic.
		keys := make([]string, 0, len(td.series))
		for k := range td.series {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := td.series[k]
			name := MetricName(s.Metric)
			if name == nameAlertActive || name == nameLastSuccess {
				continue // would shadow Lockkeeper's own series
			}
			f := get(name, `Latest value of the Lockkeeper metric "`+s.Metric+`".`)
			f.add(buildLabels(s.Labels, map[string]string{labelTarget: target}), s.Value)
		}
		if !td.lastSuccess.IsZero() {
			f := get(nameLastSuccess, "Unix time of the last collection that completed without error, per target.")
			f.add([]label{{labelTarget, target}}, unixSeconds(td.lastSuccess))
		}
	}

	for _, e := range r.alerts {
		f := get(nameAlertActive, "1 for each alert that is currently firing.")
		f.add(buildLabels(e.Labels, map[string]string{
			labelTarget: e.Target, labelRule: e.Rule, labelSeverity: string(e.Severity),
		}), 1)
	}
	return fams
}
