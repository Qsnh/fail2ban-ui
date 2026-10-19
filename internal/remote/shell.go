package remote

import "strings"

// Quote quotes s for a POSIX shell, so that it reaches the command as one
// argument whatever it holds.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:,=@%+", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Join quotes each argument and joins them into a command line.
func Join(args ...string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = Quote(a)
	}
	return strings.Join(q, " ")
}

// SplitSections splits output into the sections after "@@name" lines, by
// name.
func SplitSections(out string) map[string]string {
	sections := map[string]string{}
	var name string
	var b strings.Builder
	flush := func() {
		if name != "" {
			sections[name] = b.String()
		}
		b.Reset()
	}
	for line := range strings.Lines(out) {
		if rest, ok := strings.CutPrefix(line, "@@"); ok && !strings.ContainsAny(strings.TrimSpace(rest), " \t") {
			flush()
			name = strings.TrimSpace(rest)
			continue
		}
		b.WriteString(line)
	}
	flush()
	return sections
}
