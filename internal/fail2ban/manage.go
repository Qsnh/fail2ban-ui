package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/rulelens/rulelens/internal/remote"
)

// Change is a change of a jail's configuration: RuleLens's file of the
// jail written anew, or removed when Override is nil.
type Change struct {
	Jail     string
	Override *Override
}

// The exits of the change's script, by the step failing.
const (
	exitWrite  = 2
	exitTest   = 3
	exitReload = 4
)

// ChangeCommand is the command making a change: it writes the file, has
// fail2ban-client check the configuration, then reloads fail2ban, which
// starts the jails enabled and stops those disabled, keeping the bans of
// the others. A step failing puts the file back as it was, so that a
// configuration fail2ban would not start with never stays.
func ChangeCommand(ch Change) (string, error) {
	if err := ValidJailName(ch.Jail); err != nil {
		return "", err
	}
	write := `rm -f "$f"`
	if o := ch.Override; o != nil {
		if o.Jail != ch.Jail {
			return "", fmt.Errorf("文件属于规则 %s，而不是 %s", o.Jail, ch.Jail)
		}
		write = "mkdir -p " + JailDir + " && printf '%s' " + remote.Quote(o.Render()) + ` >"$f.new" && chmod 644 "$f.new" && mv -f "$f.new" "$f"`
	}
	return `f=` + remote.Quote(OverridePath(ch.Jail)) + `
b=$(mktemp) || exit 2
had=0
if [ -f "$f" ]; then cp -p "$f" "$b" || exit 2; had=1; fi
undo() { if [ $had = 1 ]; then cp -p "$b" "$f"; else rm -f "$f"; fi; rm -f "$b" "$f.new"; }
` + write + ` || { undo; exit 2; }
if ! out=$(fail2ban-client -t 2>&1); then undo; printf '%s\n' "$out" >&2; exit 3; fi
if ! out=$(fail2ban-client reload 2>&1); then undo; fail2ban-client reload >/dev/null 2>&1; printf '%s\n' "$out" >&2; exit 4; fi
rm -f "$b"`, nil
}

// ChangeError is a change fail2ban did not take, undone.
type ChangeError struct {
	// Checking reports whether the configuration failed its check,
	// rather than fail2ban reloading it.
	Checking bool
	// Output is what fail2ban-client said of it.
	Output string
}

func (e *ChangeError) Error() string {
	if e.Checking {
		return "配置校验未通过，已还原，服务器未改动：" + e.Output
	}
	return "fail2ban 重新加载失败，已还原配置：" + e.Output
}

// Apply makes a change, as root.
func Apply(ctx context.Context, x remote.Executor, ch Change) error {
	cmd, err := ChangeCommand(ch)
	if err != nil {
		return err
	}
	_, err = remote.Check(ctx, x, true, remote.Prelude+cmd)
	var ce *remote.CommandError
	if errors.As(err, &ce) {
		switch ce.ExitCode {
		case exitTest, exitReload:
			return &ChangeError{Checking: ce.ExitCode == exitTest, Output: explain(ce.Output)}
		case exitWrite:
			return fmt.Errorf("写入 %s 失败：%s", OverridePath(ch.Jail), strings.TrimSpace(ce.Output))
		}
	}
	return err
}

// logPrefix is what fail2ban-client puts before its messages: "2026-10-19
// 02:48:59,040 fail2ban [1223]: ERROR ".
var logPrefix = regexp.MustCompile(`^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+ \S+\s+\[\d+\]:\s+(\w+)\s+`)

// hints explain the errors of fail2ban-client met most.
var hints = []struct {
	re   *regexp.Regexp
	hint string
}{
	{regexp.MustCompile(`Have not found any log file for (\S+) jail`), "找不到规则 $1 的日志文件，请检查日志路径，或改用 systemd 日志"},
	{regexp.MustCompile(`Unable to read the filter '([^']*)'`), "服务器上没有过滤器 $1（/etc/fail2ban/filter.d/$1.conf）"},
	{regexp.MustCompile(`Unable to read action '([^']*)'`), "服务器上没有封禁动作 $1（/etc/fail2ban/action.d/$1.conf）"},
}

// explain keeps the errors of what fail2ban-client printed, without its
// warnings, and tells what they mean.
func explain(out string) string {
	var lines []string
	for line := range strings.Lines(out) {
		line = strings.TrimSpace(line)
		if m := logPrefix.FindStringSubmatch(line); m != nil {
			if m[1] != "ERROR" && m[1] != "CRITICAL" {
				continue
			}
			line = line[len(m[0]):]
		}
		if line == "" || strings.Contains(line, "test configuration failed") || slices.Contains(lines, line) {
			continue
		}
		for _, h := range hints {
			if m := h.re.FindStringSubmatchIndex(line); m != nil {
				line = string(h.re.ExpandString(nil, h.hint, line, m)) + "（" + line + "）"
				break
			}
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return firstLines(out, 6)
	}
	return firstLines(strings.Join(lines, "\n"), 6)
}
