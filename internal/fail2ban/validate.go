package fail2ban

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	jailName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	filterName = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9_.-]*)(\[[^\[\]]*\])?$`)
	service    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)
	portRange  = regexp.MustCompile(`^(\d+)(?:[:-](\d+))?$`)
	hostName   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)
	timeParts  = regexp.MustCompile(`(\d+)([wdhms]?)`)
)

// ValidJailName checks the name of a jail RuleLens may write the file of:
// a section of the configuration, and a part of the file's name.
func ValidJailName(name string) error {
	switch {
	case name == "":
		return errors.New("请填写规则名称")
	case len(name) > 64:
		return errors.New("规则名称最长 64 个字符")
	case !jailName.MatchString(name):
		return fmt.Errorf("规则名称 %q 只能包含字母、数字、“-”、“_”与“.”，且以字母或数字开头", name)
	case strings.EqualFold(name, "DEFAULT") || strings.EqualFold(name, "INCLUDES"):
		return fmt.Errorf("%s 是 fail2ban 保留的名称", name)
	}
	return nil
}

// ValidFilter checks a filter, as "sshd" or "sshd[mode=aggressive]", and
// returns its name.
func ValidFilter(s string) (string, error) {
	m := filterName.FindStringSubmatch(s)
	if m == nil || strings.ContainsAny(s, "%\n") {
		return "", fmt.Errorf("过滤器 %q 无效，应为 filter.d 中的文件名，如 sshd", s)
	}
	return m[1], nil
}

// ValidPort checks the ports of a jail, as its actions take them: ports,
// ranges and services, separated by commas, as "ssh,2222", "8000:8100".
func ValidPort(s string) error {
	if s == "" {
		return errors.New("请填写端口")
	}
	for _, p := range strings.Split(s, ",") {
		if service.MatchString(p) {
			continue
		}
		ok := false
		if m := portRange.FindStringSubmatch(p); m != nil {
			ok = true
			for _, n := range m[1:] {
				if v, err := strconv.Atoi(n); n != "" && (err != nil || v > 65535) {
					ok = false
				}
			}
		}
		if !ok {
			return fmt.Errorf("端口 %q 无效，应为端口号、端口范围（如 8000:8100）或服务名（如 ssh），多个用逗号分隔", p)
		}
	}
	return nil
}

// ValidAddress checks an address fail2ban may ignore: an IP, a network, or
// a host name.
func ValidAddress(s string) error {
	if net.ParseIP(s) != nil || hostName.MatchString(s) {
		return nil
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}
	return fmt.Errorf("%q 不是 IP、网段或主机名", s)
}

// ValidLogPath checks a log of a jail: an absolute path, which may hold
// the wildcards of glob.
func ValidLogPath(s string) error {
	if !strings.HasPrefix(s, "/") || strings.ContainsAny(s, "%\n\r'\"") {
		return fmt.Errorf("日志路径 %q 无效，应为绝对路径，如 /var/log/auth.log", s)
	}
	return nil
}

// ParseTime parses a time as fail2ban's configuration takes it: seconds,
// or numbers with units, "10m", "1h30m", "1w".
func ParseTime(s string) (time.Duration, error) {
	s = strings.ToLower(strings.Join(strings.Fields(s), ""))
	bad := fmt.Errorf("%q 不是有效的时长，可写秒数或带单位，如 600、10m、1h、1d、1w", s)
	if s == "" {
		return 0, bad
	}
	units := map[string]time.Duration{"": time.Second, "s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour, "w": 7 * 24 * time.Hour}
	var d time.Duration
	rest := s
	for rest != "" {
		m := timeParts.FindStringSubmatchIndex(rest)
		if m == nil || m[0] != 0 {
			return 0, bad
		}
		n, err := strconv.ParseInt(rest[m[2]:m[3]], 10, 64)
		if err != nil || n > 1<<40 {
			return 0, bad
		}
		d += time.Duration(n) * units[rest[m[4]:m[5]]]
		rest = rest[m[1]:]
	}
	return d, nil
}

// FormatTime writes a duration as ParseTime reads it, in whole units:
// "10m", "1h30m", "1w"; "-1" for ever.
func FormatTime(d time.Duration) string {
	if d < 0 {
		return "-1"
	}
	d = d.Round(time.Second)
	if d == 0 {
		return "0"
	}
	week := 7 * 24 * time.Hour
	if d%week == 0 {
		return strconv.FormatInt(int64(d/week), 10) + "w"
	}
	var b strings.Builder
	for _, u := range []struct {
		d    time.Duration
		name string
	}{{24 * time.Hour, "d"}, {time.Hour, "h"}, {time.Minute, "m"}, {time.Second, "s"}} {
		if n := d / u.d; n > 0 {
			b.WriteString(strconv.FormatInt(int64(n), 10) + u.name)
			d -= n * u.d
		}
	}
	return b.String()
}
