package gui

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/rulelens/rulelens/internal/fail2ban"
)

// units are the units durations are told in, the largest first.
var units = []struct {
	d    time.Duration
	name string
}{
	{7 * 24 * time.Hour, "周"},
	{24 * time.Hour, "天"},
	{time.Hour, "小时"},
	{time.Minute, "分钟"},
	{time.Second, "秒"},
}

// durationLabel tells a duration in its two largest units: "10 分钟",
// "1 天 12 小时", "1 周".
func durationLabel(d time.Duration) string {
	if d < 0 {
		return "永久"
	}
	if d < time.Second {
		return "0 秒"
	}
	var parts []string
	for i, u := range units {
		// Weeks only for whole weeks: 10 days is "10 天".
		if i == 0 && d%u.d != 0 {
			continue
		}
		if n := d / u.d; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, u.name))
			d -= n * u.d
		}
		if len(parts) == 2 || d == 0 {
			break
		}
		if len(parts) == 1 && i < len(units)-1 && d < units[i+1].d {
			// "1 天 0 小时 5 分钟" says no more than "1 天".
			break
		}
	}
	return strings.Join(parts, " ")
}

// triggerLabel says what bans a source: "3 次 / 10 分钟".
func triggerLabel(j fail2ban.Jail) string {
	return fmt.Sprintf("%d 次 / %s", j.MaxRetry, durationLabel(j.FindTime))
}

// banTimeLabel says how long a ban lasts: "1 小时", "永久", "10 分钟起递增".
func banTimeLabel(j fail2ban.Jail) string {
	l := durationLabel(j.BanTime)
	if j.BanIncrement && !j.Permanent() {
		l += " 起递增"
	}
	return l
}

// portsLabel says what the jail bans its sources from: "ssh,2222",
// "全部端口".
func portsLabel(j fail2ban.Jail) string {
	ports := j.Ports()
	if len(ports) == 0 {
		return "—"
	}
	labels := make([]string, len(ports))
	for i, p := range ports {
		labels[i] = p
		if p == "" {
			labels[i] = "全部端口"
		}
	}
	return strings.Join(labels, "；")
}

// sourceLabel says what the jail reads: its logs, or the systemd journal.
func sourceLabel(j fail2ban.Jail) string {
	switch {
	case len(j.LogPaths) > 0:
		return strings.Join(j.LogPaths, "\n")
	case len(j.JournalMatch) > 0:
		return "systemd 日志：" + strings.Join(j.JournalMatch, "\n")
	}
	return "—"
}

// remainingLabel says how long a ban has left.
func remainingLabel(b fail2ban.Ban, now time.Time) string {
	switch {
	case b.Permanent:
		return "永久"
	case b.End.IsZero():
		return "—"
	}
	d := b.End.Sub(now).Truncate(time.Second)
	if d <= 0 {
		return "即将解封"
	}
	if d > time.Minute {
		d = d.Truncate(time.Minute)
	}
	return durationLabel(d)
}

// timeLabel tells a time, its day only when it is not today's.
func timeLabel(t, now time.Time) string {
	switch {
	case t.IsZero():
		return "—"
	case t.Year() == now.Year() && t.YearDay() == now.YearDay():
		return t.Format("15:04:05")
	case t.Year() == now.Year():
		return t.Format("01-02 15:04")
	}
	return t.Format("2006-01-02 15:04")
}

// ago says how long ago t was.
func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case t.IsZero():
		return ""
	case d < 10*time.Second:
		return "刚刚"
	case d < time.Minute:
		return fmt.Sprintf("%d 秒前", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d 小时前", int(d.Hours()))
	}
	return t.Format("2006-01-02 15:04")
}

// banRow is a ban of a jail, as the bans' table lists it.
type banRow struct {
	fail2ban.Ban
	Jail string
}

func (r banRow) Key() string { return r.Jail + " " + r.IP }

// banRows lists the bans of every jail matching query, sorted as the table
// says.
func banRows(s *fail2ban.Status, query string, sort ui.SortOrder, now time.Time) []banRow {
	q := strings.ToLower(strings.TrimSpace(query))
	var out []banRow
	for _, j := range s.Jails {
		for _, b := range j.Bans {
			if q != "" && !strings.Contains(strings.ToLower(b.IP+" "+j.Name), q) {
				continue
			}
			out = append(out, banRow{Ban: b, Jail: j.Name})
		}
	}
	// Bans for ever last longest.
	left := func(r banRow) time.Duration {
		if r.Permanent {
			return 1<<63 - 1
		}
		return r.End.Sub(now)
	}
	cmp := func(x, y banRow) int {
		switch sort.Column {
		case "规则":
			return strings.Compare(x.Jail, y.Jail)
		case "封禁时间":
			return x.Start.Compare(y.Start)
		case "剩余":
			return compare(left(x), left(y))
		}
		return compareIPs(x.IP, y.IP)
	}
	slices.SortStableFunc(out, cmp)
	if sort.Descending {
		slices.Reverse(out)
	}
	return out
}

// jailRows returns the jails sorted as the table says.
func jailRows(s *fail2ban.Status, sort ui.SortOrder) []fail2ban.Jail {
	out := slices.Clone(s.Jails)
	if sort.Column == "" {
		return out
	}
	slices.SortStableFunc(out, func(x, y fail2ban.Jail) int {
		switch sort.Column {
		case "当前封禁":
			return compare(x.CurrentlyBanned, y.CurrentlyBanned)
		case "累计封禁":
			return compare(x.TotalBanned, y.TotalBanned)
		case "封禁时长":
			return compare(x.BanTime, y.BanTime)
		}
		return strings.Compare(x.Name, y.Name)
	})
	if sort.Descending {
		slices.Reverse(out)
	}
	return out
}

func compare[T int | time.Duration](a, b T) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// compareIPs orders addresses as numbers where they are, IPv4 first.
func compareIPs(a, b string) int {
	pa, pb := ipKey(a), ipKey(b)
	if c := strings.Compare(pa, pb); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

// ipKey pads the numbers of an IPv4 address, so that they sort as text.
func ipKey(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "~" + ip
	}
	for i, p := range parts {
		if len(p) < 3 {
			parts[i] = strings.Repeat("0", 3-len(p)) + p
		}
	}
	return strings.Join(parts, ".")
}
