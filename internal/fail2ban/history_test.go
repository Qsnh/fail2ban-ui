package fail2ban

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

// historyRead is when the history fixture was read: 2026-10-19 05:21:52
// on the server, which runs 8 hours behind this computer's clock.
var historyRead = time.Date(2026, 10, 19, 13, 21, 52, 0, time.Local)

// serverTime tells a time of the history fixture's server by this
// computer's clock.
func serverTime(t *testing.T, s string) time.Time {
	t.Helper()
	at, err := time.Parse(time.DateTime, s)
	if err != nil {
		t.Fatal(err)
	}
	server, _ := time.Parse(time.DateTime, "2026-10-19 05:21:52")
	return historyRead.Add(at.Sub(server))
}

func pastBan(t *testing.T, bans []PastBan, jail, ip string, start string) PastBan {
	t.Helper()
	for _, b := range bans {
		if b.Jail == jail && b.IP == ip && (start == "" && b.Start.IsZero() || start != "" && b.Start.Equal(serverTime(t, start))) {
			return b
		}
	}
	t.Fatalf("no ban of %s by %s at %q among %+v", ip, jail, start, bans)
	return PastBan{}
}

// The fixture is what the script printed on Ubuntu 24.04 (fail2ban
// 1.0.2), with two older logs logrotate would have made, one compressed,
// and fail2ban restarted while it banned 203.0.113.77.
func TestParseHistoryLog(t *testing.T) {
	h := parseHistory(fixture(t, "history-1.0.2.txt"), historyRead)
	if h.Problem != "" || h.Source != SourceFile || h.Target != "/var/log/fail2ban.log" || h.PurgeAge != 24*time.Hour {
		t.Fatalf("history %+v", h)
	}
	if !slices.Equal(h.Files, []string{"/var/log/fail2ban.log.2.gz", "/var/log/fail2ban.log.1", "/var/log/fail2ban.log"}) {
		t.Errorf("files %q", h.Files)
	}
	if h.Count != 25 || h.Truncated || !h.Since.Equal(serverTime(t, "2026-10-05 10:00:00")) || len(h.Bans) != 12 {
		t.Errorf("count %d, truncated %v, since %v, %d bans", h.Count, h.Truncated, h.Since, len(h.Bans))
	}
	b := pastBan(t, h.Bans, "sshd", "198.51.100.1", "2026-10-05 10:00:00")
	if b.Active || !b.End.Equal(serverTime(t, "2026-10-05 11:00:00")) {
		t.Errorf("lifted ban %+v", b)
	}
	// Banned in a log, lifted in the next.
	b = pastBan(t, h.Bans, "sshd", "198.51.100.2", "2026-10-05 12:00:00")
	if b.Active || !b.End.Equal(serverTime(t, "2026-10-12 08:00:00")) {
		t.Errorf("ban across logs %+v", b)
	}
	if b := pastBan(t, h.Bans, "recidive", "198.51.100.1", "2026-10-12 09:00:00"); !b.Active || !b.End.IsZero() {
		t.Errorf("ban not lifted %+v", b)
	}
	// fail2ban stopping lifted the ban, and starting restored it: one ban.
	b = pastBan(t, h.Bans, "sshd", "203.0.113.77", "2026-10-19 05:20:20")
	if b.Active || b.Restored || !b.End.Equal(serverTime(t, "2026-10-19 05:21:45")) {
		t.Errorf("ban restored %+v", b)
	}
	n := 0
	for _, b := range h.Bans {
		if b.IP == "203.0.113.51" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("203.0.113.51 banned %d times", n)
	}
}

func TestPastBans(t *testing.T) {
	at := func(m int) time.Time { return time.Date(2026, 10, 19, 10, m, 0, 0, time.Local) }
	bans := pastBans([]event{
		{at(1), "sshd", "192.0.2.1", "Unban"},       // banned before the log
		{at(2), "sshd", "192.0.2.2", "Restore Ban"}, // so, and restored
		{at(3), "sshd", "192.0.2.3", "Ban"},
		{at(5), "sshd", "192.0.2.3", "Ban"},         // lifted unsaid
		{at(6), "sshd", "192.0.2.3", "Restore Ban"}, // fail2ban died
		{at(4), "web", "192.0.2.3", "Ban"},          // out of order
		{at(7), "web", "192.0.2.3", "Unban"},
	})
	want := []PastBan{
		{IP: "192.0.2.1", Jail: "sshd", End: at(1)},
		{IP: "192.0.2.2", Jail: "sshd", Restored: true, Active: true},
		{IP: "192.0.2.3", Jail: "sshd", Start: at(3)},
		{IP: "192.0.2.3", Jail: "web", Start: at(4), End: at(7)},
		{IP: "192.0.2.3", Jail: "sshd", Start: at(5), Active: true},
	}
	if !slices.Equal(bans, want) {
		t.Errorf("got  %+v\nwant %+v", bans, want)
	}
}

func TestMerged(t *testing.T) {
	at := func(m int) time.Time { return time.Date(2026, 10, 19, 10, m, 0, 0, time.Local) }
	h := &History{Source: SourceDB, Bans: []PastBan{
		{IP: "192.0.2.1", Jail: "sshd", Start: at(1), End: at(2)},
		{IP: "192.0.2.2", Jail: "sshd", Start: at(2), End: at(50), Active: true}, // lifted since
		{IP: "192.0.2.3", Jail: "sshd", Start: at(3), End: at(53), Active: true}, // a later ban took over
		{IP: "192.0.2.3", Jail: "sshd", Start: at(4), Active: true},
		{IP: "192.0.2.4", Jail: "sshd", Restored: true, Active: true},
	}}
	s := &Status{Jails: []Jail{{Name: "sshd", Bans: []Ban{
		{IP: "192.0.2.3", Start: at(4), End: at(64)},
		{IP: "192.0.2.4", Start: at(0), Permanent: true},
		{IP: "192.0.2.5", Start: at(5), End: at(65)}, // banned since the history was read
	}}}}
	got := h.Merged(s)
	want := []PastBan{
		{IP: "192.0.2.1", Jail: "sshd", Start: at(1), End: at(2)},
		{IP: "192.0.2.2", Jail: "sshd", Start: at(2)},
		{IP: "192.0.2.3", Jail: "sshd", Start: at(3)},
		{IP: "192.0.2.3", Jail: "sshd", Start: at(4), End: at(64), Active: true},
		{IP: "192.0.2.4", Jail: "sshd", Start: at(0), Restored: true, Active: true, Permanent: true},
		{IP: "192.0.2.5", Jail: "sshd", Start: at(5), End: at(65), Active: true},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	if h.Bans[1].End != at(50) || !h.Bans[1].Active {
		t.Errorf("the history changed: %+v", h.Bans[1])
	}
	if got := h.Merged(nil); got[3].Active || got[4].Active {
		t.Errorf("merged with nothing banned: %+v", got)
	}
}

func TestParseHistoryDB(t *testing.T) {
	out := "@@json\n" + `{"now": "2026-10-19 02:00:00", "target": "SYSLOG", "purgeage": 86400, "source": "db", "db": "/var/lib/fail2ban/fail2ban.sqlite3",` +
		` "bans": [["2026-10-19 01:40:00", "sshd", "192.0.2.1", 600], ["2026-10-19 01:30:00", "recidive", "192.0.2.2", -1], ["2026-10-19 01:50:00", "sshd", "192.0.2.3", 3600], ["2026-10-19 01:55:00", "old", "192.0.2.4", null]],` +
		` "count": 5, "events": [], "problems": ["journalctl: [Errno 2] No such file or directory: 'journalctl'"]}` + "\n"
	now := time.Date(2026, 10, 19, 10, 0, 0, 0, time.Local)
	at := func(m int) time.Time { return time.Date(2026, 10, 19, 9, m, 0, 0, time.Local) }
	h := parseHistory(out, now)
	if h.Source != SourceDB || h.DB != "/var/lib/fail2ban/fail2ban.sqlite3" || h.Target != "SYSLOG" || h.Count != 5 || !h.Truncated || len(h.Problems) != 1 {
		t.Fatalf("history %+v", h)
	}
	want := []PastBan{
		{IP: "192.0.2.2", Jail: "recidive", Start: at(30), Active: true, Permanent: true},
		{IP: "192.0.2.1", Jail: "sshd", Start: at(40), End: at(50)},
		{IP: "192.0.2.3", Jail: "sshd", Start: at(50), End: at(50).Add(time.Hour), Active: true},
		{IP: "192.0.2.4", Jail: "old", Start: at(55), Active: true},
	}
	if !slices.Equal(h.Bans, want) || !h.Since.Equal(at(30)) {
		t.Errorf("got  %+v\nwant %+v", h.Bans, want)
	}
}

func TestParseHistoryProblems(t *testing.T) {
	if h := parseHistory("@@missing\n", read); !strings.Contains(h.Problem, "未安装") {
		t.Errorf("missing: %+v", h)
	}
	if h := parseHistory("@@json\nsh: 1: python3: not found\n", read); !strings.Contains(h.Problem, "python3: not found") {
		t.Errorf("no python: %+v", h)
	}
	if h := parseHistory("@@json\n"+`{"error": "import fail2ban: No module named fail2ban"}`+"\n", read); !strings.Contains(h.Problem, "No module") {
		t.Errorf("no module: %+v", h)
	}
	h := parseHistory("@@json\n"+`{"now": "2026-10-19 02:00:00", "target": "SYSLOG", "events": [], "count": 0, "problems": ["journalctl: not found"]}`+"\n", read)
	if h.Source != "" || !strings.Contains(h.Problem, "SYSLOG") || !strings.Contains(h.Problem, "journalctl: not found") {
		t.Errorf("no source: %+v", h)
	}
	// A journal without bans.
	h = parseHistory("@@json\n"+`{"now": "2026-10-19 02:00:00", "target": "SYSTEMD-JOURNAL", "source": "journal", "events": [], "count": 0}`+"\n", read)
	if h.Source != SourceJournal || h.Problem != "" || len(h.Bans) != 0 || !h.Since.IsZero() {
		t.Errorf("empty journal: %+v", h)
	}
}

func TestReadHistoryRunsAsRoot(t *testing.T) {
	x := &fakeExec{}
	h, err := ReadHistory(context.Background(), x, read)
	if err != nil || h.Problem == "" {
		t.Fatalf("%+v, %v", h, err)
	}
	if len(x.cmds) != 1 || !strings.HasPrefix(x.cmds[0], "sudo export LC_ALL=C") || !strings.Contains(x.cmds[0], "logtarget") ||
		!strings.Contains(x.cmds[0], "LIMIT = 40000") {
		t.Errorf("commands %q", x.cmds)
	}
}
