package gui

import (
	"slices"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/rulelens/rulelens/internal/fail2ban"
)

// historyF2B is a fake server whose log has banned 198.51.100.9 three
// times, by two jails, and 203.0.113.5, banned still; recidive bans
// 192.0.2.77, banned before the log.
func historyF2B() *fakeF2B {
	f := newFakeF2B(sshdJail("203.0.113.5"), recidiveJail("192.0.2.77"))
	f.events = [][]string{
		{"2026-10-18 01:00:00", "sshd", "Ban", "198.51.100.9"},
		{"2026-10-18 02:00:00", "sshd", "Unban", "198.51.100.9"},
		{"2026-10-19 00:30:00", "sshd", "Ban", "198.51.100.9"},
		{"2026-10-19 01:00:00", "recidive", "Ban", "198.51.100.9"},
		{"2026-10-19 01:30:00", "sshd", "Unban", "198.51.100.9"},
		{"2026-10-19 01:50:00", "sshd", "Ban", "203.0.113.5"},
	}
	return f
}

func TestHistoryByAddress(t *testing.T) {
	f := historyF2B()
	a, tt, _ := connected(t, f)
	click(t, tt, "封禁历史")
	tt.Frame()
	if f.historyReads != 1 {
		t.Fatalf("history read %d times", f.historyReads)
	}
	expect(t, tt, "按 IP", "按次", "共 3 个 IP，封禁 5 次",
		"记录来自 fail2ban 日志 /var/log/fail2ban.log 及 1 个轮转的旧日志，最早一条记录于 2026-10-18 09:00。双击 IP 查看它的每次封禁。",
		"198.51.100.9", "3", "recidive, sshd", "10-18 09:00", "09:00:00", "已解封",
		"203.0.113.5", "192.0.2.77", "封禁中")
	sv := a.views["s1"]
	m := sv.historyRows(sv.f2b)
	var ips []string
	for _, r := range m.addresses {
		ips = append(ips, r.IP)
	}
	// The address banned last first.
	if !slices.Equal(ips, []string{"192.0.2.77", "203.0.113.5", "198.51.100.9"}) {
		t.Errorf("addresses %q", ips)
	}
	r := m.addresses[2]
	if r.Bans != 3 || r.Active || !slices.Equal(r.Jails, []string{"recidive", "sshd"}) ||
		!r.First.Equal(time.Date(2026, 10, 18, 9, 0, 0, 0, time.Local)) || !r.Last.Equal(time.Date(2026, 10, 19, 9, 0, 0, 0, time.Local)) {
		t.Errorf("198.51.100.9 %+v", r)
	}

	// A double click, or Enter, on an address lists its bans.
	click(t, tt, "198.51.100.9")
	tt.Key(0, ui.KeyEnter)
	tt.Frame()
	if sv.histMode != historyByBan || sv.histFilter != "198.51.100.9" {
		t.Fatalf("mode %d, filter %q", sv.histMode, sv.histFilter)
	}
	expect(t, tt, "匹配 1 个 IP，封禁 3 次", "10-18 10:00", "1 小时", "08:30:00", "09:30:00")
	if tt.HasText("203.0.113.5") {
		t.Error("the filter shows other addresses")
	}
}

func TestHistoryByBan(t *testing.T) {
	f := historyF2B()
	a, tt, _ := connected(t, f)
	click(t, tt, "封禁历史")
	click(t, tt, "按次")
	tt.Frame()
	expect(t, tt, "共 3 个 IP，封禁 5 次", "封禁记录",
		// 203.0.113.5 is banned for an hour since 09:50, 192.0.2.77 for ever.
		"预计 10:50:00", "不解封", "永久",
		// recidive's ban of 198.51.100.9 the log left on was lifted since.
		"—")
	sv := a.views["s1"]
	m := sv.historyRows(sv.f2b)
	want := []struct {
		ip, jail string
		active   bool
	}{{"192.0.2.77", "recidive", true}, {"203.0.113.5", "sshd", true}, {"198.51.100.9", "recidive", false}, {"198.51.100.9", "sshd", false}, {"198.51.100.9", "sshd", false}}
	if len(m.bans) != len(want) || len(m.keys) != len(want) {
		t.Fatalf("bans %+v", m.bans)
	}
	for i, w := range want {
		if b := m.bans[i]; b.IP != w.ip || b.Jail != w.jail || b.Active != w.active {
			t.Errorf("ban %d %+v, want %+v", i, b, w)
		}
	}
	if b := m.bans[2]; !b.End.IsZero() || b.Permanent {
		t.Errorf("ban lifted unsaid %+v", b)
	}

	typeInto(t, tt, "筛选历史", "recidive")
	tt.Frame()
	expect(t, tt, "匹配 2 个 IP，封禁 2 次")
	typeInto(t, tt, "筛选历史", "x")
	tt.Frame()
	expect(t, tt, "没有匹配的记录")
}

func TestHistorySort(t *testing.T) {
	at := func(h int) time.Time { return time.Date(2026, 10, 19, h, 0, 0, 0, time.Local) }
	bans := []fail2ban.PastBan{
		{IP: "192.0.2.10", Jail: "sshd", Start: at(1), End: at(3)},
		{IP: "192.0.2.9", Jail: "recidive", Start: at(2), Active: true, Permanent: true},
		{IP: "192.0.2.10", Jail: "sshd", End: at(0)},
		{IP: "192.0.2.11", Jail: "sshd", Start: at(4), End: at(5), Active: true},
	}
	ips := func(bans []fail2ban.PastBan) []string {
		var out []string
		for _, b := range bans {
			out = append(out, b.IP)
		}
		return out
	}
	for _, c := range []struct {
		sort ui.SortOrder
		want []string
	}{
		{ui.SortOrder{}, []string{"192.0.2.11", "192.0.2.9", "192.0.2.10", "192.0.2.10"}},
		{ui.SortOrder{Column: "IP"}, []string{"192.0.2.9", "192.0.2.10", "192.0.2.10", "192.0.2.11"}},
		{ui.SortOrder{Column: "时长", Descending: true}, []string{"192.0.2.9", "192.0.2.10", "192.0.2.11", "192.0.2.10"}},
		{ui.SortOrder{Column: "解封时间"}, []string{"192.0.2.10", "192.0.2.10", "192.0.2.11", "192.0.2.9"}},
		{ui.SortOrder{Column: "状态", Descending: true}, []string{"192.0.2.11", "192.0.2.9", "192.0.2.10", "192.0.2.10"}},
	} {
		if got := ips(sortPastBans(slices.Clone(bans), c.sort)); !slices.Equal(got, c.want) {
			t.Errorf("by %+v: %q, want %q", c.sort, got, c.want)
		}
	}
	rows := byAddress(bans, ui.SortOrder{Column: "封禁次数", Descending: true})
	if rows[0].IP != "192.0.2.10" || rows[0].Bans != 2 || !rows[0].First.Equal(at(1)) || !rows[0].Last.Equal(at(1)) || rows[0].Active {
		t.Errorf("by count %+v", rows)
	}
	if rows := byAddress(bans, ui.SortOrder{Column: "首次封禁"}); rows[0].IP != "192.0.2.10" || rows[1].IP != "192.0.2.9" || rows[2].IP != "192.0.2.11" {
		t.Errorf("by first %+v", rows)
	}
}

// Refreshing reads the history again while the page shows it, and so do
// automatic refreshes, quietly; showing the tab again reads it again.
func TestHistoryRefresh(t *testing.T) {
	f := historyF2B()
	a, tt, clock, _ := clockApp(t, f)
	click(t, tt, "封禁历史")
	tt.Frame()
	reads := f.reads
	if f.historyReads != 1 {
		t.Fatalf("history read %d times", f.historyReads)
	}
	f.events = append(f.events, []string{"2026-10-19 01:55:00", "sshd", "Unban", "203.0.113.5"})
	f.jails[0].bans = nil
	tt.Key(ui.Cmd, ui.KeyR)
	tt.Frame()
	// fail2ban is read with the history.
	if f.historyReads != 2 || f.reads != reads+1 {
		t.Fatalf("history read %d times, fail2ban %d", f.historyReads, f.reads-reads)
	}
	expect(t, tt, "共 3 个 IP，封禁 5 次")
	if sv := a.views["s1"]; sv.historyRows(sv.f2b).addresses[1].Active {
		t.Error("203.0.113.5 banned still")
	}

	f.historyFail = "sudo: a password is required"
	*clock = clock.Add(time.Minute)
	tt.Frame()
	tt.Frame()
	// A quiet failure keeps the history shown.
	if f.historyReads != 3 || tt.HasText("web-01：读取封禁历史失败") || !tt.HasText("共 3 个 IP，封禁 5 次") {
		t.Errorf("history read %d times; texts %q", f.historyReads, tt.Texts())
	}
	f.historyFail = ""

	click(t, tt, "规则 (2)")
	tt.Frame()
	tt.Key(ui.Cmd, ui.KeyR)
	tt.Frame()
	if f.historyReads != 3 {
		t.Errorf("history read %d times away from its tab", f.historyReads)
	}
	click(t, tt, "封禁历史")
	tt.Frame()
	if f.historyReads != 4 {
		t.Errorf("history read %d times, showing it again", f.historyReads)
	}
}

func TestHistoryFails(t *testing.T) {
	f := historyF2B()
	f.historyFail = "sudo: a password is required"
	a, tt, _ := connected(t, f)
	click(t, tt, "封禁历史")
	tt.Frame()
	expect(t, tt, "未能读取封禁历史", "命令执行失败（退出码 1）：sudo: a password is required", "重试")
	if tt.HasText("web-01：读取封禁历史失败") {
		t.Error("a toast tells the tab's failure")
	}
	f.historyFail = ""
	click(t, tt, "重试")
	tt.Frame()
	expect(t, tt, "共 3 个 IP，封禁 5 次")

	// Disconnected, the history is forgotten, and read as the server
	// connects again.
	sv := a.views["s1"]
	a.disconnect(sv)
	if sv.history != nil || sv.historyLoading {
		t.Errorf("history kept: %+v", sv.history)
	}
	a.connect(sv)
	tt.Frame()
	if f.historyReads != 3 || !tt.HasText("共 3 个 IP，封禁 5 次") {
		t.Errorf("history read %d times; texts %q", f.historyReads, tt.Texts())
	}

	f.historySource = "none"
	click(t, tt, "刷新")
	tt.Frame()
	expect(t, tt, "未能读取封禁历史", "fail2ban 的日志不在文件或 systemd 日志中（logtarget 为 SYSLOG），也无法读取它的数据库：journalctl: [Errno 2] No such file or directory: 'journalctl'")
}

func TestHistorySource(t *testing.T) {
	since := time.Date(2026, 10, 12, 9, 30, 0, 0, time.Local)
	for _, c := range []struct {
		h    fail2ban.History
		want string
	}{
		{fail2ban.History{Source: fail2ban.SourceFile, Files: []string{"/var/log/fail2ban.log"}}, "记录来自 fail2ban 日志 /var/log/fail2ban.log。"},
		{fail2ban.History{Source: fail2ban.SourceJournal, Since: since}, "记录来自 systemd 日志（fail2ban），最早一条记录于 2026-10-12 09:30。"},
		{fail2ban.History{Source: fail2ban.SourceDB, Target: "SYSLOG", PurgeAge: 24 * time.Hour, Since: since, Count: 50000, Truncated: true},
			"fail2ban 的日志不在文件中（logtarget 为 SYSLOG），记录来自 fail2ban 数据库：只保留最近 1 天，且不含手动解封的封禁，最早一条记录于 2026-10-12 09:30；共 50000 条记录，只读取了最近 40000 条。"},
	} {
		if got := historySource(&c.h); got != c.want {
			t.Errorf("got  %q\nwant %q", got, c.want)
		}
	}
}
