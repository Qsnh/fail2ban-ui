package gui

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/rulelens/rulelens/internal/fail2ban"
)

// fill replaces the text of the input labeled label.
func fill(t *testing.T, tt *ui.Tester, label, text string) {
	t.Helper()
	click(t, tt, label)
	tt.Key(ui.Cmd, ui.KeyA)
	tt.Type(text)
}

// openDialog clicks button, which opens a dialog, and shows the tab of the
// firewall behind it, whose texts are none of the dialog's, which the
// tests click.
func openDialog(t *testing.T, tt *ui.Tester, a *App, button string) {
	t.Helper()
	click(t, tt, button)
	a.views["s1"].tab = tabFirewall
	tt.Frame()
}

// apply clicks button, which closes the dialog, and shows the rules again.
func apply(t *testing.T, tt *ui.Tester, a *App, button string) {
	t.Helper()
	click(t, tt, button)
	a.views["s1"].tab = 0
	tt.Frame()
}

// file returns RuleLens's file of a jail on the fake server, without its
// comments.
func file(f *fakeF2B, jail string) (string, bool) {
	text, ok := f.files["zz-rulelens-"+jail+".local"]
	var lines []string
	for line := range strings.Lines(text) {
		if !strings.HasPrefix(line, "# Managed") && !strings.HasPrefix(line, "# and run") {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, ""), ok
}

func TestNewPresetRule(t *testing.T) {
	f := newFakeF2B(sshdJail())
	f.presets = []string{"nginx-http-auth", "postfix"}
	a, tt, _ := connected(t, f)
	openDialog(t, tt, a, "新增规则")
	expect(t, tt, "可填写新名称自定义规则", "请填写规则名称", "本机在服务器上的 IP 为 198.51.100.7。")
	typeInto(t, tt, "规则名称", "nginx-http-auth")
	tt.Key(0, ui.KeyTab)
	tt.Frame()
	expect(t, tt, "fail2ban 预置的规则：留空的项使用其预置设置。", "将写入 /etc/fail2ban/jail.d/zz-rulelens-nginx-http-auth.local：")
	apply(t, tt, a, "新增并应用")
	if got, _ := file(f, "nginx-http-auth"); got != "# rulelens: created\n[nginx-http-auth]\nenabled = true\n" {
		t.Errorf("file:\n%s", got)
	}
	if a.ruleForm.open {
		t.Error("the dialog stays open")
	}
	// The jail runs, and shows.
	expect(t, tt, "规则 (2)", "已在 web-01 上新增规则 nginx-http-auth", "由 RuleLens 新增\n/etc/fail2ban/jail.d/zz-rulelens-nginx-http-auth.local")
	if a.views["s1"].jail != "nginx-http-auth" {
		t.Errorf("shows %q", a.views["s1"].jail)
	}
}

func TestNewCustomRule(t *testing.T) {
	f := newFakeF2B(sshdJail())
	a, tt, _ := connected(t, f)
	openDialog(t, tt, a, "新增规则")
	typeInto(t, tt, "规则名称", "myapp")
	tt.Key(0, ui.KeyTab)
	tt.Frame()
	expect(t, tt, "服务器上没有名为 myapp 的过滤器，请填写过滤器")
	typeInto(t, tt, "过滤器", "sshd")
	tt.Key(0, ui.KeyTab)
	tt.Frame()
	expect(t, tt, "请填写日志文件路径")
	typeInto(t, tt, "日志文件路径", "/var/log/myapp.log")
	typeInto(t, tt, "端口", "8022, 8023")
	typeInto(t, tt, "统计时长", "5m")
	typeInto(t, tt, "失败次数", "4")
	typeInto(t, tt, "封禁时长", "abc")
	tt.Frame()
	expect(t, tt, `封禁时长："abc" 不是有效的时长`)
	click(t, tt, "新增并应用")
	tt.Frame()
	if len(f.files) != 0 {
		t.Fatalf("applied a time not valid: %q", f.files)
	}
	fill(t, tt, "封禁时长", "2h")
	click(t, tt, "加入本机 IP")
	tt.Frame()
	expect(t, tt, "5 分钟内失败", "2 小时")
	if tt.HasText("加入本机 IP") {
		t.Error("offers this computer's address again")
	}
	apply(t, tt, a, "新增并应用")
	want := `# rulelens: created
[myapp]
enabled = true
filter = sshd
port = 8022,8023
logpath = /var/log/myapp.log
backend = auto
maxretry = 4
findtime = 5m
bantime = 2h
ignoreip = 198.51.100.7
`
	if got, _ := file(f, "myapp"); got != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}
	expect(t, tt, "规则 (2)", "myapp", "4 次 / 5 分钟", "8022,8023", "2 小时", "198.51.100.7")
}

func TestEditAndRevertRule(t *testing.T) {
	f := newFakeF2B(sshdJail("203.0.113.5"))
	a, tt, _ := connected(t, f)
	openDialog(t, tt, a, "编辑规则")
	expect(t, tt, "编辑规则 sshd", "还没有修改。")
	if r := a.ruleForm; r.maxRetry != "3" || r.findTime != "10m" || r.banTime != "1h" || r.port != "ssh" || r.logpath != "/var/log/auth.log" ||
		r.ignoreIP != "127.0.0.1/8 ::1" || r.source != sourceFiles || r.permanent {
		t.Errorf("form %+v", r.ruleFields)
	}
	fill(t, tt, "失败次数", "5")
	fill(t, tt, "封禁时长", "1d")
	tt.Frame()
	apply(t, tt, a, "保存并应用")
	// Only what changed is written.
	if got, _ := file(f, "sshd"); got != "[sshd]\nmaxretry = 5\nbantime = 1d\n" {
		t.Errorf("file:\n%s", got)
	}
	expect(t, tt, "5 次 / 10 分钟", "1 天", "RuleLens 修改了 maxretry、bantime", "已更新 web-01 上的规则 sshd", "203.0.113.5")

	// The file keeps what it set, as it was written.
	openDialog(t, tt, a, "编辑规则")
	if r := a.ruleForm; r.maxRetry != "5" || r.banTime != "1d" {
		t.Errorf("form %+v", r.ruleFields)
	}
	fill(t, tt, "统计时长", "1h")
	apply(t, tt, a, "保存并应用")
	if got, _ := file(f, "sshd"); got != "[sshd]\nmaxretry = 5\nbantime = 1d\nfindtime = 1h\n" {
		t.Errorf("file:\n%s", got)
	}

	click(t, tt, "还原配置")
	tt.Frame()
	expect(t, tt, "还原 web-01 上的规则 sshd？", "• maxretry = 5", "• findtime = 1h")
	click(t, tt, "还原")
	tt.Frame()
	if _, ok := file(f, "sshd"); ok {
		t.Error("the file stays")
	}
	expect(t, tt, "3 次 / 10 分钟", "已还原 web-01 上的规则 sshd")
	if tt.HasText("RuleLens 修改了") {
		t.Errorf("still changed: %q", tt.Texts())
	}
}

func TestStopAndStartRule(t *testing.T) {
	f := newFakeF2B(sshdJail("203.0.113.5"), recidiveJail())
	a, tt, _ := connected(t, f)
	click(t, tt, "停用")
	tt.Frame()
	expect(t, tt, "停用 web-01 上的规则 sshd？", "它当前封禁的 1 个 IP 将被解封", "enabled = false")
	click(t, tt, "停用规则")
	tt.Frame()
	if got, _ := file(f, "sshd"); got != "[sshd]\nenabled = false\n" {
		t.Errorf("file:\n%s", got)
	}
	// It shows stopped, last, still chosen.
	expect(t, tt, "规则 (1)", "已停用 web-01 上的规则 sshd", "此规则已停用：fail2ban 不再按它监控日志，也不再封禁。", "enabled = false")
	if a.views["s1"].f2b.Banned() != 0 || tt.HasText("编辑规则") == false {
		t.Errorf("banned %d: %q", a.views["s1"].f2b.Banned(), tt.Texts())
	}

	click(t, tt, "启用规则")
	tt.Frame()
	// Nothing is left of the file.
	if _, ok := file(f, "sshd"); ok {
		t.Errorf("files %q", f.files)
	}
	expect(t, tt, "规则 (2)", "已启用 web-01 上的规则 sshd", "10 分钟内失败 3 次的来源 IP 将被封禁 1 小时。")
}

func TestRemoveCreatedRule(t *testing.T) {
	f := newFakeF2B(sshdJail())
	o := &fail2ban.Override{Jail: "myapp", Created: true}
	o.Set("enabled", "true")
	o.Set("filter", "sshd")
	o.Set("logpath", "/var/log/myapp.log")
	f.files = map[string]string{"zz-rulelens-myapp.local": o.Render()}
	f.base = slices.Clone(f.jails)
	f.reload()
	a, tt, _ := connected(t, f)
	click(t, tt, "myapp")
	tt.Frame()
	expect(t, tt, "由 RuleLens 新增", "/var/log/myapp.log")
	click(t, tt, "删除")
	tt.Frame()
	expect(t, tt, "删除 web-01 上的规则 myapp？", "将删除 /etc/fail2ban/jail.d/zz-rulelens-myapp.local 并重新加载 fail2ban，规则停止运行。")
	click(t, tt, "删除规则")
	tt.Frame()
	if len(f.files) != 0 || len(f.jails) != 1 {
		t.Errorf("files %q, jails %d", f.files, len(f.jails))
	}
	expect(t, tt, "规则 (1)", "已删除 web-01 上的规则 myapp")
	if a.views["s1"].jail != "sshd" {
		t.Errorf("shows %q", a.views["s1"].jail)
	}
}

// A change fail2ban refuses leaves the dialog open, saying why, and the
// server as it was.
func TestRuleCheckFails(t *testing.T) {
	f := newFakeF2B(sshdJail())
	f.presets = []string{"nginx-http-auth"}
	f.testErr = "2026-10-19 02:48:59,040 fail2ban                [1223]: ERROR   Failed during configuration: Have not found any log file for nginx-http-auth jail\n"
	a, tt, _ := connected(t, f)
	openDialog(t, tt, a, "新增规则")
	typeInto(t, tt, "规则名称", "nginx-http-auth")
	tt.Key(0, ui.KeyTab)
	tt.Frame()
	click(t, tt, "新增并应用")
	tt.Frame()
	if !a.ruleForm.open || a.ruleForm.applying || f.changes != 0 || len(f.files) != 0 {
		t.Fatalf("form %+v, changes %d", a.ruleForm, f.changes)
	}
	expect(t, tt, "配置校验未通过，已还原，服务器未改动：找不到规则 nginx-http-auth 的日志文件")
	if tt.HasText("web-01：应用规则失败") {
		t.Error("a toast tells too")
	}

	f.testErr = ""
	typeInto(t, tt, "日志文件路径", "/var/log/nginx/error.log")
	apply(t, tt, a, "新增并应用")
	if got, _ := file(f, "nginx-http-auth"); !strings.Contains(got, "logpath = /var/log/nginx/error.log\nbackend = auto\n") || a.ruleForm.open {
		t.Errorf("file:\n%s", got)
	}
}

// A rule of its own must not take a name in use.
func TestNewRuleNames(t *testing.T) {
	f := newFakeF2B(sshdJail())
	o := &fail2ban.Override{Jail: "postfix"}
	o.Set("enabled", "false")
	f.files = map[string]string{"zz-rulelens-postfix.local": o.Render()}
	a, tt, _ := connected(t, f)
	s := a.views["s1"].f2b
	for name, want := range map[string]string{
		"sshd":    "规则 sshd 已存在，可在列表中选中它后编辑",
		"postfix": "规则 postfix 已停用，可在列表中选中它后启用",
		"a b":     "规则名称 \"a b\" 只能包含",
		"DEFAULT": "DEFAULT 是 fail2ban 保留的名称",
	} {
		r := ruleForm{name: name}
		if _, err := r.override(s); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", name, err)
		}
	}
	expect(t, tt, "postfix", "已停用")
}

// The form switches a jail between its logs and the journal, as the
// backend says.
func TestRuleSources(t *testing.T) {
	s := &fail2ban.Status{
		Running: true,
		Jails:   []fail2ban.Jail{{Name: "sshd", MaxRetry: 3, FindTime: 10 * time.Minute, BanTime: time.Hour, Journal: true, JournalMatch: []string{"_SYSTEMD_UNIT=sshd.service"}}},
		Config:  fail2ban.Config{Read: true, Filters: []string{"sshd"}, Jails: map[string]bool{"sshd": true}},
	}
	j, _ := s.Jail("sshd")
	fields := jailFields(j)
	r := ruleForm{editing: "sshd", name: "sshd", ruleFields: fields, orig: fields}
	if r.source != sourceJournal {
		t.Fatalf("source %d", r.source)
	}
	r.source = sourceFiles
	if _, err := r.override(s); err == nil || err.Error() != "请填写日志文件路径" {
		t.Errorf("no logs: %v", err)
	}
	r.logpath = "/var/log/auth.log"
	o, err := r.override(s)
	if err != nil || !slices.Equal(o.Settings, []fail2ban.Setting{{Key: "logpath", Value: "/var/log/auth.log"}, {Key: "backend", Value: "auto"}}) {
		t.Fatalf("%+v, %v", o, err)
	}

	// Back to the journal, the file forgets the logs.
	r = ruleForm{editing: "sshd", name: "sshd", base: o}
	r.take(o)
	r.orig = r.ruleFields
	r.source = sourceJournal
	if o, err = r.override(s); err != nil || !slices.Equal(o.Settings, []fail2ban.Setting{{Key: "backend", Value: "systemd"}}) {
		t.Errorf("%+v, %v", o, err)
	}

	// Permanent bans, increasing up to a week.
	r = ruleForm{editing: "sshd", name: "sshd", ruleFields: fields, orig: fields}
	r.permanent, r.increment, r.maxTime = true, true, "7d"
	if o, err = r.override(s); err != nil || !slices.Equal(o.Settings, []fail2ban.Setting{{Key: "bantime", Value: "-1"}, {Key: "bantime.increment", Value: "true"}, {Key: "bantime.maxtime", Value: "1w"}}) {
		t.Errorf("%+v, %v", o, err)
	}
	r.ignoreIP = "10.0.0.0/8 bad;ip"
	if _, err = r.override(s); err == nil || !strings.Contains(err.Error(), "忽略 IP") {
		t.Errorf("address: %v", err)
	}

	// What the server has passes unchecked: only what is typed is.
	odd := fields
	odd.port, odd.ignoreIP, odd.logpath = "ssh port", "127.0.0.1/8 host_name", "/var/log/a b"
	r = ruleForm{editing: "sshd", name: "sshd", ruleFields: odd, orig: odd}
	r.maxRetry = "6"
	if o, err = r.override(s); err != nil || !slices.Equal(o.Settings, []fail2ban.Setting{{Key: "maxretry", Value: "6"}}) {
		t.Errorf("%+v, %v", o, err)
	}
}

// The dialog closes as the server disconnects.
func TestRuleDialogDisconnected(t *testing.T) {
	a, tt, _ := connected(t, newFakeF2B(sshdJail()))
	click(t, tt, "编辑规则")
	tt.Frame()
	a.disconnect(a.views["s1"])
	tt.Frame()
	if a.ruleForm.open || tt.HasText("编辑规则 sshd") {
		t.Errorf("open: %q", tt.Texts())
	}
}

// A jail chosen by the app, at the row the table chose before for another,
// shows chosen: the table does not follow the other as it moves.
func TestChoiceOfJailMoved(t *testing.T) {
	f := newFakeF2B(recidiveJail(), sshdJail())
	a, tt, _ := connected(t, f)
	click(t, tt, "sshd")
	tt.Frame()
	sv := a.views["s1"]
	if sv.jail != "sshd" || sv.jailRow != 1 {
		t.Fatalf("jail %q at %d", sv.jail, sv.jailRow)
	}
	f.jails = []fakeJail{f.jails[0], {name: "myapp", port: "8022", action: "nftables", maxRetry: 4, findTime: 300, banTime: 600, logPath: "/var/log/myapp.log"}, f.jails[1]}
	a.refresh(sv)
	sv.jail = "myapp"
	tt.Frame()
	tt.Frame()
	if sv.jail != "myapp" || sv.jailRow != 1 || !tt.HasText("5 分钟内失败 4 次的来源 IP 将被封禁 10 分钟。") {
		t.Errorf("jail %q at %d: %q", sv.jail, sv.jailRow, tt.Texts())
	}
}
