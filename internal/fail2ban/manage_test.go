package fail2ban

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rulelens/rulelens/internal/remote"
)

func TestOverrideRenderAndParse(t *testing.T) {
	o := &Override{Jail: "nginx-http-auth", Created: true}
	o.Set("enabled", "true")
	o.Set("port", "http,https")
	o.Set("logpath", "/var/log/nginx/error.log\n/var/log/nginx/*error.log")
	o.Set("maxretry", "5")
	o.Set("port", "https")
	want := `# Managed by RuleLens: change this jail in RuleLens, or delete this file
# and run "fail2ban-client reload" to undo these settings.
# rulelens: created
[nginx-http-auth]
enabled = true
port = https
logpath = /var/log/nginx/error.log
          /var/log/nginx/*error.log
maxretry = 5
`
	if got := o.Render(); got != want {
		t.Errorf("Render:\n%s\nwant:\n%s", got, want)
	}
	p := ParseOverride("nginx-http-auth", want)
	if !p.Equal(o) {
		t.Errorf("parsed %+v, want %+v", p, o)
	}
	if v, ok := p.Get("logpath"); !ok || v != "/var/log/nginx/error.log\n/var/log/nginx/*error.log" {
		t.Errorf("logpath %q", v)
	}

	// A file edited by hand: other sections, comments, ":" for "=", keys
	// in capitals.
	p = ParseOverride("sshd", "[DEFAULT]\nbantime = 1d\n\n[sshd]\n; mine\nMaxRetry: 2\nignoreip = 127.0.0.1/8\n  10.0.0.0/8\n[recidive]\nenabled = false\n")
	if p.Created || !slices.Equal(p.Settings, []Setting{{"maxretry", "2"}, {"ignoreip", "127.0.0.1/8\n10.0.0.0/8"}}) || p.Disabled() {
		t.Errorf("by hand: %+v", p)
	}
	p.Set("enabled", "false")
	p.Unset("maxretry")
	if !p.Disabled() || p.Has("maxretry") || p.Settings[0].Key != "ignoreip" {
		t.Errorf("changed: %+v", p)
	}
	c := p.Clone()
	c.Set("bantime", "1h")
	c.Settings[0].Value = "x"
	if p.Has("bantime") || p.Settings[0].Value == "x" {
		t.Error("the clone shares its settings")
	}
}

func TestValidate(t *testing.T) {
	for _, name := range []string{"sshd", "nginx-http-auth", "my_app.v2"} {
		if err := ValidJailName(name); err != nil {
			t.Errorf("ValidJailName(%q): %v", name, err)
		}
	}
	for _, name := range []string{"", "-x", "a b", "a/b", "../x", "DEFAULT", "includes", "x]\n[y", strings.Repeat("a", 65)} {
		if ValidJailName(name) == nil {
			t.Errorf("ValidJailName(%q) passed", name)
		}
	}
	for _, p := range []string{"ssh", "ssh,2222", "http,https", "0:65535", "8000-8100", "smtp,465,submission"} {
		if err := ValidPort(p); err != nil {
			t.Errorf("ValidPort(%q): %v", p, err)
		}
	}
	for _, p := range []string{"", "99999", "22 ,23", "ssh;reboot", "%(ssh_port)s", "1:70000", ","} {
		if ValidPort(p) == nil {
			t.Errorf("ValidPort(%q) passed", p)
		}
	}
	for _, a := range []string{"127.0.0.1/8", "::1", "10.0.0.0/8", "203.0.113.5", "2001:db8::/32", "gw.example.com"} {
		if err := ValidAddress(a); err != nil {
			t.Errorf("ValidAddress(%q): %v", a, err)
		}
	}
	for _, a := range []string{"1.2.3.4;x", "a b", "%(x)s", "-1.2.3.4"} {
		if ValidAddress(a) == nil {
			t.Errorf("ValidAddress(%q) passed", a)
		}
	}
	if name, err := ValidFilter("sshd[mode=aggressive]"); err != nil || name != "sshd" {
		t.Errorf("ValidFilter: %q %v", name, err)
	}
	for _, f := range []string{"", "a b", "../x", "x[%(y)s]"} {
		if _, err := ValidFilter(f); err == nil {
			t.Errorf("ValidFilter(%q) passed", f)
		}
	}
	if ValidLogPath("/var/log/nginx/*error.log") != nil || ValidLogPath("var/log/x") == nil || ValidLogPath("/var/log/%(x)s") == nil {
		t.Error("ValidLogPath")
	}
}

func TestTimes(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"600":     10 * time.Minute,
		"10m":     10 * time.Minute,
		"1h30m":   90 * time.Minute,
		"1H 30M":  90 * time.Minute,
		"1d":      24 * time.Hour,
		"2w":      14 * 24 * time.Hour,
		"1h30":    time.Hour + 30*time.Second,
		"90s":     90 * time.Second,
		"1d12h":   36 * time.Hour,
		"0":       0,
		" 5 m ":   5 * time.Minute,
		"1w2d":    9 * 24 * time.Hour,
		"10m10m":  20 * time.Minute,
		"3600 s":  time.Hour,
		"86400":   24 * time.Hour,
		"5m 30s ": 5*time.Minute + 30*time.Second,
	} {
		if got, err := ParseTime(in); err != nil || got != want {
			t.Errorf("ParseTime(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "abc", "10x", "-1", "1.5h", "h", "1e9"} {
		if _, err := ParseTime(in); err == nil {
			t.Errorf("ParseTime(%q) passed", in)
		}
	}
	for d, want := range map[time.Duration]string{
		-time.Second:        "-1",
		0:                   "0",
		10 * time.Minute:    "10m",
		90 * time.Minute:    "1h30m",
		time.Hour:           "1h",
		36 * time.Hour:      "1d12h",
		7 * 24 * time.Hour:  "1w",
		10 * 24 * time.Hour: "10d",
		90 * time.Second:    "1m30s",
	} {
		if got := FormatTime(d); got != want {
			t.Errorf("FormatTime(%v) = %q, want %q", d, got, want)
		}
		if d >= 0 {
			if back, err := ParseTime(FormatTime(d)); err != nil || back != d {
				t.Errorf("ParseTime(FormatTime(%v)) = %v, %v", d, back, err)
			}
		}
	}
}

func TestChangeCommand(t *testing.T) {
	o := &Override{Jail: "sshd"}
	o.Set("maxretry", "5")
	o.Set("ignoreip", "127.0.0.1/8 it's")
	cmd, err := ChangeCommand(Change{Jail: "sshd", Override: o})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"f=/etc/fail2ban/jail.d/zz-rulelens-sshd.local\n",
		"printf '%s' '# Managed by RuleLens",
		"[sshd]\nmaxretry = 5\nignoreip = 127.0.0.1/8 it'\\''s\n'",
		"fail2ban-client -t 2>&1",
		"fail2ban-client reload 2>&1",
	} {
		if !strings.Contains(cmd, s) {
			t.Errorf("no %q in\n%s", s, cmd)
		}
	}
	// The file is checked before fail2ban reloads it.
	if strings.Index(cmd, "-t 2>&1") > strings.Index(cmd, "reload 2>&1") {
		t.Errorf("reloads first:\n%s", cmd)
	}
	cmd, _ = ChangeCommand(Change{Jail: "sshd"})
	if !strings.Contains(cmd, `rm -f "$f" || { undo; exit 2; }`) || strings.Contains(cmd, "printf '%s' '#") {
		t.Errorf("removing:\n%s", cmd)
	}
	if _, err := ChangeCommand(Change{Jail: "../../passwd"}); err == nil {
		t.Error("a path for a jail")
	}
	if _, err := ChangeCommand(Change{Jail: "sshd", Override: &Override{Jail: "recidive"}}); err == nil {
		t.Error("the file of another jail")
	}
}

// exitExec exits as the change's script does when a step fails.
type exitExec struct {
	code int
	out  string
	cmds []string
}

func (x *exitExec) Run(ctx context.Context, cmd string) (remote.Result, error) {
	return remote.Result{}, nil
}

func (x *exitExec) RunPrivileged(ctx context.Context, cmd string) (remote.Result, error) {
	x.cmds = append(x.cmds, cmd)
	return remote.Result{ExitCode: x.code, Stderr: x.out}, nil
}

func TestApply(t *testing.T) {
	x := &exitExec{}
	if err := Apply(context.Background(), x, Change{Jail: "sshd"}); err != nil || len(x.cmds) != 1 || !strings.HasPrefix(x.cmds[0], remote.Prelude) {
		t.Fatalf("%v: %q", err, x.cmds)
	}

	// fail2ban-client's own words, as 1.0.2 prints them.
	x = &exitExec{code: 3, out: `2026-10-19 02:48:59,036 fail2ban.configreader   [1223]: WARNING 'allowipv6' not defined in 'Definition'. Using default one: 'auto'
2026-10-19 02:48:59,040 fail2ban                [1223]: ERROR   Failed during configuration: Have not found any log file for nginx-http-auth jail
2026-10-19 02:48:59,040 fail2ban                [1223]: ERROR   ERROR: test configuration failed
`}
	err := Apply(context.Background(), x, Change{Jail: "nginx-http-auth"})
	var ce *ChangeError
	if !errors.As(err, &ce) || !ce.Checking ||
		ce.Output != "找不到规则 nginx-http-auth 的日志文件，请检查日志路径，或改用 systemd 日志（Failed during configuration: Have not found any log file for nginx-http-auth jail）" {
		t.Fatalf("%#v", err)
	}
	if !strings.HasPrefix(err.Error(), "配置校验未通过，已还原，服务器未改动：找不到规则") {
		t.Errorf("message %q", err)
	}

	x = &exitExec{code: 3, out: `2026-10-19 02:49:13,514 fail2ban.configreader   [1287]: ERROR   Found no accessible config files for 'filter.d/nosuch' under /etc/fail2ban
2026-10-19 02:49:13,514 fail2ban.jailreader     [1287]: ERROR   Unable to read the filter 'nosuch'
2026-10-19 02:49:13,514 fail2ban.jailsreader    [1287]: ERROR   Errors in jail 'rl-test'.
`}
	err = Apply(context.Background(), x, Change{Jail: "rl-test"})
	if !errors.As(err, &ce) || !strings.Contains(ce.Output, "服务器上没有过滤器 nosuch（/etc/fail2ban/filter.d/nosuch.conf）") || !strings.Contains(ce.Output, "Errors in jail 'rl-test'.") {
		t.Errorf("%v", err)
	}

	x = &exitExec{code: 4, out: "Sorry but the jail 'x' does not exist\n"}
	if err := Apply(context.Background(), x, Change{Jail: "x"}); !errors.As(err, &ce) || ce.Checking || err.Error() != "fail2ban 重新加载失败，已还原配置：Sorry but the jail 'x' does not exist" {
		t.Errorf("%v", err)
	}
	x = &exitExec{code: 2, out: "mv: cannot move: Read-only file system\n"}
	if err := Apply(context.Background(), x, Change{Jail: "x"}); err == nil || errors.As(err, &ce) || !strings.Contains(err.Error(), "Read-only file system") {
		t.Errorf("%v", err)
	}
}

func TestStoppedAndPresets(t *testing.T) {
	s := &Status{
		Jails: []Jail{{Name: "sshd"}, {Name: "recidive"}},
		Config: Config{
			Read:  true,
			Jails: map[string]bool{"sshd": true, "recidive": true, "nginx-http-auth": false, "apache-auth": false, "postfix": false, "dovecot": false},
			Overrides: map[string]*Override{
				"postfix":  ParseOverride("postfix", "[postfix]\nenabled = false\n"),
				"dovecot":  ParseOverride("dovecot", "[dovecot]\nmaxretry = 2\n"),
				"recidive": ParseOverride("recidive", "[recidive]\nenabled = false\n"), // not reloaded yet
			},
		},
	}
	if got := s.Stopped(); !slices.Equal(got, []string{"postfix"}) {
		t.Errorf("stopped %q", got)
	}
	if got := s.Presets(); !slices.Equal(got, []string{"apache-auth", "nginx-http-auth"}) {
		t.Errorf("presets %q", got)
	}
}
