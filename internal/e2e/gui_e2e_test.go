package e2e

import (
	"context"
	"fmt"
	"image/png"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/rulelens/rulelens/internal/gui"
	"github.com/rulelens/rulelens/internal/remote"
	"github.com/rulelens/rulelens/internal/session"
	"github.com/rulelens/rulelens/internal/sshx"
	"github.com/rulelens/rulelens/internal/store"
)

// TestWindow drives the window, without one, against the real server: it
// adds the server as a user would, trusts its key, and finds the server's
// jails, then an address banned meanwhile.
func TestWindow(t *testing.T) {
	addr := os.Getenv("RULELENS_E2E")
	if addr == "" {
		t.Skip("RULELENS_E2E is not set")
	}
	host, port, _ := net.SplitHostPort(addr)
	c := dial(t)
	f2b(t, c, "unban", "--all")

	dir := t.TempDir()
	inv, err := store.Open(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The clock runs ahead when the test says, for automatic refreshing.
	var ahead time.Duration
	a := gui.New(gui.Options{
		Inventory: inv,
		Vault:     &store.MemoryVault{},
		Dialer:    &session.SSHDialer{HostKeys: sshx.NewHostKeys(filepath.Join(dir, "known_hosts"))},
		Now:       func() time.Time { return time.Now().Add(ahead) },
		Settings:  store.Settings{RefreshSeconds: 60},
	})
	defer a.Close()
	tt := ui.NewTester(a.View, 1280, 820)
	step := func(what string, fn func() error) {
		t.Helper()
		if err := fn(); err != nil {
			t.Fatalf("%s: %v\ntexts %q", what, err, tt.Texts())
		}
	}
	click := func(s string) { t.Helper(); step("click "+s, func() error { return tt.Click(s) }) }
	fill := func(label, text string) {
		t.Helper()
		click(label)
		tt.Key(ui.Cmd, ui.KeyA)
		tt.Type(text)
	}
	expect := func(s string) {
		t.Helper()
		tt.Frame()
		if !tt.HasText(s) {
			t.Fatalf("no %q among %q", s, tt.Texts())
		}
	}
	// With RULELENS_SNAPSHOTS set, the pages are drawn there too.
	snapshot := func(name string) {
		t.Helper()
		dir := os.Getenv("RULELENS_SNAPSHOTS")
		if dir == "" {
			return
		}
		tt.SetScale(2)
		defer tt.SetScale(1)
		tt.Frame()
		f, err := os.Create(filepath.Join(dir, name+".png"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		png.Encode(f, tt.Image())
	}
	clickPrefix := func(prefix string) {
		t.Helper()
		for _, s := range tt.Texts() {
			if strings.HasPrefix(s, prefix) {
				click(s)
				return
			}
		}
		t.Fatalf("no %q… among %q", prefix, tt.Texts())
	}

	tt.Key(ui.Cmd, ui.KeyN)
	fill("服务器名称", "docker-ubuntu")
	fill("主机地址", host)
	fill("SSH 端口", port)
	fill("登录用户名", "ops")
	fill("登录密码", "rulelens")
	click("添加并连接")
	expect("确认主机指纹")
	click("信任并连接")
	expect("fail2ban 运行中")
	expect("Ubuntu 2") // 24.04 or 22.04
	expect("规则 (2)")
	expect("sshd")
	expect("recidive")
	expect("ssh,2222")
	expect("3 次 / 10 分钟")
	expect("1 天内失败 5 次的来源 IP 将被封禁 1 周。") // recidive comes first
	click("sshd")
	expect("10 分钟内失败 3 次的来源 IP 将被封禁 1 小时。")
	expect("/var/log/auth.log")

	// An address banned meanwhile shows once refreshed: by itself, a
	// minute later.
	f2b(t, c, "set", "sshd", "banip", "203.0.113.51")
	t.Cleanup(func() { f2b(t, c, "set", "sshd", "unbanip", "203.0.113.51") })
	ahead = time.Minute
	tt.Frame()
	expect("203.0.113.51") // in the detail of sshd
	snapshot("e2e-rules")
	// recidive may ban too, as the tests ban addresses again and again.
	clickPrefix("封禁 IP (")
	expect("203.0.113.51")
	expect("59 分钟")
	snapshot("e2e-bans")
	click("防火墙中的封禁")
	tt.Frame()
	found := false
	for _, s := range tt.Texts() {
		if strings.Contains(s, "f2b-") && strings.Contains(s, "203.0.113.51") {
			found = true
		}
	}
	if !found {
		t.Errorf("no ban in the firewall: %q", tt.Texts())
	}
	snapshot("e2e-firewall")

	// Lifting the ban from the window lifts it on the server.
	// An address of its own each run: recidive bans one banned again and
	// again, which would keep it listed.
	ip := fmt.Sprintf("203.0.113.%d", 60+time.Now().UnixNano()%40)
	f2b(t, c, "set", "sshd", "banip", ip)
	tt.Key(ui.Cmd, ui.KeyR)
	clickPrefix("封禁 IP (")
	click(ip)
	click("解封 1 项")
	expect("解封 " + ip + "？")
	click("解封")
	expect("203.0.113.51")
	for _, s := range tt.Texts() {
		if s == ip {
			t.Errorf("still listed: %q", tt.Texts())
		}
	}
	if out := f2b(t, c, "status", "sshd"); strings.Contains(out, ip) || !strings.Contains(out, "203.0.113.51") {
		t.Errorf("server's bans:\n%s", out)
	}

	// The history lists the address lifted, and the one banned still.
	click("封禁历史")
	expect("按 IP")
	expect(ip)
	expect("203.0.113.51")
	expect("封禁中")
	snapshot("e2e-history")
	fill("筛选历史", ip)
	click("按次")
	expect("匹配 1 个 IP，封禁")
	expect("已解封")
	snapshot("e2e-history-bans")

	// The log shows the commands, and never a password.
	clickPrefix("操作日志")
	tt.Frame()
	logged := false
	for _, s := range tt.Texts() {
		logged = logged || strings.Contains(s, "fail2ban-client")
		// The files of RuleLens are named so, the password is not.
		if s := strings.ReplaceAll(s, "zz-rulelens-", ""); strings.Contains(s, "rulelens") && !strings.Contains(s, "RuleLens") {
			t.Errorf("the log shows the password: %q", s)
		}
	}
	if !logged {
		t.Errorf("the log lacks the commands: %q", tt.Texts())
	}

	// A jail created in the window runs on the server, stops, and goes.
	const jail = "rulelens-gui"
	t.Cleanup(func() {
		remote.Check(context.Background(), c, true, remote.Prelude+"rm -f /etc/fail2ban/jail.d/zz-rulelens-"+jail+".local && fail2ban-client reload")
	})
	jails := func() string { return f2b(t, c, "status") }
	clickPrefix("规则 (")
	click("新增规则")
	expect("可填写新名称自定义规则")
	fill("规则名称", jail)
	tt.Key(0, ui.KeyTab)
	fill("过滤器", "sshd")
	tt.Key(0, ui.KeyTab)
	fill("日志文件路径", "/var/log/auth.log")
	fill("统计时长", "5m")
	fill("失败次数", "4")
	expect("将写入 /etc/fail2ban/jail.d/zz-rulelens-" + jail + ".local：")
	snapshot("e2e-rule-new")
	click("新增并应用")
	expect("已在 docker-ubuntu 上新增规则 " + jail)
	expect("4 次 / 5 分钟")
	expect("由 RuleLens 新增")
	if !strings.Contains(jails(), jail) {
		t.Errorf("not running:\n%s", jails())
	}
	if got := f2b(t, c, "get", jail, "findtime"); strings.TrimSpace(got) != "300" {
		t.Errorf("findtime %q", got)
	}
	snapshot("e2e-rule-created")

	click("停用")
	expect("停用 docker-ubuntu 上的规则 " + jail + "？")
	click("停用规则")
	expect("已停用 docker-ubuntu 上的规则 " + jail)
	expect("此规则已停用")
	if strings.Contains(jails(), jail) {
		t.Errorf("still running:\n%s", jails())
	}
	click("删除")
	expect("删除 docker-ubuntu 上的规则 " + jail + "？")
	click("删除规则")
	expect("已删除 docker-ubuntu 上的规则 " + jail)
	res, err := remote.Check(context.Background(), c, true, "ls /etc/fail2ban/jail.d")
	if err != nil || strings.Contains(res.Stdout, jail) {
		t.Errorf("files %q, %v", res.Stdout, err)
	}
}
