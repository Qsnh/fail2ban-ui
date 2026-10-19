package gui

import (
	"errors"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/rulelens/rulelens/internal/fail2ban"
	"github.com/rulelens/rulelens/internal/sshx"
	"github.com/rulelens/rulelens/internal/store"
)

func newTestApp(t *testing.T) (*App, *fakeDialer, *store.Inventory, *store.MemoryVault) {
	t.Helper()
	inv, err := store.Open(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	vault := &store.MemoryVault{}
	d := newFakeDialer(t)
	return New(Options{Inventory: inv, Vault: vault, Dialer: d, Now: func() time.Time { return testNow }}), d, inv, vault
}

func click(t *testing.T, tt *ui.Tester, s string) {
	t.Helper()
	if err := tt.Click(s); err != nil {
		t.Fatalf("%v; texts %q", err, tt.Texts())
	}
}

func typeInto(t *testing.T, tt *ui.Tester, label, text string) {
	t.Helper()
	click(t, tt, label)
	tt.Type(text)
}

func expect(t *testing.T, tt *ui.Tester, texts ...string) {
	t.Helper()
	for _, s := range texts {
		if !tt.HasText(s) {
			t.Errorf("no %q among %q", s, tt.Texts())
		}
	}
}

func TestAddServerTrustAndConnect(t *testing.T) {
	a, d, inv, vault := newTestApp(t)
	tt := ui.NewTester(a.View, 1280, 820)
	if !tt.HasText("添加第一台服务器") {
		t.Fatalf("no welcome: %q", tt.Texts())
	}
	tt.Key(ui.Cmd, ui.KeyN)
	if !tt.HasText("添加并连接") {
		t.Fatalf("no server dialog: %q", tt.Texts())
	}
	typeInto(t, tt, "服务器名称", "web-01")
	typeInto(t, tt, "主机地址", "203.0.113.10")
	typeInto(t, tt, "登录密码", "s3cret")
	typeInto(t, tt, "服务器分组", "生产")
	click(t, tt, "添加并连接")

	servers := inv.List()
	if len(servers) != 1 || servers[0].Name != "web-01" || servers[0].Host != "203.0.113.10" || servers[0].User != "root" ||
		servers[0].Port != 22 || servers[0].Auth != sshx.AuthPassword || servers[0].Group != "生产" {
		t.Fatalf("inventory %+v", servers)
	}
	if sec, _ := vault.Get(servers[0].ID); sec.Password != "s3cret" {
		t.Errorf("vault %+v", sec)
	}
	// The first connection asks to trust the server's key.
	tt.Frame()
	if !tt.HasText("确认主机指纹") || !tt.HasText(ssh256(d)) {
		t.Fatalf("no fingerprint question: %q", tt.Texts())
	}
	click(t, tt, "信任并连接")
	if !d.trusted["203.0.113.10:22"] {
		t.Error("key not trusted")
	}
	tt.Frame()
	expect(t, tt, "fail2ban 运行中", "Ubuntu 24.04.1 LTS", "fail2ban 1.0.2", "规则 (1)", "sshd")
	if len(d.dialed) != 2 || d.dialed[1].Password != "s3cret" {
		t.Errorf("dialed with %+v", d.dialed)
	}
}

func ssh256(d *fakeDialer) string {
	return strings.Fields(sshx.Fingerprint(d.key))[1]
}

// connected returns an app showing a server connected to f.
func connected(t *testing.T, f *fakeF2B) (*App, *ui.Tester, *fakeDialer) {
	t.Helper()
	a, d, inv, vault := newTestApp(t)
	srv := store.Server{ID: "s1", Name: "web-01", Host: "203.0.113.10", Port: 22, User: "ops", Auth: sshx.AuthPassword}
	inv.Put(srv)
	vault.Set("s1", store.Secrets{Password: "pw"})
	d.trusted["203.0.113.10:22"] = true
	d.servers["203.0.113.10"] = f
	a.page = "s1"
	a.servers()
	a.connect(a.views["s1"])
	tt := ui.NewTester(a.View, 1280, 820)
	if a.views["s1"].state != stateConnected {
		t.Fatalf("state %v: %s", a.views["s1"].state, a.views["s1"].err)
	}
	return a, tt, d
}

func TestJailsAndDetail(t *testing.T) {
	f := newFakeF2B(sshdJail("203.0.113.5", "198.51.100.23"), recidiveJail("192.0.2.77"))
	_, tt, _ := connected(t, f)
	expect(t, tt, "规则 (2)", "封禁 IP (3)", "当前封禁 IP", "sshd", "recidive", "3 次 / 10 分钟", "1 小时", "永久", "全部端口")
	// The first jail shows in detail.
	expect(t, tt, "10 分钟内失败 3 次的来源 IP 将被封禁 1 小时。", "ssh（tcp）", "iptables-multiport", "/var/log/auth.log",
		"127.0.0.1/8  ::1", "203.0.113.5", "50 分钟", "匹配规则 failregex（2）")
	readable := false
	for _, s := range tt.Texts() {
		if strings.Contains(s, "for .* from <HOST>( via") {
			readable = true
		}
		if strings.Contains(s, "(?P<ip4>") {
			t.Errorf("an expanded failregex shows: %q", s)
		}
	}
	if !readable {
		t.Errorf("no readable failregex: %q", tt.Texts())
	}

	click(t, tt, "recidive")
	tt.Frame()
	expect(t, tt, "1 天内失败 5 次的来源 IP 将被永久封禁。", "iptables-allports", "192.0.2.77")
	if tt.HasText("203.0.113.5") {
		t.Errorf("the bans of sshd still show: %q", tt.Texts())
	}
}

func TestBansTab(t *testing.T) {
	f := newFakeF2B(sshdJail("203.0.113.5", "198.51.100.23"), recidiveJail("192.0.2.77"))
	a, tt, _ := connected(t, f)
	click(t, tt, "封禁 IP (3)")
	tt.Frame()
	expect(t, tt, "203.0.113.5", "198.51.100.23", "192.0.2.77", "09:50:00", "50 分钟", "10:50:00", "不解封")
	typeInto(t, tt, "筛选封禁", "recid")
	tt.Frame()
	if tt.HasText("203.0.113.5") || !tt.HasText("192.0.2.77") {
		t.Errorf("filtered by jail: %q", tt.Texts())
	}

	rows := banRows(a.views["s1"].f2b, "", ui.SortOrder{}, testNow)
	if len(rows) != 3 || rows[0].IP != "192.0.2.77" || rows[1].IP != "198.51.100.23" || rows[2].IP != "203.0.113.5" {
		t.Errorf("by address: %+v", rows)
	}
	rows = banRows(a.views["s1"].f2b, "", ui.SortOrder{Column: "剩余", Descending: true}, testNow)
	if rows[0].Jail != "recidive" {
		t.Errorf("by time left: %+v", rows)
	}
}

// The bans since fail2ban started outnumber those still on, as bans end:
// the page says so where the list is empty.
func TestBansEnded(t *testing.T) {
	j := sshdJail()
	j.total = 51
	_, tt, _ := connected(t, newFakeF2B(j))
	expect(t, tt, "51", "启动以来，含已解封", "当前 0 · 启动以来 51（含已解封）")
	click(t, tt, "封禁 IP (0)")
	tt.Frame()
	expect(t, tt, "当前没有被封禁的 IP", "fail2ban 启动以来共封禁 51 次，均已解封。")
	click(t, tt, "查看封禁历史")
	tt.Frame()
	expect(t, tt, "没有封禁记录")
}

func TestFirewallTab(t *testing.T) {
	f := newFakeF2B(sshdJail("203.0.113.5"))
	f.firewall = "# iptables -S\n-A f2b-sshd -s 203.0.113.5/32 -j REJECT --reject-with icmp-port-unreachable"
	_, tt, _ := connected(t, f)
	click(t, tt, "防火墙中的封禁")
	tt.Frame()
	expect(t, tt, f.firewall)

	f.firewall = ""
	tt.Key(ui.Cmd, ui.KeyR)
	tt.Frame()
	expect(t, tt, "防火墙中没有 fail2ban 的规则")
}

func TestNotInstalledOrNotRunning(t *testing.T) {
	f := newFakeF2B()
	f.missing = true
	a, tt, _ := connected(t, f)
	expect(t, tt, "服务器未安装 fail2ban", "未安装 fail2ban")

	f.missing, f.down = false, true
	click(t, tt, "刷新")
	tt.Frame()
	expect(t, tt, "fail2ban 未运行")
	if !strings.Contains(a.views["s1"].f2b.Problem, "No such file") {
		t.Errorf("problem %q", a.views["s1"].f2b.Problem)
	}

	f.down = false
	f.jails = nil
	click(t, tt, "刷新")
	tt.Frame()
	expect(t, tt, "fail2ban 运行中", "没有启用的规则（jail）")
}

func TestReadFails(t *testing.T) {
	f := newFakeF2B(sshdJail())
	f.fail = fmt.Errorf("%w：%s", sshx.ErrSudo, "该用户没有 sudo 权限")
	a, tt, _ := connected(t, f)
	expect(t, tt, "未能读取 fail2ban", "sudo 提权失败：该用户没有 sudo 权限")

	// Once read, a failure keeps what was read and tells.
	f.fail = nil
	click(t, tt, "刷新")
	tt.Frame()
	expect(t, tt, "sshd")
	f.fail = errors.New("timeout")
	a.read(a.views["s1"], false)
	tt.Frame()
	expect(t, tt, "sshd", "web-01：读取 fail2ban 失败")
}

func TestOverview(t *testing.T) {
	f := newFakeF2B(sshdJail("203.0.113.5", "198.51.100.23"), recidiveJail("192.0.2.77"))
	a, tt, _ := connected(t, f)
	a.page = pageOverview
	tt.Frame()
	expect(t, tt, "概览", "web-01", "ops@203.0.113.10", "fail2ban 运行中", "当前封禁 IP", "sshd", "ssh",
		"3 次 / 10 分钟 → 封禁 1 小时", "封禁 2", "recidive", "5 次 / 1 天 → 永久封禁", "封禁 1")
	click(t, tt, "web-01")
	if a.page != "s1" {
		t.Errorf("page %q after clicking the card", a.page)
	}
}

func TestDeleteServer(t *testing.T) {
	a, tt, _ := connected(t, newFakeF2B(sshdJail()))
	click(t, tt, "更多操作")
	if err := tt.ChooseMenuItem("删除服务器…"); err != nil {
		t.Fatalf("%v: menu %q", err, tt.Menu())
	}
	tt.Frame()
	click(t, tt, "删除服务器")
	if len(a.inv.List()) != 0 || a.page != pageOverview {
		t.Errorf("servers %+v, page %q", a.inv.List(), a.page)
	}
}

func TestEditServerKeepsSavedPassword(t *testing.T) {
	a, tt, d := connected(t, newFakeF2B(sshdJail()))
	click(t, tt, "更多操作")
	if err := tt.ChooseMenuItem("编辑服务器…"); err != nil {
		t.Fatalf("%v: menu %q", err, tt.Menu())
	}
	tt.Frame()
	if !tt.HasText("编辑服务器") || !tt.HasText("保存并重新连接") {
		t.Fatalf("no edit dialog: %q", tt.Texts())
	}
	click(t, tt, "服务器名称")
	tt.Key(ui.Cmd, ui.KeyA)
	tt.Type("web-primary")
	click(t, tt, "保存并重新连接")
	srv, _ := a.inv.Get("s1")
	sec, _ := a.vault.Get("s1")
	if srv.Name != "web-primary" || srv.User != "ops" || sec.Password != "pw" {
		t.Errorf("server %+v, secrets %+v", srv, sec)
	}
	// It connected again, with the password kept.
	if n := len(d.dialed); n != 2 || d.dialed[1].Password != "pw" {
		t.Errorf("dialed %+v", d.dialed)
	}
}

// deferred runs the app's background work only when flushed, so that tests
// see the frames in between, as the app does while SSH answers.
type deferred struct{ work []func() func() }

func (d *deferred) async(w func() func()) { d.work = append(d.work, w) }

func (d *deferred) flush() {
	for len(d.work) > 0 {
		w := d.work[0]
		d.work = d.work[1:]
		w()()
	}
}

func deferredApp(t *testing.T, f *fakeF2B) (*App, *ui.Tester, *deferred) {
	t.Helper()
	inv, err := store.Open(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	d := newFakeDialer(t)
	q := &deferred{}
	a := New(Options{Inventory: inv, Vault: &store.MemoryVault{}, Dialer: d, Async: q.async, Now: func() time.Time { return testNow }})
	inv.Put(store.Server{ID: "s1", Name: "web-01", Host: "203.0.113.10", Port: 22, User: "ops", Auth: sshx.AuthPassword})
	d.trusted["203.0.113.10:22"] = true
	d.servers["203.0.113.10"] = f
	a.servers()
	a.connect(a.views["s1"])
	q.flush()
	return a, ui.NewTester(a.View, 1280, 820), q
}

// The overview draws servers while they connect again, which once read
// the connection of a server between two.
func TestOverviewWhileReconnecting(t *testing.T) {
	a, tt, q := deferredApp(t, newFakeF2B(sshdJail()))
	sv := a.views["s1"]
	sv.conn.Close() // as the keepalive does
	tt.Frame()
	if sv.state != stateFailed || !tt.HasText("连接失败") {
		t.Fatalf("a dead connection shows as %v: %q", sv.state, tt.Texts())
	}
	tt.Key(ui.Cmd, ui.KeyR) // on the overview: connect to every server
	if sv.state != stateConnecting {
		t.Fatalf("state %v after refreshing", sv.state)
	}
	tt.Frame()
	expect(t, tt, "连接中…")
	q.flush()
	tt.Frame()
	if sv.state != stateConnected || !tt.HasText("fail2ban 运行中") {
		t.Errorf("after connecting: %v %q", sv.state, tt.Texts())
	}
}

// A refresh asked for while one runs is the same, an unbanning waits for
// it, and one of a connection dropped meanwhile leaves it alone.
func TestRefreshWhileReading(t *testing.T) {
	f := newFakeF2B(sshdJail("203.0.113.5"))
	a, _, q := deferredApp(t, f)
	sv := a.views["s1"]
	a.refresh(sv)
	a.refresh(sv)
	if sv.busy != "刷新" || len(q.work) != 1 {
		t.Fatalf("busy %q, work %d", sv.busy, len(q.work))
	}
	a.requestUnban(sv, []banRow{{Ban: sv.f2b.Jails[0].Bans[0], Jail: "sshd"}})
	confirm := a.alerts[0].actions[1]
	a.alerts = nil
	confirm()
	if len(sv.queued) != 1 {
		t.Fatalf("queued %d", len(sv.queued))
	}
	q.flush()
	if sv.busy != "" || f.reads != 3 || len(f.unbans) != 1 || sv.f2b.Banned() != 0 {
		t.Errorf("busy %q, reads %d, unbans %q, banned %d", sv.busy, f.reads, f.unbans, sv.f2b.Banned())
	}

	a.refresh(sv)
	a.disconnect(sv)
	q.flush()
	if sv.state != stateIdle || sv.f2b != nil || sv.busy != "" {
		t.Errorf("a reading of a dropped connection changed it: %v %+v %q", sv.state, sv.f2b, sv.busy)
	}
}

func TestUnbanFromBansTab(t *testing.T) {
	f := newFakeF2B(sshdJail("203.0.113.5", "198.51.100.23"), recidiveJail("192.0.2.77"))
	a, tt, _ := connected(t, f)
	click(t, tt, "封禁 IP (3)")
	tt.Frame()
	click(t, tt, "198.51.100.23")
	if err := tt.ClickWith(ui.Cmd, "203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	click(t, tt, "解封 2 项")
	expect(t, tt, "解封 2 项？")
	found := false
	for _, s := range tt.Texts() {
		found = found || strings.Contains(s, "将执行：sudo fail2ban-client set sshd unbanip 198.51.100.23 203.0.113.5")
	}
	if !found || tt.HasText("在所有 jail 中解封") {
		t.Errorf("question: %q", tt.Texts())
	}
	click(t, tt, "解封")
	tt.Frame()
	if !slices.Equal(f.unbans, []string{"sshd 198.51.100.23", "sshd 203.0.113.5"}) {
		t.Errorf("unbans %q", f.unbans)
	}
	expect(t, tt, "封禁 IP (1)", "192.0.2.77", "已在 web-01 上解封 2 个 IP")
	if tt.HasText("203.0.113.5") || a.views["s1"].banChosen.Len() != 0 {
		t.Errorf("after unbanning: %q, chosen %d", tt.Texts(), a.views["s1"].banChosen.Len())
	}
}

// An address another jail bans as well stays banned unless lifted there
// too, which the question offers.
func TestUnbanInEveryJail(t *testing.T) {
	f := newFakeF2B(sshdJail("203.0.113.5"), recidiveJail("203.0.113.5"))
	_, tt, _ := connected(t, f)
	click(t, tt, "解封 203.0.113.5") // in the detail of sshd
	expect(t, tt, "解封 203.0.113.5？", "仅解封所选", "在所有 jail 中解封")
	click(t, tt, "在所有 jail 中解封")
	if !slices.Equal(f.unbans, []string{"sshd 203.0.113.5", "recidive 203.0.113.5"}) {
		t.Errorf("unbans %q", f.unbans)
	}
	tt.Frame()
	expect(t, tt, "封禁 IP (0)")

	f.jails[0].bans = []string{"203.0.113.9"}
	f.jails[1].bans = []string{"203.0.113.9"}
	f.unbans = nil
	click(t, tt, "刷新")
	tt.Frame()
	click(t, tt, "解封 203.0.113.9")
	click(t, tt, "仅解封所选")
	if !slices.Equal(f.unbans, []string{"sshd 203.0.113.9"}) {
		t.Errorf("unbans %q", f.unbans)
	}
}

// clockApp returns an app showing a server connected to f, with a clock the
// test moves, refreshing every minute, and the settings it saves.
func clockApp(t *testing.T, f *fakeF2B) (*App, *ui.Tester, *time.Time, *[]store.Settings) {
	t.Helper()
	inv, err := store.Open(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	d := newFakeDialer(t)
	now := testNow
	var saved []store.Settings
	a := New(Options{
		Inventory: inv, Vault: &store.MemoryVault{}, Dialer: d,
		Now:          func() time.Time { return now },
		Settings:     store.Settings{RefreshSeconds: 60},
		SaveSettings: func(s store.Settings) error { saved = append(saved, s); return nil },
	})
	inv.Put(store.Server{ID: "s1", Name: "web-01", Host: "203.0.113.10", Port: 22, User: "ops", Auth: sshx.AuthPassword})
	inv.Put(store.Server{ID: "s2", Name: "web-02", Host: "203.0.113.11", Port: 22, User: "ops", Auth: sshx.AuthPassword})
	d.trusted["203.0.113.10:22"] = true
	d.trusted["203.0.113.11:22"] = true
	d.servers["203.0.113.10"] = f
	a.page = "s1"
	a.servers()
	a.connect(a.views["s1"])
	return a, ui.NewTester(a.View, 1280, 820), &now, &saved
}

func TestAutoRefresh(t *testing.T) {
	f := newFakeF2B(sshdJail("203.0.113.5"))
	a, tt, now, saved := clockApp(t, f)
	sv := a.views["s1"]
	if f.reads != 1 || !tt.HasText("每 1 分钟自动刷新") {
		t.Fatalf("reads %d: %q", f.reads, tt.Texts())
	}
	*now = now.Add(59 * time.Second)
	tt.Frame()
	if f.reads != 1 {
		t.Errorf("read before it was due: %d", f.reads)
	}
	f.jails[0].bans = append(f.jails[0].bans, "203.0.113.6")
	*now = now.Add(time.Second)
	tt.Frame()
	tt.Frame()
	if f.reads != 2 || !tt.HasText("封禁 IP (2)") {
		t.Errorf("reads %d: %q", f.reads, tt.Texts())
	}
	// A server not connected stays so.
	if a.views["s2"].state != stateIdle {
		t.Errorf("web-02 is %v", a.views["s2"].state)
	}

	// An automatic reading that fails tells on the page, not in a toast.
	f.fail = errors.New("timeout")
	*now = now.Add(time.Minute)
	tt.Frame()
	tt.Frame()
	if f.reads != 2 || sv.readErr == "" || !tt.HasText("刷新失败") || tt.HasText("web-01：读取 fail2ban 失败") {
		t.Errorf("reads %d, error %q: %q", f.reads, sv.readErr, tt.Texts())
	}
	f.fail = nil
	*now = now.Add(time.Minute)
	tt.Frame()
	tt.Frame()
	if f.reads != 3 || sv.readErr != "" || tt.HasText("刷新失败") {
		t.Errorf("reads %d, error %q: %q", f.reads, sv.readErr, tt.Texts())
	}

	// Turned off, it reads no more, and the setting is saved.
	a.setRefresh(0)
	*now = now.Add(time.Hour)
	tt.Frame()
	if f.reads != 3 || len(*saved) != 1 || (*saved)[0].RefreshSeconds != 0 || !tt.HasText("不自动刷新") {
		t.Errorf("reads %d, saved %+v: %q", f.reads, *saved, tt.Texts())
	}
}

func TestRefreshSelect(t *testing.T) {
	_, tt, _, saved := clockApp(t, newFakeF2B(sshdJail()))
	click(t, tt, "自动刷新")
	tt.Frame()
	click(t, tt, "每 5 分钟自动刷新")
	tt.Frame()
	if len(*saved) != 1 || (*saved)[0].RefreshSeconds != 300 || !tt.HasText("每 5 分钟自动刷新") {
		t.Errorf("saved %+v: %q", *saved, tt.Texts())
	}
}

// Questions wait for those asked before: two servers met for the first
// time each ask to trust their key.
func TestQuestionsQueue(t *testing.T) {
	a, d, inv, vault := newTestApp(t)
	for i, host := range []string{"203.0.113.1", "203.0.113.2"} {
		id := fmt.Sprint("s", i)
		inv.Put(store.Server{ID: id, Name: host, Host: host, Port: 22, User: "root", Auth: sshx.AuthPassword})
		vault.Set(id, store.Secrets{Password: "pw"})
	}
	tt := ui.NewTester(a.View, 1280, 820)
	a.refreshAll()
	tt.Frame()
	if len(a.alerts) != 2 || !tt.HasText("首次连接 203.0.113.1") {
		t.Fatalf("alerts %d: %q", len(a.alerts), tt.Texts())
	}
	click(t, tt, "信任并连接")
	tt.Frame()
	if !tt.HasText("首次连接 203.0.113.2") {
		t.Fatalf("second question: %q", tt.Texts())
	}
	click(t, tt, "信任并连接")
	if !d.trusted["203.0.113.1:22"] || !d.trusted["203.0.113.2:22"] || a.views["s0"].state != stateConnected || a.views["s1"].state != stateConnected {
		t.Errorf("trusted %v", d.trusted)
	}
}

func TestDurationLabel(t *testing.T) {
	for d, want := range map[time.Duration]string{
		-time.Second:                    "永久",
		0:                               "0 秒",
		45 * time.Second:                "45 秒",
		90 * time.Second:                "1 分钟 30 秒",
		10 * time.Minute:                "10 分钟",
		time.Hour:                       "1 小时",
		36 * time.Hour:                  "1 天 12 小时",
		24*time.Hour + 5*time.Minute:    "1 天",
		7 * 24 * time.Hour:              "1 周",
		10 * 24 * time.Hour:             "10 天",
		5*time.Hour + 30*time.Minute:    "5 小时 30 分钟",
		2*time.Hour + 3*time.Second:     "2 小时",
		59*time.Minute + 59*time.Second: "59 分钟 59 秒",
	} {
		if got := durationLabel(d); got != want {
			t.Errorf("durationLabel(%v) = %q, want %q", d, got, want)
		}
	}
	j := fail2ban.Jail{BanTime: time.Hour, BanIncrement: true, BanMaxTime: 7 * 24 * time.Hour}
	if got := banDurationSentence(j); got != "1 小时，再次被封时递增，最长 1 周" {
		t.Errorf("banDurationSentence %q", got)
	}
}

// snapshotEvents is a log of two weeks of bans, for the snapshots.
func snapshotEvents() [][]string {
	ips := []string{"203.0.113.5", "198.51.100.23", "192.0.2.140", "45.33.12.7", "185.220.101.4", "103.152.18.66",
		"2001:db8::42", "61.177.172.13", "218.92.0.112", "203.0.113.77", "141.98.11.31"}
	start, _ := time.Parse(time.DateTime, "2026-10-05 03:12:40")
	var out [][]string
	for i := range 60 {
		ip, jail := ips[i*7%len(ips)], "sshd"
		if i%5 == 3 {
			jail = "nginx-http-auth"
		}
		at := start.Add(time.Duration(i)*5*time.Hour + time.Duration(i*i%37)*time.Minute)
		out = append(out, []string{at.Format(time.DateTime), jail, "Ban", ip}, []string{at.Add(time.Hour).Format(time.DateTime), jail, "Unban", ip})
	}
	return out
}

// TestSnapshots draws the main pages into PNGs of the directory
// RULELENS_SNAPSHOTS names, to look at.
func TestSnapshots(t *testing.T) {
	dir := os.Getenv("RULELENS_SNAPSHOTS")
	if dir == "" {
		t.Skip("RULELENS_SNAPSHOTS is not set")
	}
	os.MkdirAll(dir, 0o755)
	nginx := fakeJail{
		name: "nginx-http-auth", port: "http,https", protocol: "tcp", action: "nftables",
		maxRetry: 5, findTime: 600, banTime: 600, total: 7, bans: []string{"192.0.2.140"},
		logPath:   "/var/log/nginx/error.log",
		failRegex: []string{`^ \[error\] \d+#\d+: \*\d+ user "(?:[^"]+|.*?)":? (?:password mismatch|was not found in "[^\"]*"), client: <HOST>, server: \S*, request: "\S+ \S+ HTTP/\d+\.\d+", host: "\S+"(?:, referrer: "\S+")?\s*$`},
	}
	f := newFakeF2B(sshdJail("203.0.113.5", "198.51.100.23", "203.0.113.77", "2001:db8::42"), nginx, recidiveJail("192.0.2.9", "203.0.113.5"))
	f.firewall = `# nft list table inet f2b-table
table inet f2b-table {
	set addr-set-sshd {
		type ipv4_addr
		elements = { 198.51.100.23, 203.0.113.5, 203.0.113.77 }
	}

	chain f2b-chain {
		type filter hook input priority filter - 1; policy accept;
		tcp dport 22 ip saddr @addr-set-sshd reject with icmp port-unreachable
	}
}`
	a, tt, d := connected(t, f)
	a.settings.RefreshSeconds = 60
	a.inv.Put(store.Server{ID: "s2", Name: "db-01", Host: "10.0.0.20", Port: 22, User: "ubuntu", Auth: sshx.AuthKey, KeyPath: "~/.ssh/id_ed25519", Group: "生产"})
	a.inv.Put(store.Server{ID: "s3", Name: "staging", Host: "192.0.2.30", Port: 2222, User: "root", Auth: sshx.AuthPassword, Group: "测试"})
	a.inv.Put(store.Server{ID: "s4", Name: "build", Host: "192.0.2.31", Port: 22, User: "root", Auth: sshx.AuthPassword, Group: "测试"})
	d.trusted["10.0.0.20:22"] = true
	d.trusted["192.0.2.31:22"] = true
	d.servers["10.0.0.20"] = newFakeF2B(sshdJail())
	d.servers["192.0.2.31"] = &fakeF2B{down: true}
	a.servers()
	a.connect(a.views["s2"])
	a.connect(a.views["s4"])
	a.views["s3"].state, a.views["s3"].err = stateFailed, "认证失败：用户名、密码或密钥不正确"

	save := func(name string) {
		tt.Frame()
		tt.Frame()
		f, err := os.Create(filepath.Join(dir, name+".png"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		png.Encode(f, tt.Image())
	}
	tt.SetScale(2)
	save("server")
	a.page = pageOverview
	save("overview")
	a.page = "s1"
	a.views["s1"].tab = 1
	sv := a.views["s1"]
	sv.banChosen.Add("sshd 203.0.113.5")
	sv.banChosen.Add("sshd 198.51.100.23")
	save("bans")
	a.requestUnban(sv, []banRow{{Ban: sv.f2b.Jails[0].Bans[0], Jail: "sshd"}, {Ban: sv.f2b.Jails[0].Bans[1], Jail: "sshd"}})
	save("unban")
	a.alerts = nil
	sv.banChosen.Clear()
	a.views["s1"].tab = tabFirewall
	save("firewall")
	f.events = snapshotEvents()
	sv.tab = tabHistory
	save("history")
	sv.histMode = historyByBan
	save("history-bans")
	sv.histMode = historyByIP
	a.views["s1"].tab = 0
	a.views["s1"].jail = "recidive"
	tt.SetDark(true)
	save("server-dark")
	tt.SetDark(false)
	a.page = "s2"
	a.views["s2"].tab = 1
	save("bans-empty")
	a.page = "s4"
	save("not-running")
	a.page = "s1"
	a.NewServer()
	save("add-server")
	a.serverForm.open = false

	// Rules: changed, stopped, and the dialogs.
	sv.tab, sv.jail = 0, "sshd"
	a.editRule(sv, "sshd")
	a.ruleForm.maxRetry, a.ruleForm.banTime = "5", "1d"
	save("rule-edit")
	a.saveRule()
	f.presets = []string{"apache-auth", "dovecot", "postfix"}
	a.requestStopRule(sv, "nginx-http-auth")
	a.alerts[0].actions[1]()
	a.alerts = nil
	sv.jail = "sshd"
	save("rules-changed")
	sv.jail = "nginx-http-auth"
	save("rules-stopped")
	a.newRule(sv)
	a.ruleForm.name, a.ruleForm.filter, a.ruleForm.logpath = "myapp", "sshd", "/var/log/myapp.log"
	a.ruleForm.port, a.ruleForm.findTime, a.ruleForm.maxRetry, a.ruleForm.banTime = "8022", "5m", "4", "2h"
	save("rule-new")
	tt.SetSize(980, 620)
	save("rule-new-small")
}
