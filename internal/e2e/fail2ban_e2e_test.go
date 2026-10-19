// Package e2e tests RuleLens against a real Ubuntu server with fail2ban,
// over SSH. It runs only when RULELENS_E2E is set to the server's
// host:port, as the container of testdata/ubuntu-fail2ban gives it:
//
//	docker build -t rulelens-ubuntu testdata/ubuntu-fail2ban
//	docker run -d --cap-add NET_ADMIN -p 2222:22 --name rulelens-ubuntu rulelens-ubuntu
//	RULELENS_E2E=127.0.0.1:2222 go test ./internal/e2e -v
//
// The server must take the user "ops" with the password "rulelens", who
// may sudo, and run the jails sshd and recidive. The tests ban and unban
// addresses of 203.0.113.0/24 (TEST-NET-3) in the jail sshd.
package e2e

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rulelens/rulelens/internal/fail2ban"
	"github.com/rulelens/rulelens/internal/remote"
	"github.com/rulelens/rulelens/internal/sshx"
)

func dial(t *testing.T) *sshx.Client {
	addr := os.Getenv("RULELENS_E2E")
	if addr == "" {
		t.Skip("RULELENS_E2E is not set")
	}
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(p)
	hk := sshx.NewHostKeys(filepath.Join(t.TempDir(), "known_hosts"))
	cfg := sshx.Config{Host: host, Port: port, User: "ops", Auth: sshx.AuthPassword, Password: "rulelens", HostKeys: hk}
	ctx := context.Background()
	_, err = sshx.Dial(ctx, cfg)
	var unknown *sshx.UnknownHostError
	if !errors.As(err, &unknown) {
		t.Fatalf("first connection: %v, want an unknown host", err)
	}
	if err := hk.Trust(unknown.Hostport, unknown.Key); err != nil {
		t.Fatal(err)
	}
	c, err := sshx.Dial(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// f2b runs fail2ban-client on the server, as root.
func f2b(t *testing.T, c *sshx.Client, args ...string) string {
	t.Helper()
	res, err := remote.Check(context.Background(), c, true, remote.Prelude+remote.Join(append([]string{"fail2ban-client"}, args...)...))
	if err != nil {
		t.Fatalf("fail2ban-client %s: %v", strings.Join(args, " "), err)
	}
	return res.Stdout
}

// TestFail2ban reads fail2ban, as the login user through sudo, with an
// address banned.
func TestFail2ban(t *testing.T) {
	c := dial(t)
	// An address of its own each run: recidive bans one banned again and
	// again.
	ip := fmt.Sprintf("203.0.113.%d", 100+time.Now().UnixNano()%150)
	f2b(t, c, "set", "sshd", "banip", ip)
	t.Cleanup(func() { f2b(t, c, "set", "sshd", "unbanip", ip) })

	now := time.Now()
	s, err := fail2ban.Read(context.Background(), c, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fail2ban %s, %d jails, firewall:\n%s", s.Version, len(s.Jails), s.Firewall)
	if !s.Installed || !s.Running || s.Problem != "" || s.Version == "" {
		t.Fatalf("status %+v", s)
	}
	i := slices.IndexFunc(s.Jails, func(j fail2ban.Jail) bool { return j.Name == "sshd" })
	if i < 0 {
		t.Fatalf("no jail sshd: %+v", s.Jails)
	}
	j := s.Jails[i]
	if j.MaxRetry != 3 || j.FindTime != 10*time.Minute || j.BanTime != time.Hour || !slices.Equal(j.Ports(), []string{"ssh,2222"}) ||
		!slices.Contains(j.LogPaths, "/var/log/auth.log") || len(j.FailRegex) == 0 || !strings.Contains(fail2ban.Readable(j.FailRegex[0]), "<HOST>") {
		t.Errorf("jail %+v", j)
	}
	b := slices.IndexFunc(j.Bans, func(b fail2ban.Ban) bool { return b.IP == ip })
	if b < 0 || j.CurrentlyBanned < 1 {
		t.Fatalf("bans %+v", j.Bans)
	}
	// The ban began just now and ends in an hour, by this clock.
	ban := j.Bans[b]
	if d := now.Sub(ban.Start); d < -5*time.Second || d > time.Minute || ban.End.Sub(ban.Start) != time.Hour {
		t.Errorf("ban %+v, read at %v", ban, now)
	}
	if !strings.Contains(s.Firewall, ip) {
		t.Errorf("the firewall lacks the ban:\n%s", s.Firewall)
	}

	// Lifting the ban takes it out of fail2ban and of the firewall.
	if err := fail2ban.Unban(context.Background(), c, []fail2ban.Unbanning{{Jail: "sshd", IPs: []string{ip}}}); err != nil {
		t.Fatal(err)
	}
	s, err = fail2ban.Read(context.Background(), c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range s.Jails {
		for _, b := range j.Bans {
			if b.IP == ip {
				t.Errorf("still banned by %s", j.Name)
			}
		}
	}
	if strings.Contains(s.Firewall, ip) {
		t.Errorf("still in the firewall:\n%s", s.Firewall)
	}
}

// TestManage creates a jail, stops it, has fail2ban refuse a change, and
// changes sshd, as the login user through sudo, then undoes it all.
func TestManage(t *testing.T) {
	c := dial(t)
	ctx := context.Background()
	const jail = "rulelens-e2e"
	apply := func(ch fail2ban.Change) error {
		t.Helper()
		return fail2ban.Apply(ctx, c, ch)
	}
	read := func() *fail2ban.Status {
		t.Helper()
		s, err := fail2ban.Read(ctx, c, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Cleanup(func() {
		apply(fail2ban.Change{Jail: jail})
		apply(fail2ban.Change{Jail: "sshd"})
	})
	// A ban of another jail stays as fail2ban reloads.
	ip := fmt.Sprintf("203.0.113.%d", 100+time.Now().UnixNano()%150)
	f2b(t, c, "set", "sshd", "banip", ip)
	t.Cleanup(func() { f2b(t, c, "set", "sshd", "unbanip", ip) })
	banned := func(s *fail2ban.Status) bool {
		j, _ := s.Jail("sshd")
		return slices.ContainsFunc(j.Bans, func(b fail2ban.Ban) bool { return b.IP == ip })
	}

	s := read()
	if !s.Config.Read || !slices.Contains(s.Config.Filters, "sshd") || !s.Config.Jails["sshd"] || !slices.Contains(s.Presets(), "nginx-http-auth") {
		t.Fatalf("config %+v, presets %q", s.Config, s.Presets())
	}

	o := &fail2ban.Override{Jail: jail, Created: true}
	for _, kv := range [][2]string{{"enabled", "true"}, {"filter", "sshd"}, {"port", "8022"}, {"logpath", "/var/log/auth.log"}, {"backend", "auto"},
		{"maxretry", "4"}, {"findtime", "5m"}, {"bantime", "1h30m"}, {"ignoreip", "127.0.0.1/8 192.0.2.1"}} {
		o.Set(kv[0], kv[1])
	}
	if err := apply(fail2ban.Change{Jail: jail, Override: o}); err != nil {
		t.Fatal(err)
	}
	s = read()
	j, ok := s.Jail(jail)
	if !ok || j.MaxRetry != 4 || j.FindTime != 5*time.Minute || j.BanTime != 90*time.Minute || !slices.Equal(j.Ports(), []string{"8022"}) ||
		!slices.Contains(j.IgnoreIP, "192.0.2.1") || !slices.Contains(j.LogPaths, "/var/log/auth.log") {
		t.Errorf("jail %+v", j)
	}
	if got := s.Config.Overrides[jail]; !got.Equal(o) {
		t.Errorf("file %+v", got)
	}
	if !banned(s) {
		t.Error("the ban of sshd was lost")
	}

	// Stopped, it is listed so.
	o.Set("enabled", "false")
	if err := apply(fail2ban.Change{Jail: jail, Override: o}); err != nil {
		t.Fatal(err)
	}
	s = read()
	if _, ok := s.Jail(jail); ok || !slices.Contains(s.Stopped(), jail) {
		t.Errorf("running %v, stopped %q", ok, s.Stopped())
	}

	// A change fail2ban refuses leaves the file as it was.
	bad := o.Clone()
	bad.Set("enabled", "true")
	bad.Set("logpath", "/var/log/rulelens-missing.log")
	err := apply(fail2ban.Change{Jail: jail, Override: bad})
	var ce *fail2ban.ChangeError
	if !errors.As(err, &ce) || !ce.Checking || !strings.Contains(ce.Output, "找不到规则 "+jail+" 的日志文件") {
		t.Fatalf("%v", err)
	}
	s = read()
	if got := s.Config.Overrides[jail]; !got.Equal(o) || !slices.Contains(s.Stopped(), jail) {
		t.Errorf("file %+v, stopped %q", got, s.Stopped())
	}

	// A jail of the configuration takes the settings of RuleLens over its
	// own, until the file goes.
	so := &fail2ban.Override{Jail: "sshd"}
	so.Set("maxretry", "6")
	if err := apply(fail2ban.Change{Jail: "sshd", Override: so}); err != nil {
		t.Fatal(err)
	}
	s = read()
	if j, _ := s.Jail("sshd"); j.MaxRetry != 6 || j.FindTime != 10*time.Minute || !banned(s) {
		t.Errorf("sshd %+v", j)
	}
	if err := apply(fail2ban.Change{Jail: "sshd"}); err != nil {
		t.Fatal(err)
	}
	if err := apply(fail2ban.Change{Jail: jail}); err != nil {
		t.Fatal(err)
	}
	s = read()
	if j, _ := s.Jail("sshd"); j.MaxRetry != 3 || len(s.Config.Overrides) != 0 || len(s.Stopped()) != 0 || !banned(s) {
		t.Errorf("sshd %+v, files %v, stopped %q", j, s.Config.Overrides, s.Stopped())
	}
}
