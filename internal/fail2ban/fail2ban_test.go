package fail2ban

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rulelens/rulelens/internal/remote"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func jail(t *testing.T, s *Status, name string) Jail {
	t.Helper()
	i := slices.IndexFunc(s.Jails, func(j Jail) bool { return j.Name == name })
	if i < 0 {
		t.Fatalf("no jail %q among %+v", name, s.Jails)
	}
	return s.Jails[i]
}

// The fixtures are what the script printed on Ubuntu 24.04 (fail2ban
// 1.0.2, nftables) and 22.04 (0.11.2, iptables), at 2026-10-19 02:02:12.
var read = time.Date(2026, 10, 19, 10, 2, 12, 0, time.Local)

func TestParse102(t *testing.T) {
	s := parse(fixture(t, "fail2ban-1.0.2.txt"), read)
	if !s.Installed || !s.Running || s.Problem != "" || s.Version != "1.0.2" || len(s.Jails) != 2 {
		t.Fatalf("status %+v", s)
	}
	if s.Banned() != 3 || s.TotalBanned() != 3 {
		t.Errorf("banned %d, total %d", s.Banned(), s.TotalBanned())
	}
	j := jail(t, s, "sshd")
	if j.MaxRetry != 3 || j.FindTime != 10*time.Minute || j.BanTime != time.Hour || j.Permanent() || j.BanIncrement {
		t.Errorf("sshd %+v", j)
	}
	if !slices.Equal(j.IgnoreIP, []string{"127.0.0.0/8", "10.0.0.0/8", "::1"}) || !slices.Equal(j.LogPaths, []string{"/var/log/auth.log"}) {
		t.Errorf("ignoreip %q, logpaths %q", j.IgnoreIP, j.LogPaths)
	}
	if len(j.Actions) != 1 || j.Actions[0] != (Action{Name: "nftables", Port: "ssh,2222", Protocol: "tcp"}) ||
		!slices.Equal(j.Ports(), []string{"ssh,2222"}) || !slices.Equal(j.Protocols(), []string{"tcp"}) {
		t.Errorf("actions %+v", j.Actions)
	}
	if j.CurrentlyBanned != 2 || j.TotalBanned != 2 || len(j.Bans) != 2 || len(j.FailRegex) < 10 {
		t.Errorf("counts %+v", j)
	}
	b := j.Bans[0]
	// Banned at 01:55:26 for an hour, read at 02:02:12 server time.
	if b.IP != "203.0.113.5" || b.Permanent || !b.Start.Equal(read.Add(-6*time.Minute-46*time.Second)) || !b.End.Equal(b.Start.Add(time.Hour)) {
		t.Errorf("ban %+v", b)
	}
	if got := Readable(j.FailRegex[0]); !strings.Contains(got, " from <HOST>( via ") || strings.Contains(got, "ip4") {
		t.Errorf("readable failregex %q", got)
	}
	r := jail(t, s, "recidive")
	if !slices.Equal(r.Ports(), []string{""}) || r.BanTime != 7*24*time.Hour {
		t.Errorf("recidive %+v", r)
	}
	if !strings.Contains(s.Firewall, "table inet f2b-table") || !strings.Contains(s.Firewall, "203.0.113.5") {
		t.Errorf("firewall %q", s.Firewall)
	}
}

func TestParse0112(t *testing.T) {
	s := parse(fixture(t, "fail2ban-0.11.2.txt"), read)
	if !s.Running || s.Version != "0.11.2" || len(s.Jails) != 2 {
		t.Fatalf("status %+v", s)
	}
	r := jail(t, s, "recidive")
	if !r.Permanent() || len(r.Bans) != 1 || !r.Bans[0].Permanent || !r.Bans[0].End.IsZero() || r.Bans[0].Start.IsZero() {
		t.Errorf("recidive %+v", r)
	}
	if r.Actions[0].Name != "iptables-allports" || !slices.Equal(r.Ports(), []string{""}) {
		t.Errorf("actions %+v", r.Actions)
	}
	j := jail(t, s, "sshd")
	if j.MaxRetry != 5 || j.BanTime != 10*time.Minute || !slices.Equal(j.Ports(), []string{"ssh"}) || j.Bans[0].IP != "203.0.113.9" {
		t.Errorf("sshd %+v", j)
	}
	if !strings.Contains(s.Firewall, "-A f2b-sshd -s 203.0.113.9/32 -j REJECT") {
		t.Errorf("firewall %q", s.Firewall)
	}
}

func TestParseProblems(t *testing.T) {
	if s := parse("@@missing\n", read); s.Installed || s.Running {
		t.Errorf("missing: %+v", s)
	}
	s := parse("@@json\n"+`{"jails": [], "down": true, "error": "FileNotFoundError: [Errno 2] No such file or directory"}`+"\n@@firewall\n", read)
	if !s.Installed || s.Running || !strings.Contains(s.Problem, "未运行") || !strings.Contains(s.Problem, "No such file") {
		t.Errorf("down: %+v", s)
	}
	s = parse("@@json\nsh: 1: python3: not found\n@@firewall\n", read)
	if s.Running || !strings.Contains(s.Problem, "python3: not found") {
		t.Errorf("no python: %+v", s)
	}
	// An old fail2ban, without banip --with-time: the bans come from the
	// status, untimed.
	s = parse("@@json\n"+`{"now": "x", "jails": [{"name": "sshd", "bantime": -1, "status": {"Currently banned": 1, "Banned IP list": ["192.0.2.9"], "Journal matches": [["_SYSTEMD_UNIT=sshd.service", "+", "_COMM=sshd"]]}, "journalmatch": null, "bans": null}]}`+"\n", read)
	j := s.Jails[0]
	if !s.Running || len(j.Bans) != 1 || j.Bans[0].IP != "192.0.2.9" || !j.Bans[0].Permanent || !j.Bans[0].Start.IsZero() ||
		!slices.Equal(j.JournalMatch, []string{"_SYSTEMD_UNIT=sshd.service + _COMM=sshd"}) {
		t.Errorf("old: %+v", j)
	}
}

func TestReadable(t *testing.T) {
	for in, want := range map[string]string{
		`^Failed password for .* from ` + reHost + ` port \d+`: `^Failed password for .* from <HOST> port \d+`,
		`client ` + reAddr + `:\d+`:                            `client <ADDR>:\d+`,
		`^` + reIP4 + ` - `:                                    `^<IP4> - `,
		`net ` + reSubnet:                                      `net <SUBNET>`,
		`nothing to replace`:                                   `nothing to replace`,
	} {
		if got := Readable(in); got != want {
			t.Errorf("Readable(%q) = %q, want %q", in, got, want)
		}
	}
}

type fakeExec struct{ cmds []string }

func (f *fakeExec) Run(ctx context.Context, cmd string) (remote.Result, error) {
	f.cmds = append(f.cmds, cmd)
	return remote.Result{Stdout: "@@missing\n"}, nil
}

func (f *fakeExec) RunPrivileged(ctx context.Context, cmd string) (remote.Result, error) {
	f.cmds = append(f.cmds, "sudo "+cmd)
	return remote.Result{Stdout: "@@missing\n"}, nil
}

func TestReadRunsAsRoot(t *testing.T) {
	x := &fakeExec{}
	s, err := Read(context.Background(), x, read)
	if err != nil || s.Installed {
		t.Fatalf("%+v, %v", s, err)
	}
	if len(x.cmds) != 1 || !strings.HasPrefix(x.cmds[0], "sudo "+remote.Prelude) || !strings.Contains(x.cmds[0], "fail2ban-client") {
		t.Errorf("commands %q", x.cmds)
	}
}

func TestUnbanCommand(t *testing.T) {
	cmd, err := UnbanCommand([]Unbanning{{Jail: "sshd", IPs: []string{"203.0.113.5", "2001:db8::42"}}, {Jail: "nginx-http-auth"}, {Jail: "recidive", IPs: []string{"203.0.113.5"}}})
	if want := "fail2ban-client set sshd unbanip 203.0.113.5 2001:db8::42 && fail2ban-client set recidive unbanip 203.0.113.5"; err != nil || cmd != want {
		t.Errorf("got %q, %v\nwant %q", cmd, err, want)
	}
	if _, err := UnbanCommand([]Unbanning{{Jail: "sshd", IPs: []string{"--all"}}}); err == nil {
		t.Error("an option passed for an address")
	}
	cmd, _ = UnbanCommand([]Unbanning{{Jail: "my jail", IPs: []string{"1.2.3.4; reboot"}}})
	if cmd != "fail2ban-client set 'my jail' unbanip '1.2.3.4; reboot'" {
		t.Errorf("not quoted: %q", cmd)
	}
	x := &fakeExec{}
	if err := Unban(context.Background(), x, []Unbanning{{Jail: "sshd", IPs: []string{"203.0.113.5"}}}); err != nil || len(x.cmds) != 1 ||
		x.cmds[0] != "sudo "+remote.Prelude+"fail2ban-client set sshd unbanip 203.0.113.5" {
		t.Errorf("commands %q, %v", x.cmds, err)
	}
}
