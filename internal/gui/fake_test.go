package gui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rulelens/rulelens/internal/fail2ban"
	"github.com/rulelens/rulelens/internal/remote"
	"github.com/rulelens/rulelens/internal/session"
	"github.com/rulelens/rulelens/internal/sshx"
	"github.com/rulelens/rulelens/internal/store"
)

// serverNow is the time on the fake servers, when the tests' clock says
// testNow.
const serverNow = "2026-10-19 02:00:00"

var testNow = time.Date(2026, 10, 19, 10, 0, 0, 0, time.Local)

// fakeJail is a jail of a fake server. Its bans began 10 minutes before
// serverNow.
type fakeJail struct {
	name               string
	port, protocol     string
	action             string
	maxRetry           int
	findTime, banTime  int
	failed, total      int
	bans               []string
	logPath            string
	failRegex, ignored []string
	// ignoreIP is the addresses the jail ignores, as RuleLens set them.
	ignoreIP []string
}

// fakeF2B is fail2ban on a fake server, which answers its reading as the
// script would.
type fakeF2B struct {
	mu       sync.Mutex
	missing  bool
	down     bool
	version  string
	jails    []fakeJail
	firewall string
	fail     error // what the reading fails with
	reads    int
	// unbans are the bans lifted, as "sshd 203.0.113.5".
	unbans []string

	// filters are those of filter.d, presets the jails configured but not
	// enabled, and files those of RuleLens in jail.d, by name.
	filters []string
	presets []string
	files   map[string]string
	// base are the jails as configured without the files of RuleLens.
	base []fakeJail
	// testErr is what fail2ban-client -t says of the configuration,
	// failing it; changes counts the changes taken.
	testErr string
	changes int

	// events are the lines of its log, as the history's script prints
	// them; historySource is where it reads them, "file" when empty, and
	// historyFail the error it exits with. historyReads counts its runs.
	events        [][]string
	historySource string
	historyFail   string
	historyReads  int
}

// historyOutput is what the history's script prints.
func (f *fakeF2B) historyOutput() remote.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.historyReads++
	if f.historyFail != "" {
		return remote.Result{ExitCode: 1, Stderr: f.historyFail}
	}
	out := map[string]any{"now": serverNow, "target": "/var/log/fail2ban.log", "purgeage": 86400, "count": len(f.events), "problems": []string{}}
	switch f.historySource {
	case "", "file":
		out["source"], out["files"], out["events"] = "file", []string{"/var/log/fail2ban.log.1", "/var/log/fail2ban.log"}, f.events
	case "none":
		out["target"], out["events"] = "SYSLOG", []string{}
		out["problems"] = []string{"journalctl: [Errno 2] No such file or directory: 'journalctl'"}
	}
	b, _ := json.Marshal(out)
	return remote.Result{Stdout: "@@json\n" + string(b) + "\n"}
}

// change makes a change as its script does: it writes or removes the file,
// checks the configuration, and reloads.
func (f *fakeF2B) change(cmd string) remote.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := regexp.MustCompile(`f=(\S+)\n`).FindStringSubmatch(cmd)[1]
	name := filepath.Base(path)
	if f.testErr != "" {
		return remote.Result{ExitCode: 3, Stderr: f.testErr}
	}
	if f.base == nil {
		f.base = slices.Clone(f.jails)
	}
	if f.files == nil {
		f.files = map[string]string{}
	}
	if i := strings.Index(cmd, "printf '%s' "); i >= 0 {
		f.files[name] = shellWord(cmd[i+len("printf '%s' "):])
	} else {
		delete(f.files, name)
	}
	f.changes++
	f.reload()
	return remote.Result{}
}

// reload runs the jails as the configuration and the files say, keeping
// the bans of those that ran.
func (f *fakeF2B) reload() {
	running := map[string]fakeJail{}
	for _, j := range f.jails {
		running[j.name] = j
	}
	var names []string
	base := map[string]fakeJail{}
	for _, j := range f.base {
		names = append(names, j.name)
		base[j.name] = j
	}
	var created []string
	for file := range f.files {
		name := strings.TrimSuffix(strings.TrimPrefix(file, "zz-rulelens-"), ".local")
		if _, ok := base[name]; !ok {
			created = append(created, name)
		}
	}
	slices.Sort(created)
	var jails []fakeJail
	for _, name := range append(names, created...) {
		j, enabled := base[name]
		var o *fail2ban.Override
		if text, ok := f.files["zz-rulelens-"+name+".local"]; ok {
			o = fail2ban.ParseOverride(name, text)
		}
		if o.Has("enabled") {
			enabled = o.Bool("enabled")
		}
		if !enabled {
			continue
		}
		if _, ok := base[name]; !ok {
			j = fakeJail{name: name, port: "0:65535", protocol: "tcp", action: "nftables", maxRetry: 5, findTime: 600, banTime: 600, logPath: "/var/log/" + name + ".log"}
		}
		if prev, ok := running[name]; ok {
			j.bans, j.total, j.failed = prev.bans, prev.total, prev.failed
		}
		secs := func(key string, to *int) {
			if v, ok := o.Get(key); ok {
				d, _ := fail2ban.ParseTime(v)
				*to = int(d.Seconds())
				if v == "-1" {
					*to = -1
				}
			}
		}
		secs("findtime", &j.findTime)
		secs("bantime", &j.banTime)
		if v, ok := o.Get("maxretry"); ok {
			j.maxRetry, _ = strconv.Atoi(v)
		}
		if v, ok := o.Get("port"); ok {
			j.port = v
		}
		if v, ok := o.Get("logpath"); ok {
			j.logPath, _, _ = strings.Cut(v, "\n")
		}
		if v, ok := o.Get("ignoreip"); ok {
			j.ignoreIP = strings.Fields(v)
		}
		jails = append(jails, j)
	}
	f.jails = jails
}

// shellWord reads the word of a command line s starts with, quoted as
// remote.Quote quotes.
func shellWord(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			b.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case '\\':
			i++
			b.WriteByte(s[i])
		case ' ':
			return b.String()
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// unban lifts bans as `fail2ban-client set <jail> unbanip <ip>...` does.
func (f *fakeF2B) unban(cmd string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range strings.Split(strings.TrimPrefix(cmd, remote.Prelude), " && ") {
		w := strings.Fields(c)
		jail, ips := w[2], w[4:]
		for _, ip := range ips {
			f.unbans = append(f.unbans, jail+" "+ip)
		}
		for i := range f.jails {
			if f.jails[i].name == jail {
				f.jails[i].bans = slices.DeleteFunc(f.jails[i].bans, func(b string) bool { return slices.Contains(ips, b) })
			}
		}
	}
}

func sshdJail(bans ...string) fakeJail {
	return fakeJail{
		name: "sshd", port: "ssh", protocol: "tcp", action: "iptables-multiport",
		maxRetry: 3, findTime: 600, banTime: 3600, failed: 1, total: 12 + len(bans), bans: bans,
		logPath: "/var/log/auth.log",
		failRegex: []string{
			`^[aA]uthentication (?:failure|error|failed) for .* from ` + hostRE + `( via \S+)?\s*$`,
			`^Failed \S+ for (?P<cond_inv>invalid user )?(?P<user>\S+) from ` + hostRE + `(?: port \d+)?`,
		},
	}
}

const hostRE = `(?:\[?(?:(?:::f{4,6}:)?(?P<ip4>(?:\d{1,3}\.){3}\d{1,3})|(?P<ip6>(?:[0-9a-fA-F]{1,4}::?|::){1,7}(?:[0-9a-fA-F]{1,4}|(?<=:):)))\]?|(?P<dns>[\w\-.^_]*\w))`

func recidiveJail(bans ...string) fakeJail {
	return fakeJail{
		name: "recidive", port: "0:65535", protocol: "tcp", action: "iptables-allports",
		maxRetry: 5, findTime: 86400, banTime: -1, total: len(bans), bans: bans,
		logPath:   "/var/log/fail2ban.log",
		failRegex: []string{`^(?:\s*\S+)?\s+fail2ban\.actions\s+\[\d+\]: NOTICE\s+\[(?!recidive\])(?:.*)\]\s+Ban\s+<HOST>`},
	}
}

func newFakeF2B(jails ...fakeJail) *fakeF2B {
	return &fakeF2B{version: "1.0.2", jails: jails}
}

// output is what the reading script prints.
func (f *fakeF2B) output() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.missing {
		return "@@missing\n"
	}
	out := map[string]any{"now": serverNow, "jails": []any{}}
	if f.down {
		out["down"], out["error"] = true, "FileNotFoundError: [Errno 2] No such file or directory"
	} else {
		out["version"] = f.version
		var jails []any
		for _, j := range f.jails {
			var bans []string
			for _, ip := range j.bans {
				bans = append(bans, fmt.Sprintf("%s \t2026-10-19 01:50:00 + %d = %s", ip, j.banTime, banEnd(j.banTime)))
			}
			ignoreIP := j.ignoreIP
			if ignoreIP == nil {
				ignoreIP = []string{"127.0.0.1/8", "::1"}
			}
			jails = append(jails, map[string]any{
				"name": j.name,
				"status": map[string]any{
					"Currently failed": j.failed, "Total failed": j.failed * 4, "File list": []string{j.logPath},
					"Currently banned": len(j.bans), "Total banned": j.total, "Banned IP list": j.bans,
				},
				"maxretry": j.maxRetry, "findtime": j.findTime, "bantime": j.banTime,
				"bantime.increment": nil, "bantime.maxtime": nil,
				"ignoreip": ignoreIP, "logpath": []string{j.logPath}, "journalmatch": []string{},
				"failregex": j.failRegex, "ignoreregex": j.ignored,
				"actions": []any{map[string]any{"name": j.action, "port": j.port, "protocol": j.protocol}},
				"bans":    bans,
			})
		}
		out["jails"] = jails
		configured := map[string]string{}
		for _, j := range f.jails {
			configured[j.name] = "true"
		}
		for _, name := range f.presets {
			if configured[name] == "" {
				configured[name] = "false"
			}
		}
		for file := range f.files {
			if name := strings.TrimSuffix(strings.TrimPrefix(file, "zz-rulelens-"), ".local"); configured[name] == "" {
				configured[name] = "false"
			}
		}
		filters := f.filters
		if filters == nil {
			filters = []string{"nginx-http-auth", "recidive", "sshd"}
		}
		out["config"] = map[string]any{"read": true, "filters": filters, "jails": configured, "files": f.files}
	}
	b, _ := json.Marshal(out)
	return "@@json\n" + string(b) + "\n@@firewall\n" + f.firewall + "\n"
}

func banEnd(secs int) string {
	if secs < 0 {
		return "9999-12-31 23:59:59"
	}
	t, _ := time.Parse(time.DateTime, "2026-10-19 01:50:00")
	return t.Add(time.Duration(secs) * time.Second).Format(time.DateTime)
}

// fakeExec runs the commands of a fake server.
type fakeExec struct{ f2b *fakeF2B }

func (x fakeExec) Run(context.Context, string) (remote.Result, error) {
	return remote.Result{}, nil
}

func (x fakeExec) RunPrivileged(_ context.Context, cmd string) (remote.Result, error) {
	if !strings.Contains(cmd, "fail2ban-client") {
		return remote.Result{}, nil
	}
	if err := x.f2b.fail; err != nil {
		return remote.Result{}, err
	}
	if strings.Contains(cmd, " unbanip ") {
		x.f2b.unban(cmd)
		return remote.Result{Stdout: "1\n"}, nil
	}
	if strings.Contains(cmd, "fail2ban-client -t") {
		return x.f2b.change(cmd), nil
	}
	if strings.Contains(cmd, "logtarget") {
		return x.f2b.historyOutput(), nil
	}
	return remote.Result{Stdout: x.f2b.output()}, nil
}

// fakeConn is a connection to a fake server.
type fakeConn struct {
	info   session.Info
	f2b    *fakeF2B
	closed bool
}

func (c *fakeConn) Info() session.Info    { return c.info }
func (c *fakeConn) Exec() remote.Executor { return fakeExec{c.f2b} }
func (c *fakeConn) Log() []session.Entry {
	return []session.Entry{{Command: "fail2ban-client status", Output: "Status", Privileged: true}}
}
func (c *fakeConn) Alive() bool  { return !c.closed }
func (c *fakeConn) Close() error { c.closed = true; return nil }

// fakeDialer connects to fake servers by host, asking to trust them first.
type fakeDialer struct {
	key     ssh.PublicKey
	trusted map[string]bool
	servers map[string]*fakeF2B
	dialed  []store.Secrets
}

func newFakeDialer(t *testing.T) *fakeDialer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeDialer{key: signer.PublicKey(), trusted: map[string]bool{}, servers: map[string]*fakeF2B{}}
}

func (d *fakeDialer) Dial(_ context.Context, srv store.Server, sec store.Secrets) (session.Conn, error) {
	d.dialed = append(d.dialed, sec)
	hostport := fmt.Sprintf("%s:%d", srv.Host, srv.Port)
	if !d.trusted[hostport] {
		return nil, &sshx.UnknownHostError{Hostport: hostport, Key: d.key}
	}
	f := d.servers[srv.Host]
	if f == nil {
		f = newFakeF2B(sshdJail())
		d.servers[srv.Host] = f
	}
	return &fakeConn{
		info: session.Info{
			OS:       remote.OSInfo{ID: "ubuntu", PrettyName: "Ubuntu 24.04.1 LTS"},
			ClientIP: "198.51.100.7",
			ServerIP: srv.Host,
			SSHPort:  srv.Port,
		},
		f2b: f,
	}, nil
}

func (d *fakeDialer) Trust(hostport string, key ssh.PublicKey) error {
	d.trusted[hostport] = true
	return nil
}
