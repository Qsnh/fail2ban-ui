package fail2ban

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rulelens/rulelens/internal/remote"
)

// probeHead starts the Python scripts that ask the fail2ban server, over
// its socket, as fail2ban-client does: q asks, failing as the server
// does, and opt asks, None when it fails. done prints out as one line of
// JSON, and ends. The scripts run with the Python of fail2ban-client, 2
// or 3, whose fail2ban package they use.
const probeHead = `import glob, json, os, sys, time
out = {}
def done():
    sys.stdout.write(json.dumps(out, default=str) + "\n")
    sys.exit(0)
try:
    from fail2ban.client.csocket import CSocket
except Exception as e:
    out["error"] = "import fail2ban: %s" % e
    done()
sock = "/var/run/fail2ban/fail2ban.sock"
try:
    from fail2ban.client.fail2banreader import Fail2banReader
    r = Fail2banReader()
    r.setBaseDir("/etc/fail2ban")
    r.read()
    sock = r.getEarlyOptions().get("socket") or sock
except Exception:
    pass
def q(*cmd):
    s = CSocket(sock)
    try:
        code, val = s.send(list(cmd))
    finally:
        try:
            s.close()
        except Exception:
            pass
    if code != 0:
        raise Exception(str(val))
    return val
def opt(*cmd):
    try:
        return q(*cmd)
    except Exception:
        return None
out["now"] = time.strftime("%Y-%m-%d %H:%M:%S")
`

// probe asks what fail2ban-client would print of each jail, reads the
// configuration of the jails, those not running too, and prints it all.
const probe = probeHead + `out["jails"] = []
try:
    st = dict(q("status"))
except Exception as e:
    out["down"] = isinstance(e, (IOError, OSError))
    out["error"] = "%s: %s" % (type(e).__name__, e)
    done()
out["version"] = opt("version")
for name in [n.strip() for n in str(st.get("Jail list") or "").split(",") if n.strip()]:
    j = {"name": name, "status": {}}
    try:
        for _, items in q("status", name):
            for k, v in items:
                j["status"][k] = v
    except Exception as e:
        j["error"] = str(e)
    for k in ("maxretry", "findtime", "bantime", "bantime.increment", "bantime.maxtime",
              "ignoreip", "logpath", "journalmatch", "failregex", "ignoreregex"):
        j[k] = opt("get", name, k)
    j["actions"] = [{"name": a, "port": opt("get", name, "action", a, "port"),
                     "protocol": opt("get", name, "action", a, "protocol")}
                    for a in opt("get", name, "actions") or []]
    j["bans"] = opt("get", name, "banip", "--with-time")
    out["jails"].append(j)
cfg = {"filters": [], "jails": {}, "files": {}}
out["config"] = cfg
try:
    cfg["filters"] = sorted(n[:-5] for n in os.listdir("/etc/fail2ban/filter.d") if n.endswith(".conf"))
    for p in sorted(glob.glob("/etc/fail2ban/jail.d/zz-rulelens-*.local")):
        f = open(p)
        try:
            cfg["files"][os.path.basename(p)] = f.read()
        finally:
            f.close()
    from fail2ban.client.jailsreader import JailsReader
    r = JailsReader()
    r.setBaseDir("/etc/fail2ban")
    if not r.read():
        raise Exception("no jail.conf")
    for sec in r.sections():
        if sec != "INCLUDES":
            try:
                cfg["jails"][sec] = r.get(sec, "enabled")
            except Exception:
                cfg["jails"][sec] = None
    cfg["read"] = True
except Exception as e:
    cfg["error"] = "%s: %s" % (type(e).__name__, e)
done()
`

// python runs a script with the Python of fail2ban-client, printing what
// it prints after "@@json", or "@@missing" without fail2ban.
func python(script string) string {
	return `f2b=$(command -v fail2ban-client) || { echo '@@missing'; exit 0; }
py=$(sed -n '1s/^#![[:space:]]*//p' "$f2b")
echo '@@json'
${py:-python3} -c ` + remote.Quote(script) + ` 2>&1
`
}

// script reads fail2ban, and what it put in the firewall, in sections.
var script = python(probe) + `echo '@@firewall'
{
  if command -v iptables >/dev/null 2>&1; then
    r=$(iptables -S 2>/dev/null | grep -E 'f2b-|fail2ban'); [ -n "$r" ] && printf '# iptables -S\n%s\n\n' "$r"
  fi
  if command -v ip6tables >/dev/null 2>&1; then
    r=$(ip6tables -S 2>/dev/null | grep -E 'f2b-|fail2ban'); [ -n "$r" ] && printf '# ip6tables -S\n%s\n\n' "$r"
  fi
  if command -v nft >/dev/null 2>&1; then
    nft list tables 2>/dev/null | while read -r _ family table; do
      case "$table" in *f2b*|*fail2ban*) echo "# nft list table $family $table"; nft list table "$family" "$table" 2>&1; echo;; esac
    done
  fi
  if command -v ipset >/dev/null 2>&1; then
    ipset list -n 2>/dev/null | grep -E 'f2b|fail2ban' | while read -r set; do echo "# ipset list $set"; ipset list "$set" 2>&1; echo; done
  fi
} | head -n 3000
exit 0`

// Read reads fail2ban on the server x runs commands on, as root. now is
// the time of the reading, by which the times of the bans are told.
func Read(ctx context.Context, x remote.Executor, now time.Time) (*Status, error) {
	res, err := remote.Check(ctx, x, true, remote.Prelude+script)
	if err != nil {
		return nil, err
	}
	return parse(res.Stdout, now), nil
}

// report is what the probe prints.
type report struct {
	Error   string       `json:"error"`
	Down    bool         `json:"down"`
	Now     string       `json:"now"`
	Version any          `json:"version"`
	Jails   []jailReport `json:"jails"`
	Config  configReport `json:"config"`
}

type configReport struct {
	Read    bool                       `json:"read"`
	Error   string                     `json:"error"`
	Filters []string                   `json:"filters"`
	Jails   map[string]json.RawMessage `json:"jails"`
	Files   map[string]string          `json:"files"`
}

type jailReport struct {
	Name         string                     `json:"name"`
	Error        string                     `json:"error"`
	Status       map[string]json.RawMessage `json:"status"`
	MaxRetry     json.RawMessage            `json:"maxretry"`
	FindTime     json.RawMessage            `json:"findtime"`
	BanTime      json.RawMessage            `json:"bantime"`
	BanIncrement json.RawMessage            `json:"bantime.increment"`
	BanMaxTime   json.RawMessage            `json:"bantime.maxtime"`
	IgnoreIP     json.RawMessage            `json:"ignoreip"`
	LogPath      json.RawMessage            `json:"logpath"`
	JournalMatch json.RawMessage            `json:"journalmatch"`
	FailRegex    json.RawMessage            `json:"failregex"`
	IgnoreRegex  json.RawMessage            `json:"ignoreregex"`
	Actions      []struct {
		Name     string          `json:"name"`
		Port     json.RawMessage `json:"port"`
		Protocol json.RawMessage `json:"protocol"`
	} `json:"actions"`
	Bans json.RawMessage `json:"bans"`
}

func parse(out string, now time.Time) *Status {
	sections := remote.SplitSections(out)
	if _, ok := sections["missing"]; ok {
		return &Status{}
	}
	s := &Status{Installed: true, Firewall: strings.TrimSpace(sections["firewall"])}
	text := sections["json"]
	var r report
	found := false
	for line := range strings.Lines(text) {
		if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &r) == nil {
			found = true
			break
		}
	}
	switch {
	case !found:
		s.Problem = "无法读取 fail2ban：" + firstLines(text, 6)
		return s
	case r.Down:
		s.Problem = "fail2ban 服务未运行（" + r.Error + "）"
		return s
	case r.Error != "":
		s.Problem = "无法读取 fail2ban：" + r.Error
		return s
	}
	s.Running = true
	s.Version = scalar(r.Version)
	serverNow, timed := parseTime(r.Now)
	for _, jr := range r.Jails {
		j := Jail{
			Name:            jr.Name,
			Problem:         jr.Error,
			MaxRetry:        int(number(jr.MaxRetry)),
			FindTime:        seconds(jr.FindTime),
			BanTime:         seconds(jr.BanTime),
			BanIncrement:    truth(jr.BanIncrement),
			BanMaxTime:      seconds(jr.BanMaxTime),
			IgnoreIP:        strs(jr.IgnoreIP),
			LogPaths:        strs(jr.LogPath),
			JournalMatch:    strs(jr.JournalMatch),
			FailRegex:       strs(jr.FailRegex),
			IgnoreRegex:     strs(jr.IgnoreRegex),
			CurrentlyFailed: int(number(jr.Status["Currently failed"])),
			TotalFailed:     int(number(jr.Status["Total failed"])),
			CurrentlyBanned: int(number(jr.Status["Currently banned"])),
			TotalBanned:     int(number(jr.Status["Total banned"])),
		}
		for _, a := range jr.Actions {
			j.Actions = append(j.Actions, Action{Name: a.Name, Port: str(a.Port), Protocol: str(a.Protocol)})
		}
		if len(j.LogPaths) == 0 {
			j.LogPaths = strs(jr.Status["File list"])
		}
		if len(j.JournalMatch) == 0 {
			j.JournalMatch = strs(jr.Status["Journal matches"])
		}
		// The status of a jail reading the journal lists its matches, even
		// none, instead of its files.
		_, j.Journal = jr.Status["Journal matches"]
		j.Journal = j.Journal || len(j.JournalMatch) > 0 && len(j.LogPaths) == 0
		if bans := strs(jr.Bans); len(bans) > 0 {
			for _, b := range bans {
				j.Bans = append(j.Bans, parseBan(b, now, serverNow, timed))
			}
		} else {
			for _, ip := range strs(jr.Status["Banned IP list"]) {
				j.Bans = append(j.Bans, Ban{IP: ip, Permanent: j.Permanent()})
			}
		}
		s.Jails = append(s.Jails, j)
	}
	s.Config = parseConfig(r.Config)
	return s
}

// parseConfig takes the configuration as the probe read it.
func parseConfig(r configReport) Config {
	c := Config{Read: r.Read, Problem: r.Error, Filters: r.Filters, Jails: map[string]bool{}, Overrides: map[string]*Override{}}
	for name, enabled := range r.Jails {
		c.Jails[name] = truth(enabled)
	}
	for file, text := range r.Files {
		if jail, ok := overrideJail(file); ok && ValidJailName(jail) == nil {
			c.Overrides[jail] = ParseOverride(jail, text)
		}
	}
	return c
}

// banTimes is what follows the address of a ban: "2026-10-19 01:55:26 +
// 3600 = 2026-10-19 02:55:26".
var banTimes = regexp.MustCompile(`^(.+?)\s+\+\s+(-?\d+)\s+=\s+(.+)$`)

// parseBan parses a ban as `get <jail> banip --with-time` lists it, telling
// its times by this computer's clock: now here is serverNow there.
func parseBan(s string, now, serverNow time.Time, timed bool) Ban {
	ip, rest, _ := strings.Cut(strings.TrimSpace(s), "\t")
	if rest == "" {
		ip, rest, _ = strings.Cut(strings.TrimSpace(s), " ")
	}
	b := Ban{IP: strings.TrimSpace(ip)}
	m := banTimes.FindStringSubmatch(strings.TrimSpace(rest))
	if m == nil {
		return b
	}
	secs, _ := strconv.Atoi(m[2])
	b.Permanent = secs < 0
	if !timed {
		return b
	}
	if start, ok := parseTime(m[1]); ok {
		b.Start = now.Add(start.Sub(serverNow))
	}
	if end, ok := parseTime(m[3]); ok && !b.Permanent {
		b.End = now.Add(end.Sub(serverNow))
	}
	return b
}

// parseTime parses a time of the server, as fail2ban writes them.
func parseTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.DateTime, strings.TrimSpace(s))
	return t, err == nil
}

// firstLines returns the first n lines of s, trimmed.
func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = append(lines[:n], "…")
	}
	return strings.Join(lines, "\n")
}

// decode decodes a value of the probe's JSON, nil when it cannot.
func decode(raw json.RawMessage) any {
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return v
}

// scalar writes a value of the probe as fail2ban-client would.
func scalar(v any) string {
	switch v := v.(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "true"
		}
		return "false"
	case []any:
		parts := make([]string, 0, len(v))
		for _, x := range v {
			parts = append(parts, scalar(x))
		}
		return strings.Join(parts, " ")
	}
	return fmt.Sprint(v)
}

func str(raw json.RawMessage) string { return scalar(decode(raw)) }

// strs decodes a list, as of addresses, or of the journal's matches, which
// are lists themselves.
func strs(raw json.RawMessage) []string {
	switch v := decode(raw).(type) {
	case nil:
		return nil
	case []any:
		var out []string
		for _, x := range v {
			if s := scalar(x); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return []string{scalar(v)}
	}
}

func number(raw json.RawMessage) float64 {
	switch v := decode(raw).(type) {
	case float64:
		return v
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f
	}
	return 0
}

func seconds(raw json.RawMessage) time.Duration {
	return time.Duration(number(raw) * float64(time.Second))
}

func truth(raw json.RawMessage) bool {
	switch v := decode(raw).(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "yes", "on", "1":
			return true
		}
	case float64:
		return v != 0
	}
	return false
}
