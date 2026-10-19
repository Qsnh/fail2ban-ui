package fail2ban

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rulelens/rulelens/internal/remote"
)

// HistoryLimit is how many records of bans a reading of the history takes
// at most, the latest.
const HistoryLimit = 40000

// historyProbe reads the bans fail2ban made, lifted too, from its log: the
// lines "[jail] Ban <ip>", "[jail] Restore Ban <ip>" and "[jail] Unban
// <ip>" of the log file and the files logrotate made of it, compressed or
// not, oldest first; or, logging elsewhere, of the systemd journal, where
// fail2ban logs as "fail2ban", as "fail2ban-server" to the standard output
// of its service, and as "fail2ban.actions" to syslog. Without them, it
// reads the bans of fail2ban's database instead, which keeps those of the
// last dbpurgeage, and forgets those lifted by hand.
var historyProbe = probeHead + `import gzip, re
from collections import deque
LIMIT = ` + strconv.Itoa(HistoryLimit) + `
stamp = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)")
act = re.compile(r"\[([^\]\s]+)\]\s+(Restore Ban|Ban|Unban)\s+(\S+)")
events = deque(maxlen=LIMIT)
count = [0]
problems = []
def add(when, line):
    m = act.search(line)
    if m:
        count[0] += 1
        events.append([when, m.group(1), m.group(2), m.group(3)])
def reader(p):
    if p.endswith(".gz"):
        return gzip.open(p, "rb")
    if p.endswith(".bz2"):
        import bz2
        return bz2.BZ2File(p, "rb")
    if p.endswith(".xz"):
        import lzma
        return lzma.open(p, "rb")
    return open(p, "rb")
target = str(opt("get", "logtarget") or "/var/log/fail2ban.log")
out["target"] = target
out["purgeage"] = opt("get", "dbpurgeage")
name = target.split("[")[0].strip()
journal = False
if not name.startswith("/"):
    try:
        import subprocess
        p = subprocess.Popen(["journalctl", "-q", "--no-pager", "-o", "json", "SYSLOG_IDENTIFIER=fail2ban",
                              "SYSLOG_IDENTIFIER=fail2ban-server", "SYSLOG_IDENTIFIER=fail2ban.actions"],
                             stdout=subprocess.PIPE, stderr=open(os.devnull, "w"))
        for raw in p.stdout:
            if b"Ban " in raw or b"Unban " in raw:
                try:
                    e = json.loads(raw.decode("utf-8", "replace"))
                    t = time.localtime(int(e["__REALTIME_TIMESTAMP"]) / 1000000.0)
                    add(time.strftime("%Y-%m-%d %H:%M:%S", t), e["MESSAGE"])
                except Exception:
                    pass
        code = p.wait()
        journal = code == 0
        if journal and count[0] > 0:
            out["source"] = "journal"
        elif not journal:
            problems.append("journalctl: exit status %d" % code)
    except Exception as e:
        problems.append("journalctl: %s" % e)
else:
    rotated = re.compile(r"^[.-]\d")
    files = [p for p in glob.glob(name + "*") if os.path.isfile(p) and (p == name or rotated.match(p[len(name):]))]
    files.sort(key=os.path.getmtime)
    for p in files:
        try:
            f = reader(p)
            try:
                for raw in f:
                    if b"Ban " in raw or b"Unban " in raw:
                        line = raw.decode("utf-8", "replace")
                        m = stamp.match(line)
                        if m:
                            add(m.group(1), line)
            finally:
                f.close()
        except Exception as e:
            problems.append("%s: %s" % (p, e))
    if files:
        out["source"] = "file"
        out["files"] = files
if "source" not in out:
    db = str(opt("get", "dbfile") or "")
    if db and db != ":memory:" and os.path.isfile(db):
        try:
            import sqlite3
            c = sqlite3.connect(db, timeout=10)
            try:
                try:
                    rows = c.execute("SELECT timeofban, jail, ip, bantime FROM bans ORDER BY timeofban").fetchall()
                except Exception:
                    rows = [r + (None,) for r in c.execute("SELECT timeofban, jail, ip FROM bans ORDER BY timeofban").fetchall()]
            finally:
                c.close()
            if rows or not journal:
                count[0] = len(rows)
                out["bans"] = [[time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r[0])), r[1], r[2], r[3]] for r in rows[-LIMIT:]]
                out["source"] = "db"
                out["db"] = db
        except Exception as e:
            problems.append("%s: %s" % (db, e))
if "source" not in out and journal:
    out["source"] = "journal"
out["events"] = list(events)
out["count"] = count[0]
out["problems"] = problems
done()
`

// historyScript reads the history, as root.
var historyScript = python(historyProbe) + "exit 0"

// The sources of a history.
const (
	// SourceFile is the log files of fail2ban.
	SourceFile = "file"
	// SourceJournal is the systemd journal.
	SourceJournal = "journal"
	// SourceDB is fail2ban's database.
	SourceDB = "db"
)

// History is the bans fail2ban made, those lifted too, as far back as its
// log goes.
type History struct {
	// Source is where the bans were read: SourceFile, the log files of
	// Files, oldest first; SourceJournal; or SourceDB, fail2ban's database
	// DB, which keeps the bans of the last PurgeAge and forgets those
	// lifted by hand. It is "" when none could be read, as Problem tells.
	Source   string
	Files    []string
	DB       string
	PurgeAge time.Duration
	// Target is where fail2ban logs, its logtarget: a file,
	// "SYSTEMD-JOURNAL", "SYSLOG".
	Target string
	// Count is how many records the source has; Truncated reports it has
	// more than HistoryLimit, the latest of which were read.
	Count     int
	Truncated bool
	// Since is when the earliest record read was made.
	Since time.Time
	// Bans are the bans, in the order they began.
	Bans []PastBan
	// Problem is why the history could not be read, Problems what of it
	// could not, as a log file.
	Problem  string
	Problems []string
}

// PastBan is a ban of an address by a jail, lifted or not.
type PastBan struct {
	IP   string
	Jail string
	// Start is when the ban began, zero when before the history; Restored
	// reports the history saw it only restored as fail2ban started.
	Start    time.Time
	Restored bool
	// End is when the ban was lifted, or for one in effect, when it will
	// be; zero when not told, and for bans for ever.
	End time.Time
	// Active reports whether the ban is in effect, and Permanent whether
	// it is for ever.
	Active    bool
	Permanent bool
}

// Key identifies the jail and the address.
func (b PastBan) Key() string { return b.Jail + " " + b.IP }

// ReadHistory reads the bans fail2ban made on the server x runs commands
// on, as root. now is the time of the reading, by which the times of the
// bans are told.
func ReadHistory(ctx context.Context, x remote.Executor, now time.Time) (*History, error) {
	res, err := remote.Check(ctx, x, true, remote.Prelude+historyScript)
	if err != nil {
		return nil, err
	}
	return parseHistory(res.Stdout, now), nil
}

// historyReport is what the history's probe prints.
type historyReport struct {
	Error    string              `json:"error"`
	Now      string              `json:"now"`
	Target   string              `json:"target"`
	PurgeAge json.RawMessage     `json:"purgeage"`
	Source   string              `json:"source"`
	Files    []string            `json:"files"`
	DB       string              `json:"db"`
	Count    int                 `json:"count"`
	Events   [][]string          `json:"events"`
	Bans     [][]json.RawMessage `json:"bans"`
	Problems []string            `json:"problems"`
}

// event is a line of the log: a jail banned an address, restored its ban,
// or lifted it.
type event struct {
	at       time.Time
	jail, ip string
	kind     string
}

func parseHistory(out string, now time.Time) *History {
	sections := remote.SplitSections(out)
	if _, ok := sections["missing"]; ok {
		return &History{Problem: "服务器未安装 fail2ban"}
	}
	text := sections["json"]
	var r historyReport
	found := false
	for line := range strings.Lines(text) {
		if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &r) == nil {
			found = true
			break
		}
	}
	switch {
	case !found:
		return &History{Problem: "无法读取封禁历史：" + firstLines(text, 6)}
	case r.Error != "":
		return &History{Problem: "无法读取封禁历史：" + r.Error}
	}
	h := &History{
		Source:   r.Source,
		Files:    r.Files,
		DB:       r.DB,
		PurgeAge: seconds(r.PurgeAge),
		Target:   r.Target,
		Count:    r.Count,
		Problems: r.Problems,
	}
	serverNow, timed := parseTime(r.Now)
	// at tells a time of the server by this computer's clock.
	at := func(s string) time.Time {
		t, ok := parseTime(s)
		if !ok || !timed {
			return time.Time{}
		}
		return now.Add(t.Sub(serverNow))
	}
	switch r.Source {
	case SourceFile, SourceJournal:
		h.Truncated = r.Count > len(r.Events)
		evs := make([]event, 0, len(r.Events))
		for _, e := range r.Events {
			if len(e) == 4 {
				evs = append(evs, event{at: at(e[0]), jail: e[1], kind: e[2], ip: e[3]})
			}
		}
		// pastBans sorts the events by time.
		h.Bans = pastBans(evs)
		if len(evs) > 0 {
			h.Since = evs[0].at
		}
	case SourceDB:
		h.Truncated = r.Count > len(r.Bans)
		for _, row := range r.Bans {
			if len(row) != 4 {
				continue
			}
			b := PastBan{Start: at(str(row[0])), Jail: str(row[1]), IP: str(row[2]), Active: true}
			if bt := decode(row[3]); bt != nil {
				secs := number(row[3])
				b.Permanent = secs < 0
				if !b.Permanent {
					b.End = b.Start.Add(time.Duration(secs * float64(time.Second)))
					b.Active = b.End.After(now)
				}
			}
			h.Bans = append(h.Bans, b)
		}
		slices.SortStableFunc(h.Bans, func(x, y PastBan) int { return x.Start.Compare(y.Start) })
		if len(h.Bans) > 0 {
			h.Since = h.Bans[0].Start
		}
	default:
		h.Problem = "fail2ban 的日志不在文件或 systemd 日志中（logtarget 为 " + orNone(r.Target) + "），也无法读取它的数据库"
		if len(r.Problems) > 0 {
			h.Problem += "：" + strings.Join(r.Problems, "；")
		}
	}
	return h
}

func orNone(s string) string {
	if s == "" {
		return "空"
	}
	return s
}

// pastBans pairs the bans of the log with their ends. fail2ban stopping
// lifts the bans in effect, and restores them as it starts: a ban
// restored goes on.
func pastBans(evs []event) []PastBan {
	slices.SortStableFunc(evs, func(x, y event) int { return x.at.Compare(y.at) })
	var out []PastBan
	// open are the bans in effect, by key, and last the latest of each key,
	// as indexes of out.
	open, last := map[string]int{}, map[string]int{}
	for _, e := range evs {
		k := e.jail + " " + e.ip
		switch e.kind {
		case "Ban":
			if i, ok := open[k]; ok {
				// Lifted, but the log did not say when.
				out[i].Active = false
			}
			out = append(out, PastBan{IP: e.ip, Jail: e.jail, Start: e.at, Active: true})
			open[k], last[k] = len(out)-1, len(out)-1
		case "Restore Ban":
			if _, ok := open[k]; ok {
				continue // fail2ban ended without lifting it
			}
			if i, ok := last[k]; ok {
				// The ban was lifted as fail2ban stopped.
				out[i].End, out[i].Active = time.Time{}, true
				open[k] = i
				continue
			}
			out = append(out, PastBan{IP: e.ip, Jail: e.jail, Restored: true, Active: true})
			open[k], last[k] = len(out)-1, len(out)-1
		case "Unban":
			if i, ok := open[k]; ok {
				out[i].End, out[i].Active = e.at, false
				delete(open, k)
				continue
			}
			// Banned before the log began.
			out = append(out, PastBan{IP: e.ip, Jail: e.jail, End: e.at})
			last[k] = len(out) - 1
		}
	}
	return out
}

// Merged returns the bans of the history with what s, read since, says of
// those in effect: a ban the history has in effect is so when s lists it,
// and was lifted otherwise; bans s lists that the history lacks, begun
// before it or since it was read, are added.
func (h *History) Merged(s *Status) []PastBan {
	current := map[string]Ban{}
	if s != nil {
		for _, j := range s.Jails {
			for _, b := range j.Bans {
				current[j.Name+" "+b.IP] = b
			}
		}
	}
	out := slices.Clone(h.Bans)
	matched := map[string]bool{}
	for i := len(out) - 1; i >= 0; i-- {
		b := &out[i]
		if !b.Active {
			continue
		}
		k := b.Key()
		cur, ok := current[k]
		if !ok || matched[k] {
			// Lifted since, or as a later ban began: when, it does not
			// tell.
			b.Active, b.Permanent, b.End = false, false, time.Time{}
			continue
		}
		matched[k] = true
		b.End, b.Permanent = cur.End, cur.Permanent
		if b.Start.IsZero() {
			b.Start = cur.Start
		}
	}
	if s != nil {
		for _, j := range s.Jails {
			for _, b := range j.Bans {
				if !matched[j.Name+" "+b.IP] {
					out = append(out, PastBan{IP: b.IP, Jail: j.Name, Start: b.Start, End: b.End, Active: true, Permanent: b.Permanent})
				}
			}
		}
	}
	return out
}
