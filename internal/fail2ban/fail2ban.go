// Package fail2ban reads the state of fail2ban on a server through a
// remote.Executor: its jails, the rules each applies, and the addresses it
// bans.
package fail2ban

import (
	"slices"
	"strings"
	"time"
)

// Status is fail2ban on a server, as read at one moment.
type Status struct {
	// Installed reports whether the server has fail2ban, Running whether
	// its server answered, and Problem why it could not be read.
	Installed bool
	Running   bool
	Problem   string
	Version   string
	Jails     []Jail
	// Firewall is what fail2ban put in the server's firewall: its chains,
	// tables and sets, as the firewall's tools list them.
	Firewall string
	// Config is the configuration of the jails, those not running too.
	Config Config
}

// Banned counts the addresses the jails ban now.
func (s *Status) Banned() int {
	n := 0
	for _, j := range s.Jails {
		n += j.CurrentlyBanned
	}
	return n
}

// TotalBanned counts the bans since fail2ban started.
func (s *Status) TotalBanned() int {
	n := 0
	for _, j := range s.Jails {
		n += j.TotalBanned
	}
	return n
}

// Jail is a rule of fail2ban: the lines of its logs that are failures, how
// many failures make a ban, how long a ban lasts, and the actions banning.
type Jail struct {
	Name string
	// A source failing MaxRetry times within FindTime is banned for
	// BanTime, or for ever when BanTime is negative.
	MaxRetry int
	FindTime time.Duration
	BanTime  time.Duration
	// BanIncrement makes each ban of a source banned before last longer,
	// up to BanMaxTime when it is set.
	BanIncrement bool
	BanMaxTime   time.Duration
	// LogPaths are the logs the jail reads; Journal reports whether it
	// reads the systemd journal instead, and JournalMatch what of it.
	LogPaths     []string
	Journal      bool
	JournalMatch []string
	// FailRegex are the patterns of failures, IgnoreRegex those of lines
	// that are not, and IgnoreIP the sources never banned.
	FailRegex   []string
	IgnoreRegex []string
	IgnoreIP    []string
	Actions     []Action

	CurrentlyFailed int
	TotalFailed     int
	CurrentlyBanned int
	TotalBanned     int
	Bans            []Ban
	// Problem is what kept the jail from being read in full.
	Problem string
}

// Permanent reports whether the jail bans for ever.
func (j Jail) Permanent() bool { return j.BanTime < 0 }

// Ports lists the ports the jail's actions ban sources from, once each:
// "ssh", "http,https", or "" for all.
func (j Jail) Ports() []string {
	var out []string
	for _, a := range j.Actions {
		p := a.Port
		if AllPorts(p) {
			p = ""
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// Protocols lists the protocols of the jail's actions, once each.
func (j Jail) Protocols() []string {
	var out []string
	for _, a := range j.Actions {
		if a.Protocol != "" && !slices.Contains(out, a.Protocol) {
			out = append(out, a.Protocol)
		}
	}
	return out
}

// AllPorts reports whether port, as an action has it, is every port.
func AllPorts(port string) bool {
	switch strings.TrimSpace(port) {
	case "", "0:65535", "1:65535", "0-65535", "1-65535", "all", "any":
		return true
	}
	return false
}

// Action bans the sources of a jail, as "iptables-multiport" does on the
// ports it names.
type Action struct {
	Name string
	// Port is as the action has it: "ssh", "http,https", "0:65535".
	Port     string
	Protocol string
}

// Ban is an address a jail bans.
type Ban struct {
	IP string
	// Start and End are when the ban began and ends, by this computer's
	// clock; zero when the server did not tell, and End for ever.
	Start time.Time
	End   time.Time
	// Permanent bans never end.
	Permanent bool
}

// The patterns fail2ban puts for the tags of failregex, as <HOST>.
const (
	reIP4    = `(?:::f{4,6}:)?(?P<ip4>(?:\d{1,3}\.){3}\d{1,3})`
	reIP6    = `(?P<ip6>(?:[0-9a-fA-F]{1,4}::?|::){1,7}(?:[0-9a-fA-F]{1,4}|(?<=:):))`
	reDNS    = `(?P<dns>[\w\-.^_]*\w)`
	reAddr   = `\[?(?:` + reIP4 + `|` + reIP6 + `)\]?`
	reHost   = `(?:` + reAddr + `|` + reDNS + `)`
	reSubnet = `\[?(?:` + reIP4 + `|` + reIP6 + `)(?:/(?P<cidr>\d+))?\]?`
)

var tags = strings.NewReplacer(
	reHost, "<HOST>",
	reSubnet, "<SUBNET>",
	reAddr, "<ADDR>",
	reIP4, "<IP4>",
	reIP6, "<IP6>",
	reDNS, "<DNS>",
	`(?P<fid>\S+)`, "<F-ID/>",
	`(?P<fport>\w+)`, "<F-PORT/>",
)

// Readable writes a failregex as the filter's author did: with the tags,
// as <HOST>, in place of the patterns fail2ban expanded them to.
func Readable(re string) string {
	return tags.Replace(re)
}
