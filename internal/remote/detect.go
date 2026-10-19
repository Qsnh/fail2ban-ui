package remote

import (
	"bufio"
	"context"
	"slices"
	"strconv"
	"strings"
)

// OSInfo is what /etc/os-release says of the server's system.
type OSInfo struct {
	ID         string   // "ubuntu"
	IDLike     []string // "debian"
	Name       string   // "Ubuntu"
	Version    string   // "24.04"
	PrettyName string   // "Ubuntu 24.04.1 LTS"
}

// Is reports whether the system is id or derives from it.
func (o OSInfo) Is(id string) bool {
	return o.ID == id || slices.Contains(o.IDLike, id)
}

// String names the system for people.
func (o OSInfo) String() string {
	if o.PrettyName != "" {
		return o.PrettyName
	}
	if o.Name != "" {
		return strings.TrimSpace(o.Name + " " + o.Version)
	}
	if o.ID != "" {
		return o.ID
	}
	return "未知系统"
}

// ParseOSRelease parses the contents of /etc/os-release.
func ParseOSRelease(s string) OSInfo {
	var o OSInfo
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, `'"`)
		}
		switch k {
		case "ID":
			o.ID = strings.ToLower(v)
		case "ID_LIKE":
			o.IDLike = strings.Fields(strings.ToLower(v))
		case "NAME":
			o.Name = v
		case "VERSION_ID":
			o.Version = v
		case "PRETTY_NAME":
			o.PrettyName = v
		}
	}
	return o
}

// Detection is what Detect learned of a server.
type Detection struct {
	OS OSInfo
	// Kernel is `uname -sr`.
	Kernel string
	// Root tells whether the login user is root.
	Root bool
	// ClientIP is the address the server sees the SSH connection come
	// from, ServerIP the address it came in on, and SSHPort the port,
	// from $SSH_CONNECTION.
	ClientIP string
	ServerIP string
	SSHPort  int
}

// detectScript prints sections of facts, each after a marker line.
const detectScript = `echo '@@os'; cat /etc/os-release 2>/dev/null
echo '@@kernel'; uname -sr 2>/dev/null
echo '@@uid'; id -u
echo '@@ssh'; echo "$SSH_CONNECTION"`

// Detect learns what system the server runs, and who the login user is.
func Detect(ctx context.Context, x Executor) (Detection, error) {
	res, err := Check(ctx, x, false, detectScript)
	if err != nil {
		return Detection{}, err
	}
	return parseDetection(res.Stdout), nil
}

func parseDetection(out string) Detection {
	var d Detection
	sections := SplitSections(out)
	d.OS = ParseOSRelease(sections["os"])
	d.Kernel = strings.TrimSpace(sections["kernel"])
	d.Root = strings.TrimSpace(sections["uid"]) == "0"
	// SSH_CONNECTION is "client-ip client-port server-ip server-port".
	if f := strings.Fields(sections["ssh"]); len(f) == 4 {
		d.ClientIP, d.ServerIP = f[0], f[2]
		d.SSHPort, _ = strconv.Atoi(f[3])
	}
	return d
}
