package fail2ban

import (
	"context"
	"fmt"
	"strings"

	"github.com/rulelens/rulelens/internal/remote"
)

// Unbanning lifts the bans of addresses in a jail.
type Unbanning struct {
	Jail string
	IPs  []string
}

// UnbanCommand is the command lifting the bans, one fail2ban-client call by
// jail.
func UnbanCommand(us []Unbanning) (string, error) {
	var cmds []string
	for _, u := range us {
		if len(u.IPs) == 0 {
			continue
		}
		args := []string{"fail2ban-client", "set", u.Jail, "unbanip"}
		for _, s := range append([]string{u.Jail}, u.IPs...) {
			// An argument fail2ban-client would take for an option.
			if s == "" || strings.HasPrefix(s, "-") {
				return "", fmt.Errorf("无效的 jail 或 IP：%q", s)
			}
		}
		cmds = append(cmds, remote.Join(append(args, u.IPs...)...))
	}
	return strings.Join(cmds, " && "), nil
}

// Unban lifts the bans, as root.
func Unban(ctx context.Context, x remote.Executor, us []Unbanning) error {
	cmd, err := UnbanCommand(us)
	if err != nil || cmd == "" {
		return err
	}
	_, err = remote.Check(ctx, x, true, remote.Prelude+cmd)
	return err
}
