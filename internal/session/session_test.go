package session

import (
	"context"
	"strings"
	"testing"

	"github.com/rulelens/rulelens/internal/remote"
)

// fakeClient answers the detection script with detect, and other commands
// with nothing.
type fakeClient struct {
	detect string
	root   bool
	closed bool
}

func (f *fakeClient) Run(_ context.Context, cmd string) (remote.Result, error) {
	if strings.Contains(cmd, "@@os") {
		return remote.Result{Stdout: f.detect}, nil
	}
	return remote.Result{}, nil
}

func (f *fakeClient) RunPrivileged(ctx context.Context, cmd string) (remote.Result, error) {
	return remote.Result{Stdout: "ok\n"}, nil
}

func (f *fakeClient) SetRoot(root bool) { f.root = root }
func (f *fakeClient) Alive() bool       { return !f.closed }
func (f *fakeClient) Close() error      { f.closed = true; return nil }

const ubuntu = "@@os\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\n@@kernel\nLinux 5.15\n@@uid\n0\n@@ssh\n198.51.100.7 50000 203.0.113.10 2222\n"

func TestStart(t *testing.T) {
	client := &fakeClient{detect: ubuntu}
	conn, err := Start(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	info := conn.Info()
	if !info.Root || !client.root || info.SSHPort != 2222 ||
		info.ClientIP != "198.51.100.7" || info.ServerIP != "203.0.113.10" || info.OS.String() != "Ubuntu 22.04.4 LTS" {
		t.Errorf("info %+v", info)
	}
	if _, err := conn.Exec().RunPrivileged(context.Background(), remote.Prelude+"fail2ban-client status"); err != nil {
		t.Fatal(err)
	}
	log := conn.Log()
	if len(log) != 2 || log[1].Command != "fail2ban-client status" || !log[1].Privileged || !log[1].OK() || log[1].Output != "ok" {
		t.Errorf("log %+v", log)
	}
}

func TestLogKeepsTheLast(t *testing.T) {
	c := &conn{client: &fakeClient{}}
	for range maxLog + 10 {
		c.Run(context.Background(), "true")
	}
	if n := len(c.Log()); n != maxLog {
		t.Errorf("%d entries, want %d", n, maxLog)
	}
}
