package remote

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeExec answers commands from a function and records them.
type fakeExec struct {
	cmds   []string
	answer func(cmd string) Result
}

func (f *fakeExec) Run(ctx context.Context, cmd string) (Result, error) {
	f.cmds = append(f.cmds, cmd)
	return f.answer(cmd), nil
}

func (f *fakeExec) RunPrivileged(ctx context.Context, cmd string) (Result, error) {
	f.cmds = append(f.cmds, "sudo "+cmd)
	return f.answer(cmd), nil
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"":            "''",
		"22/tcp":      "22/tcp",
		"a b":         "'a b'",
		"it's":        `'it'\''s'`,
		"$(reboot)":   "'$(reboot)'",
		"10.0.0.0/8":  "10.0.0.0/8",
		"2001:db8::1": "2001:db8::1",
	} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
	if got := Join("echo", "a b", "c"); got != "echo 'a b' c" {
		t.Errorf("Join: %s", got)
	}
}

func TestSplitSections(t *testing.T) {
	s := SplitSections("before\n@@one\na\nb\n@@two\n@@ not a marker\n")
	if len(s) != 2 || s["one"] != "a\nb\n" || s["two"] != "@@ not a marker\n" {
		t.Errorf("sections %q", s)
	}
}

func TestDetect(t *testing.T) {
	out := `@@os
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04.1 LTS"
@@kernel
Linux 6.8.0-45-generic
@@uid
1000
@@ssh
198.51.100.7 51234 203.0.113.10 22
`
	x := &fakeExec{answer: func(cmd string) Result { return Result{Stdout: out} }}
	d, err := Detect(context.Background(), x)
	if err != nil {
		t.Fatal(err)
	}
	if d.OS.ID != "ubuntu" || !d.OS.Is("debian") || d.OS.String() != "Ubuntu 24.04.1 LTS" || d.Root ||
		d.Kernel != "Linux 6.8.0-45-generic" || d.ClientIP != "198.51.100.7" || d.ServerIP != "203.0.113.10" || d.SSHPort != 22 {
		t.Errorf("detection %+v", d)
	}
	if len(x.cmds) != 1 || strings.HasPrefix(x.cmds[0], "sudo ") {
		t.Errorf("commands %q", x.cmds)
	}
}

func TestCheck(t *testing.T) {
	x := &fakeExec{answer: func(cmd string) Result { return Result{ExitCode: 2, Stderr: "boom\n"} }}
	_, err := Check(context.Background(), x, true, "false")
	var ce *CommandError
	if !errors.As(err, &ce) || ce.ExitCode != 2 || !strings.Contains(err.Error(), "boom") || x.cmds[0] != "sudo false" {
		t.Errorf("err %v, commands %q", err, x.cmds)
	}
}
