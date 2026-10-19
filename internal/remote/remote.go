// Package remote runs shell commands on a server through an Executor (over
// SSH in the app), and learns what system the server runs.
package remote

import (
	"context"
	"fmt"
	"strings"
)

// Result is what a command printed and how it exited.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Executor runs shell commands on a server.
type Executor interface {
	// Run runs cmd with sh as the login user. A command that ran and
	// failed is not an error: its exit code is in the result. The error is
	// for commands that could not run, as when the connection broke.
	Run(ctx context.Context, cmd string) (Result, error)
	// RunPrivileged runs cmd as root: through sudo, unless the login user
	// is root.
	RunPrivileged(ctx context.Context, cmd string) (Result, error)
}

// CommandError is a command that exited with an error.
type CommandError struct {
	Command  string
	ExitCode int
	Output   string
}

func (e *CommandError) Error() string {
	out := strings.TrimSpace(e.Output)
	if out == "" {
		return fmt.Sprintf("命令执行失败（退出码 %d）", e.ExitCode)
	}
	return fmt.Sprintf("命令执行失败（退出码 %d）：%s", e.ExitCode, out)
}

// Check runs cmd, as root when privileged, and turns its exit with an error
// into a *CommandError.
func Check(ctx context.Context, x Executor, privileged bool, cmd string) (Result, error) {
	var res Result
	var err error
	if privileged {
		res, err = x.RunPrivileged(ctx, cmd)
	} else {
		res, err = x.Run(ctx, cmd)
	}
	if err != nil {
		return res, err
	}
	if res.ExitCode != 0 {
		out := res.Stderr
		if strings.TrimSpace(out) == "" {
			out = res.Stdout
		}
		return res, &CommandError{Command: cmd, ExitCode: res.ExitCode, Output: out}
	}
	return res, nil
}

// Prelude makes the output of commands parseable whatever the server's
// language, and finds the tools in sbin for users whose PATH lacks it.
// Logs leave it out.
const Prelude = `export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin"; `

// DisplayCommand returns cmd as a log shows it: without the Prelude.
func DisplayCommand(cmd string) string {
	return strings.TrimPrefix(cmd, Prelude)
}
