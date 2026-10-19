// Package session connects to a server of the inventory over SSH, detects
// its system, and logs the commands run on it.
package session

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rulelens/rulelens/internal/remote"
	"github.com/rulelens/rulelens/internal/sshx"
	"github.com/rulelens/rulelens/internal/store"
)

// Info is what a connection learned of its server.
type Info struct {
	OS       remote.OSInfo
	Kernel   string
	Root     bool
	ClientIP string
	ServerIP string
	SSHPort  int
}

// Entry is a command a connection ran, for the log of operations.
type Entry struct {
	Time       time.Time
	Command    string
	Privileged bool
	ExitCode   int
	Output     string
	Err        string
	Duration   time.Duration
}

// OK reports whether the command ran and exited with success.
func (e Entry) OK() bool { return e.Err == "" && e.ExitCode == 0 }

// Conn is a connection to a server.
type Conn interface {
	Info() Info
	// Exec runs commands on the server, recording them in the log.
	Exec() remote.Executor
	// Log returns the commands run so far, the oldest first.
	Log() []Entry
	Alive() bool
	Close() error
}

// Dialer connects to servers.
type Dialer interface {
	Dial(ctx context.Context, srv store.Server, sec store.Secrets) (Conn, error)
	// Trust accepts the key of an *sshx.UnknownHostError.
	Trust(hostport string, key ssh.PublicKey) error
}

// SSHDialer connects over SSH, checking the servers' keys with HostKeys.
type SSHDialer struct {
	HostKeys *sshx.HostKeys
}

// Dial connects to srv and detects its system.
func (d *SSHDialer) Dial(ctx context.Context, srv store.Server, sec store.Secrets) (Conn, error) {
	client, err := sshx.Dial(ctx, sshx.Config{
		Host:         srv.Host,
		Port:         srv.Port,
		User:         srv.User,
		Auth:         srv.Auth,
		Password:     sec.Password,
		KeyPath:      srv.KeyPath,
		Passphrase:   sec.Passphrase,
		SudoPassword: sec.SudoPassword,
		HostKeys:     d.HostKeys,
	})
	if err != nil {
		return nil, err
	}
	conn, err := Start(ctx, client)
	if err != nil {
		client.Close()
		return nil, err
	}
	return conn, nil
}

// Trust accepts a server's key.
func (d *SSHDialer) Trust(hostport string, key ssh.PublicKey) error {
	return d.HostKeys.Trust(hostport, key)
}

// Client is a connection that runs commands, as an *sshx.Client.
type Client interface {
	remote.Executor
	SetRoot(bool)
	Alive() bool
	Close() error
}

// Start detects the system of the server of client.
func Start(ctx context.Context, client Client) (Conn, error) {
	c := &conn{client: client}
	det, err := remote.Detect(ctx, c)
	if err != nil {
		return nil, err
	}
	client.SetRoot(det.Root)
	c.info = Info{
		OS:       det.OS,
		Kernel:   det.Kernel,
		Root:     det.Root,
		ClientIP: det.ClientIP,
		ServerIP: det.ServerIP,
		SSHPort:  det.SSHPort,
	}
	return c, nil
}

// conn records the commands it runs.
type conn struct {
	client Client
	info   Info

	mu  sync.Mutex
	log []Entry
}

// maxLog is how many entries a connection keeps.
const maxLog = 300

func (c *conn) Info() Info            { return c.info }
func (c *conn) Exec() remote.Executor { return c }
func (c *conn) Alive() bool           { return c.client.Alive() }
func (c *conn) Close() error          { return c.client.Close() }

func (c *conn) Log() []Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.log)
}

func (c *conn) Run(ctx context.Context, cmd string) (remote.Result, error) {
	start := time.Now()
	res, err := c.client.Run(ctx, cmd)
	c.record(start, cmd, false, res, err)
	return res, err
}

func (c *conn) RunPrivileged(ctx context.Context, cmd string) (remote.Result, error) {
	start := time.Now()
	res, err := c.client.RunPrivileged(ctx, cmd)
	c.record(start, cmd, true, res, err)
	return res, err
}

func (c *conn) record(start time.Time, cmd string, privileged bool, res remote.Result, err error) {
	e := Entry{
		Time:       start,
		Command:    remote.DisplayCommand(cmd),
		Privileged: privileged,
		ExitCode:   res.ExitCode,
		Output:     strings.TrimRight(res.Stdout+res.Stderr, "\n"),
		Duration:   time.Since(start),
	}
	if len(e.Output) > 8000 {
		e.Output = e.Output[:8000] + "\n…"
	}
	if err != nil {
		e.Err = err.Error()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log = append(c.log, e)
	if len(c.log) > maxLog {
		c.log = slices.Delete(c.log, 0, len(c.log)-maxLog)
	}
}
