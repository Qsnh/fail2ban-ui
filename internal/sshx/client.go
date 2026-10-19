// Package sshx connects to servers over SSH and runs commands on them, as
// the login user or as root through sudo.
package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/rulelens/rulelens/internal/remote"
)

// AuthMethod is how a client proves who it is.
type AuthMethod string

const (
	AuthPassword AuthMethod = "password"
	AuthKey      AuthMethod = "key"
	AuthAgent    AuthMethod = "agent"
)

// Config says where and how to connect.
type Config struct {
	Host string
	Port int
	User string
	Auth AuthMethod
	// Password is the login password of AuthPassword.
	Password string
	// KeyPath is the private key file of AuthKey, which Passphrase
	// decrypts when it is encrypted.
	KeyPath    string
	Passphrase string
	// SudoPassword is the password sudo asks for; empty, the login
	// password, and without one sudo must not ask (NOPASSWD).
	SudoPassword string
	HostKeys     *HostKeys
	// Timeout bounds connecting; 15 seconds when zero.
	Timeout time.Duration
}

// Addr returns host:port.
func (c Config) Addr() string {
	port := c.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(c.Host, strconv.Itoa(port))
}

func (c Config) sudoPassword() string {
	if c.SudoPassword != "" {
		return c.SudoPassword
	}
	if c.Auth == AuthPassword || c.Auth == "" {
		return c.Password
	}
	return ""
}

var (
	// ErrAuth is a server that turned down the credentials.
	ErrAuth = errors.New("认证失败：用户名、密码或密钥不正确")
	// ErrPassphrase is an encrypted key without its passphrase.
	ErrPassphrase = errors.New("私钥已加密，请填写私钥口令")
	// ErrSudo is sudo refusing to run a command as root.
	ErrSudo = errors.New("sudo 提权失败")
	// ErrClosed is a client used after Close.
	ErrClosed = errors.New("连接已关闭")
)

// Client is a connection to a server.
type Client struct {
	cfg  Config
	conn *ssh.Client
	root atomic.Bool

	mu     sync.Mutex
	closed bool
	done   chan struct{}
}

// Dial connects to the server of cfg.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Host == "" || cfg.User == "" {
		return nil, errors.New("主机和用户名不能为空")
	}
	auth, err := authMethods(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.HostKeys == nil {
		return nil, errors.New("缺少主机指纹校验")
	}
	hostKeyCallback, err := cfg.HostKeys.Callback()
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	var hostKeyErr error
	sshCfg := &ssh.ClientConfig{
		User: cfg.User,
		Auth: auth,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			hostKeyErr = hostKeyCallback(hostname, remote, key)
			return hostKeyErr
		},
		// Ask for the kinds of key the known_hosts files hold for the
		// server, so that a server known by its ed25519 key is not taken
		// for another for offering its ECDSA key first.
		HostKeyAlgorithms: cfg.HostKeys.Algorithms(cfg.Addr()),
		Timeout:           timeout,
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", cfg.Addr())
	if err != nil {
		return nil, fmt.Errorf("无法连接 %s：%w", cfg.Addr(), err)
	}
	// The handshake knows no context: a deadline bounds it, and closing
	// the connection ends it when ctx is done first.
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	c, chans, reqs, err := ssh.NewClientConn(conn, cfg.Addr(), sshCfg)
	stop()
	if err != nil {
		conn.Close()
		if hostKeyErr != nil {
			return nil, hostKeyErr
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, ErrAuth
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("连接 %s 超时", cfg.Addr())
		}
		return nil, fmt.Errorf("SSH 握手失败：%w", err)
	}
	conn.SetDeadline(time.Time{})
	client := &Client{
		cfg:  cfg,
		conn: ssh.NewClient(c, chans, reqs),
		done: make(chan struct{}),
	}
	client.root.Store(cfg.User == "root")
	go client.keepAlive()
	return client, nil
}

func authMethods(cfg Config) ([]ssh.AuthMethod, error) {
	switch cfg.Auth {
	case AuthPassword, "":
		pw := cfg.Password
		return []ssh.AuthMethod{
			ssh.Password(pw),
			// Servers that only ask through keyboard-interactive get the
			// password for every question.
			ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			}),
		}, nil
	case AuthKey:
		signer, err := loadKey(cfg.KeyPath, cfg.Passphrase)
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	case AuthAgent:
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, errors.New("未检测到 ssh-agent（SSH_AUTH_SOCK 未设置）")
		}
		return []ssh.AuthMethod{ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			conn, err := net.Dial("unix", sock)
			if err != nil {
				return nil, fmt.Errorf("连接 ssh-agent 失败：%w", err)
			}
			defer conn.Close()
			return agent.NewClient(conn).Signers()
		})}, nil
	}
	return nil, fmt.Errorf("未知的认证方式 %q", cfg.Auth)
}

// ExpandHome expands a leading ~ of a path to the home directory.
func ExpandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[1:])
		}
	}
	return path
}

func loadKey(path, passphrase string) (ssh.Signer, error) {
	if path == "" {
		return nil, errors.New("请选择私钥文件")
	}
	pem, err := os.ReadFile(ExpandHome(path))
	if err != nil {
		return nil, fmt.Errorf("读取私钥失败：%w", err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if passphrase == "" {
			return nil, ErrPassphrase
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pem, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("私钥口令不正确：%w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("无法解析私钥：%w", err)
	}
	return signer, nil
}

// keepAlive pings the server every 30 seconds, and closes the client when
// it stops answering within 15, so that Alive tells a dead connection, as
// after the computer slept or changed networks.
func (c *Client) keepAlive() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
		}
		answered := make(chan error, 1)
		go func() {
			_, _, err := c.conn.SendRequest("keepalive@openssh.com", true, nil)
			answered <- err
		}()
		select {
		case <-c.done:
			return
		case err := <-answered:
			if err != nil {
				c.Close()
				return
			}
		case <-time.After(15 * time.Second):
			c.Close()
			return
		}
	}
}

// Alive reports whether the client is not closed.
func (c *Client) Alive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closed
}

// Close closes the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.done)
	c.mu.Unlock()
	return c.conn.Close()
}

// SetRoot tells the client whether the login user is root, who needs no
// sudo, as detected on the server.
func (c *Client) SetRoot(root bool) { c.root.Store(root) }

// Run runs cmd with sh as the login user.
func (c *Client) Run(ctx context.Context, cmd string) (remote.Result, error) {
	return c.exec(ctx, "sh -c "+remote.Quote(cmd), nil)
}

// RunPrivileged runs cmd with sh as root, through sudo unless the login user
// is root. sudo reads its password from the session's input, never from
// the command line.
func (c *Client) RunPrivileged(ctx context.Context, cmd string) (remote.Result, error) {
	if c.root.Load() {
		return c.Run(ctx, cmd)
	}
	// The script reads nothing: what sudo leaves of its input, the password
	// when it asks for none, never reaches the command.
	script := "sh -c " + remote.Quote("exec </dev/null; "+cmd)
	pw := c.cfg.sudoPassword()
	var res remote.Result
	var err error
	if pw == "" {
		res, err = c.exec(ctx, "sudo -n "+script, nil)
	} else {
		res, err = c.exec(ctx, "sudo -S -p '' "+script, strings.NewReader(pw+"\n"))
	}
	if err == nil && res.ExitCode != 0 {
		if msg, ok := sudoFailure(res.Stderr); ok {
			return res, fmt.Errorf("%w：%s", ErrSudo, msg)
		}
	}
	return res, err
}

// sudoFailure tells sudo's own errors apart from the command's.
func sudoFailure(stderr string) (string, bool) {
	s := strings.TrimSpace(stderr)
	for _, m := range []struct{ match, msg string }{
		{"a password is required", "该用户执行 sudo 需要密码，请在服务器设置中填写 sudo 密码"},
		{"incorrect password", "sudo 密码不正确"},
		{"no password was provided", "sudo 密码不正确"},
		{"is not in the sudoers file", "该用户没有 sudo 权限"},
		{"may not run sudo", "该用户没有 sudo 权限"},
		{"is not allowed to execute", "该用户无权以 root 执行此命令"},
		{"a terminal is required", "sudo 需要终端，请配置 sudo 密码或 NOPASSWD"},
		{"no tty present", "sudo 需要终端，请配置 sudo 密码或 NOPASSWD"},
		{"sudo: command not found", "服务器未安装 sudo，请使用 root 用户连接"},
		{"sudo: not found", "服务器未安装 sudo，请使用 root 用户连接"},
	} {
		if strings.Contains(s, m.match) {
			return m.msg, true
		}
	}
	return "", false
}

// start opens a session and starts cmd in it. Neither knows a context: on
// a connection gone silent they would wait until the system gives up on
// it, so when ctx ends first the client closes, which ends them.
func (c *Client) start(ctx context.Context, cmd string, stdout, stderr io.Writer, stdin io.Reader) (*ssh.Session, error) {
	type started struct {
		sess *ssh.Session
		err  error
	}
	ch := make(chan started, 1)
	go func() {
		sess, err := c.conn.NewSession()
		if err != nil {
			ch <- started{nil, fmt.Errorf("创建 SSH 会话失败：%w", err)}
			return
		}
		sess.Stdout, sess.Stderr, sess.Stdin = stdout, stderr, stdin
		if err := sess.Start(cmd); err != nil {
			sess.Close()
			ch <- started{nil, fmt.Errorf("执行命令失败：%w", err)}
			return
		}
		ch <- started{sess, nil}
	}()
	select {
	case s := <-ch:
		if s.err != nil && !c.Alive() {
			return nil, ErrClosed
		}
		return s.sess, s.err
	case <-ctx.Done():
		c.Close()
		go func() {
			if s := <-ch; s.sess != nil {
				s.sess.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// maxOutput bounds what a command's output keeps, against commands that
// print without end.
const maxOutput = 4 << 20

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := maxOutput - b.Len(); room < len(p) {
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

func (c *Client) exec(ctx context.Context, cmd string, stdin io.Reader) (remote.Result, error) {
	if !c.Alive() {
		return remote.Result{}, ErrClosed
	}
	var stdout, stderr limitedBuffer
	sess, err := c.start(ctx, cmd, &stdout, &stderr, stdin)
	if err != nil {
		return remote.Result{}, err
	}
	defer sess.Close()
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		sess.Signal(ssh.SIGKILL)
		sess.Close()
		return remote.Result{}, ctx.Err()
	}
	res := remote.Result{Stdout: stdout.String(), Stderr: stderr.String()}
	var exit *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		res.ExitCode = exit.ExitStatus()
	case errors.As(err, &missing):
		res.ExitCode = -1
	default:
		return res, err
	}
	return res, nil
}
