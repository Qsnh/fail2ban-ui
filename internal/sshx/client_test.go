package sshx

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// handler answers a command of the test server, with its exit status.
type handler func(cmd string, stdin io.Reader, stdout, stderr io.Writer) int

// startServer starts an SSH server on localhost that takes the password
// "secret" for user "ops" and answers commands with h.
func startServer(t *testing.T, h handler) (addr string, key ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return startServerWith(t, h, signer), signer.PublicKey()
}

// startServerWith starts a server of the host keys of signers.
func startServerWith(t *testing.T, h handler, signers ...ssh.Signer) string {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == "ops" && string(pw) == "secret" {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	for _, signer := range signers {
		cfg.AddHostKey(signer)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(conn, cfg, h)
		}
	}()
	return ln.Addr().String()
}

func serve(conn net.Conn, cfg *ssh.ServerConfig, h handler) {
	_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range chReqs {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				n := binary.BigEndian.Uint32(req.Payload)
				cmd := string(req.Payload[4 : 4+n])
				req.Reply(true, nil)
				status := h(cmd, ch, ch, ch.Stderr())
				ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, uint32(status)))
				return
			}
		}()
	}
}

func split(addr string) (string, int) {
	host, port, _ := net.SplitHostPort(addr)
	var p int
	fmt.Sscan(port, &p)
	return host, p
}

func TestHostKeyTrustOnFirstUse(t *testing.T) {
	addr, key := startServer(t, func(cmd string, _ io.Reader, out, _ io.Writer) int {
		fmt.Fprint(out, "hello")
		return 0
	})
	host, port := split(addr)
	hk := NewHostKeys(filepath.Join(t.TempDir(), "known_hosts"))
	cfg := Config{Host: host, Port: port, User: "ops", Auth: AuthPassword, Password: "secret", HostKeys: hk, Timeout: 5 * time.Second}

	_, err := Dial(context.Background(), cfg)
	var unknown *UnknownHostError
	if !errors.As(err, &unknown) {
		t.Fatalf("first connection: %v, want UnknownHostError", err)
	}
	if Fingerprint(unknown.Key) != Fingerprint(key) {
		t.Errorf("fingerprint %s, want %s", Fingerprint(unknown.Key), Fingerprint(key))
	}
	if err := hk.Trust(unknown.Hostport, unknown.Key); err != nil {
		t.Fatal(err)
	}
	c, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatalf("after trusting: %v", err)
	}
	defer c.Close()
	res, err := c.Run(context.Background(), "echo hello")
	if err != nil || res.Stdout != "hello" {
		t.Errorf("Run: %+v, %v", res, err)
	}

	// Another server answering at the same address has another key.
	other := NewHostKeys(hk.path)
	addr2, _ := startServer(t, func(string, io.Reader, io.Writer, io.Writer) int { return 0 })
	_, port2 := split(addr2)
	// Record the first key for the second port, then connect to it.
	if err := other.Trust(net.JoinHostPort(host, fmt.Sprint(port2)), key); err != nil {
		t.Fatal(err)
	}
	cfg.Port = port2
	_, err = Dial(context.Background(), cfg)
	var changed *HostKeyChangedError
	if !errors.As(err, &changed) {
		t.Errorf("changed key: %v, want HostKeyChangedError", err)
	}
}

func trusted(t *testing.T, addr string, key ssh.PublicKey) *HostKeys {
	hk := NewHostKeys(filepath.Join(t.TempDir(), "known_hosts"))
	if err := hk.Trust(addr, key); err != nil {
		t.Fatal(err)
	}
	return hk
}

func TestAuthFailure(t *testing.T) {
	addr, key := startServer(t, func(string, io.Reader, io.Writer, io.Writer) int { return 0 })
	host, port := split(addr)
	_, err := Dial(context.Background(), Config{Host: host, Port: port, User: "ops", Password: "wrong", HostKeys: trusted(t, addr, key)})
	if !errors.Is(err, ErrAuth) {
		t.Errorf("wrong password: %v, want ErrAuth", err)
	}
}

func TestRunPrivileged(t *testing.T) {
	var got []string
	addr, key := startServer(t, func(cmd string, stdin io.Reader, out, errOut io.Writer) int {
		got = append(got, cmd)
		switch {
		case strings.HasPrefix(cmd, "sudo -S -p '' "):
			pw, _ := bufio.NewReader(stdin).ReadString('\n')
			if pw != "secret\n" {
				fmt.Fprint(errOut, "sudo: 1 incorrect password attempt\n")
				return 1
			}
			fmt.Fprint(out, "as root")
			return 0
		case strings.HasPrefix(cmd, "sudo -n "):
			fmt.Fprint(errOut, "sudo: a password is required\n")
			return 1
		case strings.Contains(cmd, "exit 3"):
			fmt.Fprint(errOut, "failed")
			return 3
		}
		return 0
	})
	host, port := split(addr)
	cfg := Config{Host: host, Port: port, User: "ops", Password: "secret", HostKeys: trusted(t, addr, key)}
	c, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	res, err := c.RunPrivileged(context.Background(), "fail2ban-client status")
	if err != nil || res.Stdout != "as root" {
		t.Errorf("sudo with the login password: %+v, %v", res, err)
	}
	if want := `sudo -S -p '' sh -c 'exec </dev/null; fail2ban-client status'`; got[len(got)-1] != want {
		t.Errorf("command %q, want %q (no password on the command line)", got[len(got)-1], want)
	}

	res, err = c.Run(context.Background(), "exit 3")
	if err != nil || res.ExitCode != 3 || res.Stderr != "failed" {
		t.Errorf("exit status: %+v, %v", res, err)
	}

	c.cfg.SudoPassword = "nope"
	if _, err := c.RunPrivileged(context.Background(), "fail2ban-client status"); !errors.Is(err, ErrSudo) {
		t.Errorf("wrong sudo password: %v, want ErrSudo", err)
	}

	c.SetRoot(true)
	c.Run(context.Background(), "id")
	if _, err := c.RunPrivileged(context.Background(), "id"); err != nil || strings.HasPrefix(got[len(got)-1], "sudo") {
		t.Errorf("root ran %q, %v", got[len(got)-1], err)
	}
}

func TestRunCanceled(t *testing.T) {
	release := make(chan struct{})
	addr, key := startServer(t, func(string, io.Reader, io.Writer, io.Writer) int {
		<-release
		return 0
	})
	defer close(release)
	host, port := split(addr)
	c, err := Dial(context.Background(), Config{Host: host, Port: port, User: "ops", Password: "secret", HostKeys: trusted(t, addr, key)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.Run(ctx, "sleep 100"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err %v, want the deadline", err)
	}
}

func TestDialUnreachable(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	host, port := split(addr)
	_, err := Dial(context.Background(), Config{Host: host, Port: port, User: "ops", Password: "x",
		HostKeys: NewHostKeys(filepath.Join(t.TempDir(), "kh")), Timeout: 2 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "无法连接") {
		t.Errorf("err %v", err)
	}
}

// A server known by its ed25519 key alone is not taken for another when it
// also has an ECDSA key, which clients prefer.
func TestKnownByAnotherKind(t *testing.T) {
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	ed, _ := ssh.NewSignerFromKey(edPriv)
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, _ := ssh.NewSignerFromKey(ecPriv)
	addr := startServerWith(t, func(string, io.Reader, io.Writer, io.Writer) int { return 0 }, ec, ed)
	host, port := split(addr)
	dir := t.TempDir()
	// The user's own known_hosts holds the ed25519 key, and a line of a
	// kind of key knownhosts does not read, which must not fail it all.
	user := filepath.Join(dir, "user_known_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey())
	os.WriteFile(user, []byte("example.com ssh-unknown AAAA\n"+line+"\n"), 0o600)
	hk := NewHostKeys(filepath.Join(dir, "known_hosts"), user)
	if got := hk.Algorithms(addr); len(got) != 1 || got[0] != ssh.KeyAlgoED25519 {
		t.Errorf("Algorithms %q", got)
	}
	c, err := Dial(context.Background(), Config{Host: host, Port: port, User: "ops", Password: "secret", HostKeys: hk})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	c.Close()
}
