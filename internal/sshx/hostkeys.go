package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeys verifies the keys of servers against known_hosts files: the
// app's own, where Trust writes, and others it only reads, as the user's
// ~/.ssh/known_hosts. A server is trusted on first use only once the user
// accepted its key: an unknown key fails with an *UnknownHostError, which
// carries the key to show and Trust.
type HostKeys struct {
	path  string
	extra []string
	mu    sync.Mutex
}

// NewHostKeys returns host keys kept in path, which also reads the keys of
// the extra files that exist.
func NewHostKeys(path string, extra ...string) *HostKeys {
	return &HostKeys{path: path, extra: extra}
}

// UserKnownHosts returns the path of the user's ~/.ssh/known_hosts, or ""
// when there is no home directory.
func UserKnownHosts() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

// UnknownHostError is a server whose key no known_hosts file holds.
type UnknownHostError struct {
	Hostport string
	Key      ssh.PublicKey
}

func (e *UnknownHostError) Error() string {
	return fmt.Sprintf("首次连接 %s，需要确认主机指纹 %s", e.Hostport, Fingerprint(e.Key))
}

// HostKeyChangedError is a server whose key is not the one known for it:
// it was reinstalled, or someone is in the middle of the connection.
type HostKeyChangedError struct {
	Hostport string
	Key      ssh.PublicKey
	// Known is where the known key is: "file:line".
	Known string
}

func (e *HostKeyChangedError) Error() string {
	return fmt.Sprintf("警告：%s 的主机指纹已变化（现为 %s，记录于 %s）。可能存在中间人攻击；若服务器确实重装过，请在确认后删除旧记录。",
		e.Hostport, Fingerprint(e.Key), e.Known)
}

// Fingerprint returns the SHA-256 fingerprint of a key, as ssh-keygen -l
// shows it, after its type.
func Fingerprint(key ssh.PublicKey) string {
	if key == nil {
		return ""
	}
	return key.Type() + " " + ssh.FingerprintSHA256(key)
}

// known returns the callback of the known_hosts files, nil when there are
// none. The lines of the user's files that knownhosts cannot read, as those
// of a kind of key it does not know, are left out rather than failing every
// connection; the app's own file must read whole.
func (h *HostKeys) known() (ssh.HostKeyCallback, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var files []string
	if _, err := os.Stat(h.path); err == nil {
		files = append(files, h.path)
	}
	for _, f := range h.extra {
		data, err := os.ReadFile(f)
		if f == "" || err != nil {
			continue
		}
		readable := readableLines(data)
		// knownhosts reads files by path, at once: give it a copy of the
		// lines it reads.
		tmp, err := os.CreateTemp("", "rulelens-known-hosts-*")
		if err != nil {
			continue
		}
		defer os.Remove(tmp.Name())
		_, err = tmp.Write(readable)
		if tmp.Close() == nil && err == nil {
			files = append(files, tmp.Name())
		}
	}
	if len(files) == 0 {
		return nil, nil
	}
	cb, err := knownhosts.New(files...)
	if err != nil {
		return nil, fmt.Errorf("读取 known_hosts 失败：%w", err)
	}
	return cb, nil
}

// readableLines returns the lines of a known_hosts file that parse.
func readableLines(data []byte) []byte {
	var out []byte
	for line := range strings.Lines(string(data)) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if _, _, _, _, _, err := ssh.ParseKnownHosts([]byte(trimmed)); err == nil {
			out = append(out, trimmed+"\n"...)
		}
	}
	return out
}

var (
	probeOnce sync.Once
	probeKey  ssh.PublicKey
)

// Algorithms returns the host key algorithms of the keys the known_hosts
// files hold for hostport, to ask the server for those, or nil when they
// hold none.
func (h *HostKeys) Algorithms(hostport string) []string {
	known, err := h.known()
	if known == nil || err != nil {
		return nil
	}
	probeOnce.Do(func() {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return
		}
		if signer, err := ssh.NewSignerFromKey(priv); err == nil {
			probeKey = signer.PublicKey()
		}
	})
	if probeKey == nil {
		return nil
	}
	// A key no file holds fails with the keys they hold for the host.
	var keyErr *knownhosts.KeyError
	if !errors.As(known(hostport, &net.TCPAddr{IP: net.IPv4zero}, probeKey), &keyErr) {
		return nil
	}
	var algos []string
	add := func(a ...string) {
		for _, x := range a {
			if !slices.Contains(algos, x) {
				algos = append(algos, x)
			}
		}
	}
	for _, k := range keyErr.Want {
		switch t := k.Key.Type(); t {
		case ssh.KeyAlgoRSA:
			add(ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA)
		default:
			add(t)
		}
	}
	return algos
}

// Callback returns the callback that checks a server's key.
func (h *HostKeys) Callback() (ssh.HostKeyCallback, error) {
	known, err := h.known()
	if err != nil {
		return nil, err
	}
	return func(hostport string, remote net.Addr, key ssh.PublicKey) error {
		if known == nil {
			return &UnknownHostError{Hostport: hostport, Key: key}
		}
		err := known(hostport, remote, key)
		var keyErr *knownhosts.KeyError
		var revoked *knownhosts.RevokedError
		switch {
		case err == nil:
			return nil
		case errors.As(err, &keyErr) && len(keyErr.Want) == 0:
			return &UnknownHostError{Hostport: hostport, Key: key}
		case errors.As(err, &keyErr):
			w := keyErr.Want[0]
			return &HostKeyChangedError{Hostport: hostport, Key: key, Known: fmt.Sprintf("%s:%d", w.Filename, w.Line)}
		case errors.As(err, &revoked):
			return fmt.Errorf("主机密钥已被吊销（%s）", revoked.Revoked.String())
		}
		return err
	}, nil
}

// Trust records key as the key of the server at hostport, in the app's
// known_hosts file.
func (h *HostKeys) Trust(hostport string, key ssh.PublicKey) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(h.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(h.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	line := knownhosts.Line([]string{knownhosts.Normalize(hostport)}, key)
	if _, err := f.WriteString(strings.TrimSpace(line) + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
