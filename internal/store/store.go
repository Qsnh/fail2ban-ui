// Package store keeps the servers the app manages: their addresses in a
// JSON file, their passwords in a Vault.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/rulelens/rulelens/internal/sshx"
)

// Server is a server the app manages.
type Server struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Host string          `json:"host"`
	Port int             `json:"port"`
	User string          `json:"user"`
	Auth sshx.AuthMethod `json:"auth"`
	// KeyPath is the private key file of sshx.AuthKey.
	KeyPath string `json:"keyPath,omitempty"`
	// Group gathers servers in the sidebar, as "生产" or "测试".
	Group string `json:"group,omitempty"`
	Note  string `json:"note,omitempty"`
}

// Title is the server's name, or its address without one.
func (s Server) Title() string {
	if s.Name != "" {
		return s.Name
	}
	return s.Host
}

// Address is user@host:port, as people write it.
func (s Server) Address() string {
	addr := s.Host
	if s.Port != 0 && s.Port != 22 {
		addr = net.JoinHostPort(s.Host, fmt.Sprint(s.Port))
	}
	return s.User + "@" + addr
}

var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$`)

// Validate checks the server's fields, with an error that says what to fix.
func (s Server) Validate() error {
	host := strings.TrimSpace(s.Host)
	switch {
	case host == "":
		return errors.New("请填写主机地址")
	case net.ParseIP(host) == nil && !hostRE.MatchString(host):
		return fmt.Errorf("主机地址 %q 无效", host)
	case s.Port < 1 || s.Port > 65535:
		return errors.New("端口须在 1–65535 之间")
	case strings.TrimSpace(s.User) == "":
		return errors.New("请填写登录用户名")
	case strings.ContainsAny(s.User, " \t'\"`$;&|<>\\"):
		return errors.New("用户名包含无效字符")
	}
	switch s.Auth {
	case sshx.AuthPassword, sshx.AuthAgent:
	case sshx.AuthKey:
		if strings.TrimSpace(s.KeyPath) == "" {
			return errors.New("请填写私钥文件路径")
		}
	default:
		return fmt.Errorf("未知的认证方式 %q", s.Auth)
	}
	return nil
}

// Secrets are the passwords of a server, which the Vault keeps.
type Secrets struct {
	Password     string `json:"password,omitempty"`
	Passphrase   string `json:"passphrase,omitempty"`
	SudoPassword string `json:"sudoPassword,omitempty"`
}

// NewID returns a new random server ID.
func NewID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Inventory is the list of servers, saved to a JSON file as it changes.
type Inventory struct {
	path    string
	mu      sync.Mutex
	servers []Server
}

type inventoryFile struct {
	Version int      `json:"version"`
	Servers []Server `json:"servers"`
}

// Open reads the inventory of path, empty when the file does not exist.
func Open(path string) (*Inventory, error) {
	inv := &Inventory{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return inv, nil
	}
	if err != nil {
		return nil, err
	}
	var f inventoryFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("服务器清单 %s 已损坏：%w", path, err)
	}
	inv.servers = f.Servers
	return inv, nil
}

// List returns the servers, in the order they were added.
func (inv *Inventory) List() []Server {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	return slices.Clone(inv.servers)
}

// Get returns the server of id.
func (inv *Inventory) Get(id string) (Server, bool) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	i := slices.IndexFunc(inv.servers, func(s Server) bool { return s.ID == id })
	if i < 0 {
		return Server{}, false
	}
	return inv.servers[i], true
}

// Put adds the server, or replaces the one of its ID, and saves.
func (inv *Inventory) Put(s Server) error {
	if s.ID == "" {
		return errors.New("server without an ID")
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	servers := slices.Clone(inv.servers)
	if i := slices.IndexFunc(servers, func(o Server) bool { return o.ID == s.ID }); i >= 0 {
		servers[i] = s
	} else {
		servers = append(servers, s)
	}
	if err := inv.save(servers); err != nil {
		return err
	}
	inv.servers = servers
	return nil
}

// Delete removes the server of id and saves.
func (inv *Inventory) Delete(id string) error {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	servers := slices.DeleteFunc(slices.Clone(inv.servers), func(s Server) bool { return s.ID == id })
	if err := inv.save(servers); err != nil {
		return err
	}
	inv.servers = servers
	return nil
}

// save writes the inventory's file.
func (inv *Inventory) save(servers []Server) error {
	if inv.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(inventoryFile{Version: 1, Servers: servers}, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(inv.path, data)
}

// writeFile writes the file whole and renames it into place, so that a
// crash leaves the old file or the new one, never half of one.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+strings.TrimSuffix(filepath.Base(path), ".json")+"-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
