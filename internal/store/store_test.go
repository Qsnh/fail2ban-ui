package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rulelens/rulelens/internal/sshx"
)

func TestInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "servers.json")
	inv, err := Open(path)
	if err != nil || len(inv.List()) != 0 {
		t.Fatalf("new inventory: %v, %v", inv.List(), err)
	}
	a := Server{ID: NewID(), Name: "web-1", Host: "10.0.0.1", Port: 22, User: "ops", Auth: sshx.AuthPassword}
	b := Server{ID: NewID(), Host: "db.example.com", Port: 2222, User: "root", Auth: sshx.AuthKey, KeyPath: "~/.ssh/id_ed25519"}
	if err := inv.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := inv.Put(b); err != nil {
		t.Fatal(err)
	}
	a.Name = "web-01"
	if err := inv.Put(a); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("file %v, %v: want mode 0600", info, err)
	}

	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	list := again.List()
	if len(list) != 2 || list[0].Name != "web-01" || list[1].KeyPath != "~/.ssh/id_ed25519" {
		t.Errorf("reopened: %+v", list)
	}
	if got, ok := again.Get(b.ID); !ok || got.Title() != "db.example.com" || got.Address() != "root@db.example.com:2222" {
		t.Errorf("Get: %+v %v", got, ok)
	}
	if err := again.Delete(a.ID); err != nil {
		t.Fatal(err)
	}
	if again, _ = Open(path); len(again.List()) != 1 {
		t.Errorf("after delete: %+v", again.List())
	}

	os.WriteFile(path, []byte("{"), 0o600)
	if _, err := Open(path); err == nil {
		t.Error("no error for a broken file")
	}
}

func TestServerValidate(t *testing.T) {
	ok := Server{Host: "10.0.0.1", Port: 22, User: "ops", Auth: sshx.AuthPassword}
	if err := ok.Validate(); err != nil {
		t.Error(err)
	}
	for name, s := range map[string]Server{
		"host":      {Port: 22, User: "ops", Auth: sshx.AuthPassword},
		"bad host":  {Host: "a b;c", Port: 22, User: "ops", Auth: sshx.AuthPassword},
		"port":      {Host: "h", Port: 0, User: "ops", Auth: sshx.AuthPassword},
		"user":      {Host: "h", Port: 22, Auth: sshx.AuthPassword},
		"bad user":  {Host: "h", Port: 22, User: "a;b", Auth: sshx.AuthPassword},
		"key path":  {Host: "h", Port: 22, User: "ops", Auth: sshx.AuthKey},
		"auth kind": {Host: "h", Port: 22, User: "ops", Auth: "magic"},
	} {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: no error for %+v", name, s)
		}
	}
}

// fakeStore is a keychain of a map, or an unsupported one.
type fakeStore struct {
	m           map[string][]byte
	unsupported bool
}

var errNotFound = errors.New("not found")

func (f *fakeStore) Set(k string, v []byte) error {
	if f.unsupported {
		return errors.ErrUnsupported
	}
	f.m[k] = v
	return nil
}

func (f *fakeStore) Get(k string) ([]byte, error) {
	if f.unsupported {
		return nil, errors.ErrUnsupported
	}
	v, ok := f.m[k]
	if !ok {
		return nil, errNotFound
	}
	return v, nil
}

func (f *fakeStore) Delete(k string) error {
	if f.unsupported {
		return errors.ErrUnsupported
	}
	delete(f.m, k)
	return nil
}

func TestKeychainVault(t *testing.T) {
	fs := &fakeStore{m: map[string][]byte{}}
	v := NewKeychainVault(fs, errNotFound)
	if s, err := v.Get("x"); err != nil || s != (Secrets{}) {
		t.Errorf("missing: %+v, %v", s, err)
	}
	want := Secrets{Password: "p", SudoPassword: "s"}
	if err := v.Set("x", want); err != nil {
		t.Fatal(err)
	}
	if got, err := v.Get("x"); err != nil || got != want {
		t.Errorf("Get: %+v, %v", got, err)
	}
	if _, ok := fs.m["server:x"]; !ok || !v.Persistent() {
		t.Error("not in the keychain")
	}
	if err := v.Set("x", Secrets{}); err != nil || len(fs.m) != 0 {
		t.Errorf("empty secrets kept: %v %v", fs.m, err)
	}

	unsupported := NewKeychainVault(&fakeStore{unsupported: true}, errNotFound)
	if err := unsupported.Set("y", want); err != nil {
		t.Fatal(err)
	}
	if got, _ := unsupported.Get("y"); got != want || unsupported.Persistent() {
		t.Errorf("fallback: %+v, persistent %v", got, unsupported.Persistent())
	}
}

func TestSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	s, err := LoadSettings(path)
	if err != nil || s != DefaultSettings || s.RefreshEvery() != time.Minute {
		t.Fatalf("defaults: %+v, %v", s, err)
	}
	// Turning it off is kept, not taken for a missing setting.
	if err := SaveSettings(path, Settings{RefreshSeconds: 0}); err != nil {
		t.Fatal(err)
	}
	if s, err := LoadSettings(path); err != nil || s.RefreshSeconds != 0 || s.RefreshEvery() != 0 {
		t.Errorf("off: %+v, %v", s, err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, %v", fi.Mode(), err)
	}
	os.WriteFile(path, []byte("{"), 0o600)
	if s, err := LoadSettings(path); err == nil || s != DefaultSettings {
		t.Errorf("corrupt: %+v, %v", s, err)
	}
}
