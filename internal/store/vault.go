package store

import (
	"encoding/json"
	"errors"
	"sync"
)

// Vault keeps the secrets of servers.
type Vault interface {
	// Get returns the secrets of the server of id, empty when it has none.
	Get(id string) (Secrets, error)
	Set(id string, s Secrets) error
	Delete(id string) error
	// Persistent tells whether the secrets outlive the app's run.
	Persistent() bool
}

// SecretStore is a store of small secrets by key, as mygo.Secrets keeps
// them in the system's keychain.
type SecretStore interface {
	Set(key string, value []byte) error
	Get(key string) ([]byte, error)
	Delete(key string) error
}

// MemoryVault keeps secrets for the app's run only.
type MemoryVault struct {
	mu sync.Mutex
	m  map[string]Secrets
}

func (v *MemoryVault) Get(id string) (Secrets, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.m[id], nil
}

func (v *MemoryVault) Set(id string, s Secrets) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.m == nil {
		v.m = map[string]Secrets{}
	}
	v.m[id] = s
	return nil
}

func (v *MemoryVault) Delete(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.m, id)
	return nil
}

func (v *MemoryVault) Persistent() bool { return false }

// KeychainVault keeps secrets in a SecretStore, one entry of JSON for each
// server. Where the store is unsupported, as on Linux without a Secret
// Service, it keeps them in memory instead, for the app's run.
type KeychainVault struct {
	store    SecretStore
	notFound error
	fallback MemoryVault

	mu          sync.Mutex
	unsupported bool
}

// NewKeychainVault returns a vault in store, whose Get fails with notFound
// for keys it lacks.
func NewKeychainVault(store SecretStore, notFound error) *KeychainVault {
	return &KeychainVault{store: store, notFound: notFound}
}

func key(id string) string { return "server:" + id }

func (v *KeychainVault) useFallback(err error) bool {
	if !errors.Is(err, errors.ErrUnsupported) {
		return false
	}
	v.mu.Lock()
	v.unsupported = true
	v.mu.Unlock()
	return true
}

func (v *KeychainVault) Get(id string) (Secrets, error) {
	if !v.Persistent() {
		return v.fallback.Get(id)
	}
	data, err := v.store.Get(key(id))
	if v.notFound != nil && errors.Is(err, v.notFound) {
		return Secrets{}, nil
	}
	if v.useFallback(err) {
		return v.fallback.Get(id)
	}
	if err != nil {
		return Secrets{}, err
	}
	var s Secrets
	if err := json.Unmarshal(data, &s); err != nil {
		return Secrets{}, err
	}
	return s, nil
}

func (v *KeychainVault) Set(id string, s Secrets) error {
	if s == (Secrets{}) {
		return v.Delete(id)
	}
	if !v.Persistent() {
		return v.fallback.Set(id, s)
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	err = v.store.Set(key(id), data)
	if v.useFallback(err) {
		return v.fallback.Set(id, s)
	}
	return err
}

func (v *KeychainVault) Delete(id string) error {
	v.fallback.Delete(id)
	if !v.Persistent() {
		return nil
	}
	err := v.store.Delete(key(id))
	if v.notFound != nil && errors.Is(err, v.notFound) || v.useFallback(err) {
		return nil
	}
	return err
}

// Persistent reports whether the system's keychain keeps the secrets.
func (v *KeychainVault) Persistent() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return !v.unsupported
}
