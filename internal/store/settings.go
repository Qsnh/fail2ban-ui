package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Settings are the app's preferences.
type Settings struct {
	// RefreshSeconds is how often fail2ban is read again on the servers
	// connected; 0 never.
	RefreshSeconds int `json:"refreshSeconds"`
}

// DefaultSettings are the settings until the user changes them.
var DefaultSettings = Settings{RefreshSeconds: 60}

// RefreshEvery is how often fail2ban is read again, 0 for never.
func (s Settings) RefreshEvery() time.Duration {
	return time.Duration(max(s.RefreshSeconds, 0)) * time.Second
}

// LoadSettings reads the settings of path: the defaults when the file does
// not exist, and for what it does not set.
func LoadSettings(path string) (Settings, error) {
	s := DefaultSettings
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return DefaultSettings, fmt.Errorf("设置文件 %s 已损坏：%w", path, err)
	}
	return s, nil
}

// SaveSettings writes the settings to path.
func SaveSettings(path string, s Settings) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, data)
}
