package fail2ban

import (
	"slices"
	"strings"
)

// JailDir is the directory of the jails' configuration, where RuleLens
// writes a file of settings for each jail it creates or changes.
const JailDir = "/etc/fail2ban/jail.d"

// fail2ban reads the .local files of jail.d last, after jail.local, in the
// order of their names: those of RuleLens, "zz-" first, come after the
// others, and their settings win.
const (
	filePrefix = "zz-rulelens-"
	fileSuffix = ".local"
)

// OverridePath is the file of RuleLens's settings for a jail.
func OverridePath(jail string) string {
	return JailDir + "/" + filePrefix + jail + fileSuffix
}

// overrideJail returns the jail of a file of RuleLens, by its name.
func overrideJail(file string) (string, bool) {
	name, ok := strings.CutPrefix(file, filePrefix)
	if !ok {
		return "", false
	}
	return strings.CutSuffix(name, fileSuffix)
}

// Config is the configuration of the jails on a server, as far as RuleLens
// manages them.
type Config struct {
	// Read reports whether the configuration was read, Problem why not in
	// full.
	Read    bool
	Problem string
	// Filters are the names of the filters of filter.d.
	Filters []string
	// Jails are the jails configured, enabled or not, by name.
	Jails map[string]bool
	// Overrides are the files of RuleLens, by jail.
	Overrides map[string]*Override
}

// Jail returns the jail running of that name.
func (s *Status) Jail(name string) (Jail, bool) {
	i := slices.IndexFunc(s.Jails, func(j Jail) bool { return j.Name == name })
	if i < 0 {
		return Jail{}, false
	}
	return s.Jails[i], true
}

// Stopped lists the jails RuleLens disabled, which fail2ban runs no more.
func (s *Status) Stopped() []string {
	var out []string
	for name, o := range s.Config.Overrides {
		if _, running := s.Jail(name); !running && o.Disabled() {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// Presets lists the jails configured but not enabled, as most of those
// jail.conf ships: enabling one takes the settings configured.
func (s *Status) Presets() []string {
	var out []string
	for name, enabled := range s.Config.Jails {
		if _, running := s.Jail(name); running || enabled || s.Config.Overrides[name] != nil {
			continue
		}
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// Override is RuleLens's file of settings for a jail: its section, whose
// settings fail2ban takes over those of the other files.
type Override struct {
	Jail string
	// Created marks a jail RuleLens created, or enabled of those
	// configured: without the file, it runs no more. The file of any other
	// jail only changes its settings.
	Created  bool
	Settings []Setting
}

// Setting is an option of a jail, as "maxretry = 5". Values of several
// lines, as of logpath, hold newlines.
type Setting struct {
	Key, Value string
}

// Get returns the value of a setting, and whether the file sets it.
func (o *Override) Get(key string) (string, bool) {
	if o == nil {
		return "", false
	}
	i := slices.IndexFunc(o.Settings, func(s Setting) bool { return s.Key == key })
	if i < 0 {
		return "", false
	}
	return o.Settings[i].Value, true
}

// Has reports whether the file sets key.
func (o *Override) Has(key string) bool {
	_, ok := o.Get(key)
	return ok
}

// Set sets a setting, in its place when the file has it already.
func (o *Override) Set(key, value string) {
	i := slices.IndexFunc(o.Settings, func(s Setting) bool { return s.Key == key })
	if i < 0 {
		o.Settings = append(o.Settings, Setting{key, value})
		return
	}
	o.Settings[i].Value = value
}

// Unset leaves a setting to the other files.
func (o *Override) Unset(key string) {
	o.Settings = slices.DeleteFunc(o.Settings, func(s Setting) bool { return s.Key == key })
}

// Bool reports whether a setting of the file is true.
func (o *Override) Bool(key string) bool {
	v, _ := o.Get(key)
	return truthy(v)
}

// Disabled reports whether the file disables the jail.
func (o *Override) Disabled() bool {
	return o.Has("enabled") && !o.Bool("enabled")
}

// Clone returns a copy of the file, nil for nil.
func (o *Override) Clone() *Override {
	if o == nil {
		return nil
	}
	c := *o
	c.Settings = slices.Clone(o.Settings)
	return &c
}

// Equal reports whether two files say the same.
func (o *Override) Equal(p *Override) bool {
	if o == nil || p == nil {
		return o == p
	}
	return o.Jail == p.Jail && o.Created == p.Created && slices.Equal(o.Settings, p.Settings)
}

// createdMark marks the file of a jail RuleLens created.
const createdMark = "# rulelens: created"

// Render writes the file, in ASCII, whatever the locale of fail2ban.
func (o *Override) Render() string {
	var b strings.Builder
	b.WriteString("# Managed by RuleLens: change this jail in RuleLens, or delete this file\n")
	b.WriteString("# and run \"fail2ban-client reload\" to undo these settings.\n")
	if o.Created {
		b.WriteString(createdMark + "\n")
	}
	b.WriteString("[" + o.Jail + "]\n")
	for _, s := range o.Settings {
		// The lines after the first continue the value, indented.
		indent := "\n" + strings.Repeat(" ", len(s.Key)+3)
		b.WriteString(s.Key + " = " + strings.ReplaceAll(s.Value, "\n", indent) + "\n")
	}
	return b.String()
}

// ParseOverride reads a file of RuleLens's settings for jail: the settings
// of its section, as Render writes them or as edited by hand.
func ParseOverride(jail, text string) *Override {
	o := &Override{Jail: jail}
	section := ""
	last := -1
	for line := range strings.Lines(text) {
		line = strings.TrimRight(line, " \t\r\n")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == createdMark:
			o.Created = true
			continue
		case trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";"):
			continue
		case strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"):
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			last = -1
			continue
		}
		if section != jail {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// The value of the setting above goes on.
			if last >= 0 {
				o.Settings[last].Value += "\n" + trimmed
			}
			continue
		}
		i := strings.IndexAny(line, "=:")
		if i < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:i]))
		o.Set(key, strings.TrimSpace(line[i+1:]))
		last = slices.IndexFunc(o.Settings, func(s Setting) bool { return s.Key == key })
	}
	return o
}

// truthy reads a boolean of fail2ban's configuration.
func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "on", "1":
		return true
	}
	return false
}
