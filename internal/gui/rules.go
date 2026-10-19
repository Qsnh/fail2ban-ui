package gui

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/egoist/mygo/ui"

	"github.com/rulelens/rulelens/internal/fail2ban"
	"github.com/rulelens/rulelens/internal/remote"
)

// The sources of a jail's failures, in the order of the form's segments.
const (
	sourceFiles = iota
	sourceJournal
)

// ruleFields are the settings of a jail as the rule form edits them. An
// empty one leaves the setting to the configuration.
type ruleFields struct {
	filter, port       string
	source             int
	logpath            string
	maxRetry, findTime string
	banTime            string
	permanent          bool
	increment          bool
	maxTime            string
	ignoreIP           string
}

// jailFields returns the settings of a jail running.
func jailFields(j fail2ban.Jail) ruleFields {
	f := ruleFields{
		logpath:   strings.Join(j.LogPaths, " "),
		maxRetry:  strconv.Itoa(j.MaxRetry),
		findTime:  fail2ban.FormatTime(j.FindTime),
		permanent: j.Permanent(),
		increment: j.BanIncrement,
		ignoreIP:  strings.Join(j.IgnoreIP, " "),
	}
	if len(j.Actions) > 0 {
		f.port = j.Actions[0].Port
	}
	if j.Journal {
		f.source = sourceJournal
	}
	if !f.permanent {
		f.banTime = fail2ban.FormatTime(j.BanTime)
	}
	if j.BanMaxTime > 0 {
		f.maxTime = fail2ban.FormatTime(j.BanMaxTime)
	}
	return f
}

// take puts the settings of RuleLens's file over the fields, as written.
func (f *ruleFields) take(o *fail2ban.Override) {
	if o == nil {
		return
	}
	for _, s := range o.Settings {
		v := strings.Join(strings.Fields(s.Value), " ")
		switch s.Key {
		case "filter":
			f.filter = v
		case "port":
			f.port = v
		case "logpath":
			f.logpath = v
		case "backend":
			f.source = sourceFiles
			if strings.HasPrefix(v, "systemd") {
				f.source = sourceJournal
			}
		case "maxretry":
			f.maxRetry = v
		case "findtime":
			f.findTime = v
		case "bantime":
			f.permanent, f.banTime = strings.HasPrefix(v, "-"), v
			if f.permanent {
				f.banTime = ""
			}
		case "bantime.increment":
			f.increment = o.Bool(s.Key)
		case "bantime.maxtime":
			f.maxTime = v
		case "ignoreip":
			f.ignoreIP = v
		}
	}
}

// ruleForm is the dialog creating a jail, or changing one.
type ruleForm struct {
	open bool
	// seq tells the dialogs apart; server is the ID of the server, and
	// editing the jail changed, "" for a new one, which name names.
	seq             int
	server, editing string
	name            string
	ruleFields
	// orig are the fields as the dialog opened, and base RuleLens's file
	// of the jail then.
	orig ruleFields
	base *fail2ban.Override
	// applying tells the change runs, err why it or the last failed.
	applying bool
	err      string
}

// newRule opens the dialog creating a jail on the server.
func (a *App) newRule(sv *serverView) {
	a.ruleSeq++
	a.ruleForm = ruleForm{open: true, seq: a.ruleSeq, server: sv.srv.ID}
}

// editRule opens the dialog changing a jail: running, or stopped by
// RuleLens.
func (a *App) editRule(sv *serverView, name string) {
	s := sv.running()
	if s == nil {
		return
	}
	var fl ruleFields
	if j, ok := s.Jail(name); ok {
		fl = jailFields(j)
	}
	o := s.Config.Overrides[name]
	fl.take(o)
	a.ruleSeq++
	a.ruleForm = ruleForm{open: true, seq: a.ruleSeq, server: sv.srv.ID, editing: name, name: name, ruleFields: fl, orig: fl, base: o.Clone()}
}

// override returns RuleLens's file of the jail as the form says, checked
// against fail2ban on the server: the settings changed are written, and
// those the file had kept.
func (f *ruleForm) override(s *fail2ban.Status) (*fail2ban.Override, error) {
	isNew := f.editing == ""
	name := f.editing
	if isNew {
		name = strings.TrimSpace(f.name)
	}
	if err := fail2ban.ValidJailName(name); err != nil {
		return nil, err
	}
	o := f.base.Clone()
	_, preset := s.Config.Jails[name]
	if isNew {
		if _, ok := s.Jail(name); ok {
			return nil, fmt.Errorf("规则 %s 已存在，可在列表中选中它后编辑", name)
		}
		if slices.Contains(s.Stopped(), name) {
			return nil, fmt.Errorf("规则 %s 已停用，可在列表中选中它后启用", name)
		}
		o = s.Config.Overrides[name].Clone()
		if o == nil {
			o = &fail2ban.Override{Jail: name}
		}
		o.Created = true
		o.Set("enabled", "true")
	} else if o == nil {
		o = &fail2ban.Override{Jail: name}
	}
	cur, was := f.ruleFields, f.orig
	// What the server had passes as it was: only what was typed is checked.
	typed := func(cur, was string) bool { return strings.TrimSpace(cur) != strings.TrimSpace(was) }
	// set writes a setting changed, or one the file has: empty, it leaves
	// it to the configuration.
	set := func(key, value, orig string) {
		switch {
		case value == orig && !o.Has(key):
		case value == "":
			o.Unset(key)
		default:
			o.Set(key, value)
		}
	}

	filter := strings.TrimSpace(cur.filter)
	// A jail of its own takes the filter of its name unless told.
	if filter != "" && typed(cur.filter, was.filter) || isNew && !preset {
		base := name
		if filter != "" {
			var err error
			if base, err = fail2ban.ValidFilter(filter); err != nil {
				return nil, err
			}
		}
		if len(s.Config.Filters) > 0 && !slices.Contains(s.Config.Filters, base) {
			if filter == "" {
				return nil, fmt.Errorf("服务器上没有名为 %s 的过滤器，请填写过滤器", base)
			}
			return nil, fmt.Errorf("服务器上没有过滤器 %s（/etc/fail2ban/filter.d/%s.conf）", base, base)
		}
	}
	set("filter", filter, strings.TrimSpace(was.filter))

	port, wasPort := strings.Join(strings.Fields(cur.port), ""), strings.Join(strings.Fields(was.port), "")
	if port != "" && port != wasPort {
		if err := fail2ban.ValidPort(port); err != nil {
			return nil, err
		}
	}
	set("port", port, wasPort)

	logpath, wasLogpath := strings.Join(strings.Fields(cur.logpath), "\n"), strings.Join(strings.Fields(was.logpath), "\n")
	if logpath != wasLogpath {
		for _, p := range strings.Fields(cur.logpath) {
			if err := fail2ban.ValidLogPath(p); err != nil {
				return nil, err
			}
		}
	}
	switched := !isNew && cur.source != was.source
	switch {
	case cur.source == sourceJournal:
		if isNew || switched {
			o.Set("backend", "systemd")
			o.Unset("logpath")
		}
	case logpath == "" && (switched || isNew && !preset):
		return nil, errors.New("请填写日志文件路径")
	case isNew || switched:
		if logpath != "" {
			o.Set("logpath", logpath)
			// The default may read the journal, as on Debian.
			o.Set("backend", "auto")
		}
	default:
		set("logpath", logpath, wasLogpath)
	}

	maxRetry := strings.TrimSpace(cur.maxRetry)
	if maxRetry != "" && typed(cur.maxRetry, was.maxRetry) {
		if n, err := strconv.Atoi(maxRetry); err != nil || n < 1 {
			return nil, fmt.Errorf("失败次数 %q 应为正整数", maxRetry)
		}
	}
	set("maxretry", maxRetry, strings.TrimSpace(was.maxRetry))

	// times checks a time typed, and writes the time of a field and the
	// one it had as the file has them.
	times := func(what, cur, was string) (string, string, error) {
		if !typed(cur, was) {
			return normalTime(was), normalTime(was), nil
		}
		v, err := timeSetting(what, cur)
		return v, normalTime(was), err
	}
	findTime, wasFind, err := times("统计时长", cur.findTime, was.findTime)
	if err != nil {
		return nil, err
	}
	set("findtime", findTime, wasFind)

	banTime, wasBan := "-1", "-1"
	if !was.permanent {
		wasBan = normalTime(was.banTime)
	}
	if !cur.permanent {
		if banTime, _, err = times("封禁时长", cur.banTime, was.banTime); err != nil {
			return nil, err
		}
	}
	set("bantime", banTime, wasBan)

	set("bantime.increment", strconv.FormatBool(cur.increment), strconv.FormatBool(was.increment))
	if cur.increment {
		maxTime, wasMax, err := times("最长封禁时长", cur.maxTime, was.maxTime)
		if err != nil {
			return nil, err
		}
		set("bantime.maxtime", maxTime, wasMax)
	}

	var ips []string
	for _, ip := range strings.Fields(cur.ignoreIP) {
		if !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	}
	wasIPs := strings.Join(strings.Fields(was.ignoreIP), " ")
	if strings.Join(ips, " ") != wasIPs {
		for _, ip := range ips {
			if err := fail2ban.ValidAddress(ip); err != nil {
				return nil, fmt.Errorf("忽略 IP：%w", err)
			}
		}
	}
	set("ignoreip", strings.Join(ips, " "), wasIPs)
	return o, nil
}

// changed reports whether o says other than the file did.
func (f *ruleForm) changed(o *fail2ban.Override) bool {
	if f.base == nil {
		return o.Created || len(o.Settings) > 0
	}
	return !o.Equal(f.base)
}

// timeSetting checks a time of the form, and writes it as the file has
// it: "" for none.
func timeSetting(what, s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "", nil
	}
	d, err := fail2ban.ParseTime(s)
	if err != nil {
		return "", fmt.Errorf("%s：%w", what, err)
	}
	if d <= 0 {
		return "", fmt.Errorf("%s应大于 0", what)
	}
	return fail2ban.FormatTime(d), nil
}

// normalTime writes a time as timeSetting does, or as it is when it is not
// one.
func normalTime(s string) string {
	if v, err := timeSetting("", s); err == nil {
		return v
	}
	return strings.TrimSpace(s)
}

// change is the change writing o, or removing the file when nothing is
// left of it.
func change(o *fail2ban.Override) fail2ban.Change {
	ch := fail2ban.Change{Jail: o.Jail, Override: o}
	if len(o.Settings) == 0 && !o.Created {
		ch.Override = nil
	}
	return ch
}

// changeRule makes a change of a jail's configuration on the server.
func (a *App) changeRule(sv *serverView, ch fail2ban.Change, label, done string, after func(error)) {
	a.run(sv, job{
		label: label,
		done:  done,
		work: func(ctx context.Context, x remote.Executor) error {
			return fail2ban.Apply(ctx, x, ch)
		},
		after: after,
	})
}

// saveRule applies the dialog's change, which stays open until fail2ban
// took it, telling why it did not.
func (a *App) saveRule() {
	f := &a.ruleForm
	sv := a.views[f.server]
	if sv == nil || sv.running() == nil || f.applying {
		return
	}
	s := sv.running()
	o, err := f.override(s)
	if err != nil {
		f.err = err.Error()
		return
	}
	if !f.changed(o) {
		f.err = "没有修改"
		return
	}
	f.applying, f.err = true, ""
	seq, name, title := f.seq, o.Jail, sv.srv.Title()
	done := fmt.Sprintf("已在 %s 上新增规则 %s", title, name)
	if f.editing != "" {
		done = fmt.Sprintf("已更新 %s 上的规则 %s", title, name)
	}
	a.changeRule(sv, change(o), "应用规则", done, func(err error) {
		f := &a.ruleForm
		mine := f.open && f.seq == seq
		if err != nil {
			if mine {
				f.applying, f.err = false, err.Error()
			} else {
				a.toastError(title+"：应用规则失败", err)
			}
			return
		}
		if mine {
			f.open = false
		}
		sv.jail = name
	})
}

// ruleError tells of a change of a jail that failed.
func (a *App) ruleError(sv *serverView, what string) func(error) {
	return func(err error) {
		if err != nil {
			a.toastError(fmt.Sprintf("%s：%s失败", sv.srv.Title(), what), err)
		}
	}
}

// requestStopRule asks to stop a jail running, then disables it in
// RuleLens's file, so that it stays stopped as fail2ban starts again.
func (a *App) requestStopRule(sv *serverView, name string) {
	s := sv.running()
	if s == nil {
		return
	}
	j, _ := s.Jail(name)
	o := s.Config.Overrides[name].Clone()
	if o == nil {
		o = &fail2ban.Override{Jail: name}
	}
	o.Set("enabled", "false")
	msg := "fail2ban 将不再按此规则监控日志"
	if j.CurrentlyBanned > 0 {
		msg += fmt.Sprintf("，它当前封禁的 %d 个 IP 将被解封", j.CurrentlyBanned)
	}
	msg += "。\n\n将在 " + fail2ban.OverridePath(name) + " 中写入 enabled = false，校验配置后重新加载 fail2ban。fail2ban 重启后仍保持停用，可随时在 RuleLens 中重新启用。"
	a.ask(alert{
		title:   fmt.Sprintf("停用 %s 上的规则 %s？", sv.srv.Title(), name),
		message: msg,
		buttons: []string{"取消", "停用规则"},
		actions: []func(){nil, func() {
			a.changeRule(sv, change(o), "停用规则", fmt.Sprintf("已停用 %s 上的规则 %s", sv.srv.Title(), name), a.ruleError(sv, "停用规则"))
		}},
		cancelDefault: true,
	})
}

// startRule enables a jail RuleLens stopped.
func (a *App) startRule(sv *serverView, name string) {
	s := sv.running()
	if s == nil || s.Config.Overrides[name] == nil {
		return
	}
	o := s.Config.Overrides[name].Clone()
	if o.Created {
		o.Set("enabled", "true")
	} else {
		// The configuration enables it.
		o.Unset("enabled")
	}
	a.changeRule(sv, change(o), "启用规则", fmt.Sprintf("已启用 %s 上的规则 %s", sv.srv.Title(), name), func(err error) {
		if err != nil {
			a.ruleError(sv, "启用规则")(err)
			return
		}
		sv.jail = name
	})
}

// requestRemoveRule asks to remove RuleLens's file of a jail, then
// removes it: a jail RuleLens created runs no more, any other takes its
// settings of the configuration again.
func (a *App) requestRemoveRule(sv *serverView, name string) {
	s := sv.running()
	if s == nil || s.Config.Overrides[name] == nil {
		return
	}
	o := s.Config.Overrides[name]
	path := fail2ban.OverridePath(name)
	j, running := s.Jail(name)
	al, label := alert{cancelDefault: true}, "还原配置"
	if o.Created {
		al.title = fmt.Sprintf("删除 %s 上的规则 %s？", sv.srv.Title(), name)
		al.message = "将删除 " + path + " 并重新加载 fail2ban，规则停止运行"
		if running && j.CurrentlyBanned > 0 {
			al.message += fmt.Sprintf("，它当前封禁的 %d 个 IP 将被解封", j.CurrentlyBanned)
		}
		al.message += "。"
		al.buttons = []string{"取消", "删除规则"}
		label = "删除规则"
	} else {
		al.title = fmt.Sprintf("还原 %s 上的规则 %s？", sv.srv.Title(), name)
		al.message = "将删除 RuleLens 写入的 " + path + "，规则恢复为服务器上原有的配置，并重新加载 fail2ban。\n\nRuleLens 的设置："
		for _, st := range o.Settings {
			al.message += "\n• " + st.Key + " = " + strings.ReplaceAll(st.Value, "\n", " ")
		}
		al.buttons = []string{"取消", "还原"}
	}
	al.actions = []func(){nil, func() {
		done := fmt.Sprintf("已删除 %s 上的规则 %s", sv.srv.Title(), name)
		if !o.Created {
			done = fmt.Sprintf("已还原 %s 上的规则 %s", sv.srv.Title(), name)
		}
		a.changeRule(sv, fail2ban.Change{Jail: name}, label, done, a.ruleError(sv, label))
	}}
	a.ask(al)
}

// ruleActions are the buttons changing a jail, in its details.
func (a *App) ruleActions(c *ui.Context, sv *serverView, s *fail2ban.Status, name string, stopped bool) {
	busy := sv.busy != ""
	o := s.Config.Overrides[name]
	// The configuration must have been read, and the name be one of a file.
	why := ""
	switch {
	case !s.Config.Read:
		why = "无法读取规则配置：" + s.Config.Problem
	case fail2ban.ValidJailName(name) != nil:
		why = "规则名称含有 RuleLens 无法写入文件名的字符"
	}
	off := busy || why != ""
	tip := func(e ui.Element, text string) {
		if why != "" {
			text = why
		}
		e.Tooltip(text)
	}
	ui.Row(c).Gap(6).Wrap().Children(func() {
		if stopped {
			b := labeledButton(c, true, iconPlay, "启用规则").Disabled(off).OnClick(func() { a.startRule(sv, name) })
			tip(b, "重新启用此规则")
		}
		b := labeledButton(c, false, iconEdit, "编辑规则").Disabled(off).OnClick(func() { a.editRule(sv, name) })
		tip(b, "修改端口、触发条件、封禁时长与忽略 IP")
		if !stopped {
			b := labeledButton(c, false, iconPause, "停用").Disabled(off).OnClick(func() { a.requestStopRule(sv, name) })
			tip(b, "停止此规则，并在配置中保持停用")
		}
		switch {
		case o == nil:
		case o.Created:
			b := labeledButton(c, false, iconTrash, "删除").Disabled(off).OnClick(func() { a.requestRemoveRule(sv, name) })
			tip(b, "删除 RuleLens 新增的此规则")
		default:
			b := labeledButton(c, false, iconUndo, "还原配置").Disabled(off).OnClick(func() { a.requestRemoveRule(sv, name) })
			tip(b, "撤销 RuleLens 对此规则的修改")
		}
	})
}

// overrideLabel says what RuleLens's file of a jail does, "" without one.
func overrideLabel(o *fail2ban.Override) string {
	switch {
	case o == nil:
		return ""
	case o.Created:
		return "由 RuleLens 新增"
	}
	var keys []string
	for _, s := range o.Settings {
		keys = append(keys, s.Key)
	}
	if len(keys) == 0 {
		return "RuleLens 的配置文件（没有设置）"
	}
	return "RuleLens 修改了 " + strings.Join(keys, "、")
}

// settingsList lists the settings of RuleLens's file.
func settingsList(c *ui.Context, o *fail2ban.Override) {
	t := c.Theme()
	ui.Column(c).Gap(4).Padding(8, 10).Radius(8).Background(t.Surface).Children(func() {
		for _, s := range o.Settings {
			ui.Text(c.Key(s.Key), s.Key+" = "+strings.ReplaceAll(s.Value, "\n", " ")).Font("monospace").FontSize(12).Selectable()
		}
	})
}

// stoppedDetail shows a jail RuleLens stopped, and what its file sets.
func (a *App) stoppedDetail(c *ui.Context, sv *serverView, s *fail2ban.Status, name string) {
	t := c.Theme()
	o := s.Config.Overrides[name]
	ui.Scroll(c.Key("detail:"+name)).Fill().Padding(4, 4, 4, 16).Children(func() {
		ui.Column(c).Gap(14).Children(func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
				ui.Text(c, name).FontSize(18).Bold().Selectable()
				pill(c, "已停用", t.TextMuted)
			})
			a.ruleActions(c, sv, s, name, true)
			ui.Text(c, "此规则已停用：fail2ban 不再按它监控日志，也不再封禁。").TextColor(t.TextMuted)
			section(c, "RuleLens 的设置", func() {
				ui.Text(c, fail2ban.OverridePath(name)).FontSize(12).TextColor(t.TextMuted).Font("monospace").Selectable()
				settingsList(c, o)
			})
		})
	})
}

func (a *App) ruleDialog(c *ui.Context) {
	f := &a.ruleForm
	if !f.open {
		return
	}
	sv := a.views[f.server]
	var s *fail2ban.Status
	if sv != nil {
		s = sv.running()
	}
	if s == nil {
		f.open = false
		return
	}
	if f.applying && sv.busy == "" {
		// The connection dropped before the change could tell.
		f.applying, f.err = false, "连接已断开，规则可能未应用，请重新连接后查看。"
	}
	t := c.Theme()
	isNew := f.editing == ""
	ui.Modal(c, &f.open, func() {
		ui.Column(c).Width(620).MinHeight(0).Gap(14).Children(func() {
			title := "新增规则"
			if !isNew {
				title = "编辑规则 " + f.editing
			}
			ui.Row(c).Gap(8).AlignItems(ui.Center).Shrink(0).Children(func() {
				ui.Text(c, title).FontSize(18).Bold()
				ui.Text(c, sv.srv.Title()).TextColor(t.TextMuted).SingleLine()
			})
			// The form scrolls in a window too short for it, the buttons
			// staying in sight.
			var o *fail2ban.Override
			var problem error
			ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
				ui.Column(c).Gap(14).Padding(0, 4, 0, 0).Children(func() {
					a.ruleFields(c, sv, s)
					// After the fields, which took the typing.
					o, problem = f.override(s)
					rulePreview(c, f, o, problem)
				})
			})
			if f.err != "" {
				ui.Text(c, f.err).TextColor(t.Danger).Selectable().Shrink(0)
			}
			ui.Row(c).Gap(8).Justify(ui.End).AlignItems(ui.Center).Shrink(0).Children(func() {
				if f.applying {
					ui.Spinner(c).Label("应用中")
					ui.Text(c, "正在应用…").TextColor(t.TextMuted)
				}
				if ui.Button(c, "取消").Clicked() {
					f.open = false
				}
				label := "新增并应用"
				if !isNew {
					label = "保存并应用"
				}
				// The preview tells what keeps it from saving.
				if ui.PrimaryButton(c, label).Disabled(f.applying || problem != nil || !f.changed(o)).Clicked() {
					a.saveRule()
				}
			})
		})
	})
}

// ruleFields builds the fields of the rule dialog.
func (a *App) ruleFields(c *ui.Context, sv *serverView, s *fail2ban.Status) {
	f := &a.ruleForm
	t := c.Theme()
	isNew := f.editing == ""
	_, preset := s.Config.Jails[strings.TrimSpace(f.name)]
	preset = preset && isNew
	keep, short := "留空使用默认值", "默认"
	switch {
	case !isNew:
		keep, short = "留空则不修改", "不修改"
	case preset:
		keep, short = "留空使用预置规则的设置", "预置"
	}
	ui.Form(c, func() {
		if isNew {
			note := "可填写新名称自定义规则，或选择服务器上 fail2ban 预置但未启用的规则（如 nginx-http-auth）。"
			if preset {
				note = "fail2ban 预置的规则：留空的项使用其预置设置。"
			}
			ui.Field(c, "规则名称", func() {
				ui.Autocomplete(c, &f.name, s.Presets()).Placeholder("如 nginx-http-auth").Label("规则名称").AutoFocus()
			}).Description(note)
		}
		ui.Field(c, "过滤器", func() {
			hint := "留空则使用与规则同名的过滤器"
			if !isNew || preset {
				hint = keep
			}
			ui.Autocomplete(c, &f.filter, s.Config.Filters).Placeholder(hint).Label("过滤器")
		}).Description("识别日志中失败记录的规则，即 /etc/fail2ban/filter.d/ 中的文件名，如 sshd、nginx-http-auth。")
		ui.Field(c, "端口", func() {
			ui.TextInput(c, &f.port).Placeholder("如 ssh、http,https、8000:8100；" + keep).Label("端口")
		}).Description("封禁来源访问的端口，多个用逗号分隔。")
		ui.Field(c, "日志来源", func() {
			ui.Segmented(c, &f.source, "日志文件", "systemd 日志").Label("日志来源")
			if f.source == sourceFiles {
				hint := "如 /var/log/nginx/error.log，多个用空格分隔"
				if !isNew || preset {
					hint += "；" + keep
				}
				ui.TextInput(c, &f.logpath).Placeholder(hint).Label("日志文件路径")
			} else {
				ui.Text(c, "按过滤器的 journalmatch 读取 systemd 日志（backend = systemd）。").FontSize(12.5).TextColor(t.TextMuted)
			}
		})
		ui.Field(c, "触发条件", func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.TextInput(c, &f.findTime).Placeholder(short).Label("统计时长").Width(96)
				within := "内失败"
				if d, err := fail2ban.ParseTime(f.findTime); err == nil && d > 0 {
					within = durationLabel(d) + within
				}
				ui.Text(c, within).TextColor(t.TextMuted).SingleLine()
				ui.TextInput(c, &f.maxRetry).Placeholder(short).Label("失败次数").Width(72)
				ui.Text(c, "次即封禁").TextColor(t.TextMuted).SingleLine()
			})
		}).Description("时长可写秒数或带单位，如 600、10m、1h、1d、1w。")
		ui.Field(c, "封禁时长", func() {
			ui.Row(c).Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
				// The field's label names it: a group's would take the
				// clicks meant for it.
				ui.TextInput(c, &f.banTime).Placeholder(short).Width(96).Disabled(f.permanent)
				if d, err := fail2ban.ParseTime(f.banTime); err == nil && d > 0 && !f.permanent {
					ui.Text(c, durationLabel(d)).FontSize(12.5).TextColor(t.TextMuted).SingleLine()
				}
				ui.Checkbox(c, &f.permanent, "永久封禁")
				ui.Checkbox(c, &f.increment, "再次被封时递增")
				if f.increment {
					ui.Text(c, "最长").TextColor(t.TextMuted)
					ui.TextInput(c, &f.maxTime).Placeholder("不限").Label("最长封禁时长").Width(80)
				}
			})
		})
		ui.Field(c, "忽略 IP", func() {
			ui.Row(c).Gap(8).Children(func() {
				ui.TextInput(c, &f.ignoreIP).Placeholder("如 127.0.0.1/8 ::1；" + keep).Label("忽略 IP").Grow(1)
				if ip := sv.info.ClientIP; ip != "" && !slices.Contains(strings.Fields(f.ignoreIP), ip) {
					ui.Button(c, "加入本机 IP").Tooltip("加入 " + ip + "，以免本机被封禁").OnClick(func() {
						f.ignoreIP = strings.TrimSpace(f.ignoreIP + " " + ip)
					})
				}
			})
		}).Description(ignoreNote(sv.info.ClientIP))
	})
}

// rulePreview shows what the dialog would write, or why it cannot.
func rulePreview(c *ui.Context, f *ruleForm, o *fail2ban.Override, problem error) {
	t := c.Theme()
	ui.Column(c).Gap(6).Children(func() {
		switch {
		case problem != nil:
			ui.Text(c, problem.Error()).FontSize(12.5).TextColor(t.Warning).Selectable()
		case !f.changed(o):
			ui.Text(c, "还没有修改。").FontSize(12.5).TextColor(t.TextMuted)
		case change(o).Override == nil:
			ui.Text(c, "将删除 "+fail2ban.OverridePath(o.Jail)+"：其中的设置都已还原。").FontSize(12.5).TextColor(t.TextMuted).Selectable()
		default:
			ui.Text(c, "将写入 "+fail2ban.OverridePath(o.Jail)+"：").FontSize(12.5).TextColor(t.TextMuted).Selectable()
			ui.Column(c).Padding(8, 12).Radius(8).Background(t.Surface).Children(func() {
				ui.Text(c, o.Render()).Font("monospace").FontSize(12).Selectable()
			})
		}
		ui.Text(c, "写入后先用 fail2ban-client -t 校验配置，通过后执行 fail2ban-client reload 生效；任一步失败都会还原文件。").FontSize(12).TextColor(t.TextMuted)
	})
}

// ignoreNote describes the addresses a jail ignores, with this computer's
// as the server sees it.
func ignoreNote(clientIP string) string {
	note := "这些来源永不封禁，空格分隔，可写网段如 10.0.0.0/8。"
	if clientIP != "" {
		note += "本机在服务器上的 IP 为 " + clientIP + "。"
	}
	return note
}
