package gui

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/rulelens/rulelens/internal/fail2ban"
	"github.com/rulelens/rulelens/internal/session"
)

// View builds the window.
func (a *App) View(c *ui.Context) {
	for _, t := range a.toasts {
		c.AddToast(t)
	}
	a.toasts = nil
	servers := a.servers()
	if a.page != pageOverview && a.views[a.page] == nil {
		a.page = pageOverview
	}
	t := c.Theme()
	ui.Row(c).Fill().AlignItems(ui.Stretch).Children(func() {
		a.sidebar(c, servers)
		ui.Column(c).Grow(1).MinWidth(0).Background(t.Background).Children(func() {
			// The top of the window drags it, under the hidden title bar.
			ui.Row(c).Height(max(c.TitleBar().Height, 12)).Shrink(0).DragWindow()
			if sv := a.current(); sv != nil {
				a.serverPage(c, sv)
			} else {
				a.overview(c, servers)
			}
		})
	})
	a.serverDialog(c)
	a.ruleDialog(c)
	a.alertDialog(c)

	if c.Shortcut(ui.Cmd, ui.KeyN) {
		a.NewServer()
	}
	if c.Shortcut(ui.Cmd, ui.KeyR) || c.Shortcut(0, ui.KeyF5) {
		a.Refresh()
	}
	if next := a.autoRefresh(servers); next > 0 {
		c.After(next)
	}
}

// refreshOptions are the intervals of automatic refreshing a menu offers,
// in seconds, 0 for none.
var refreshOptions = []int{0, 30, 60, 300, 600}

func refreshLabel(secs int) string {
	if secs <= 0 {
		return "不自动刷新"
	}
	return "每 " + durationLabel(time.Duration(secs)*time.Second) + "自动刷新"
}

// refreshSelect chooses how often fail2ban is read again.
func (a *App) refreshSelect(c *ui.Context) {
	opts := slices.Clone(refreshOptions)
	if cur := a.settings.RefreshSeconds; !slices.Contains(opts, cur) {
		opts = append(opts, cur)
	}
	labels := make([]string, len(opts))
	for i, o := range opts {
		labels[i] = refreshLabel(o)
	}
	label := refreshLabel(a.settings.RefreshSeconds)
	ui.Select(c, &label, labels).Label("自动刷新").Width(150)
	if i := slices.Index(labels, label); i >= 0 && opts[i] != a.settings.RefreshSeconds {
		a.setRefresh(opts[i])
	}
}

// Refresh reads fail2ban on the page's server again, or on every server on
// the overview.
func (a *App) Refresh() {
	if sv := a.current(); sv != nil {
		a.refresh(sv)
	} else {
		a.refreshAll()
	}
}

// iconButton is a button showing an icon, named for assistive technology
// and with a tip.
func iconButton(c *ui.Context, svg *ui.SVG, label string) ui.Element {
	return ui.Button(c, "").Label(label).Tooltip(label).Padding(5, 7).Children(func() {
		ui.Icon(c, svg).FontSize(15)
	})
}

// labeledButton is a button with an icon before its label.
func labeledButton(c *ui.Context, primary bool, svg *ui.SVG, label string) ui.Element {
	var b ui.Element
	if primary {
		b = ui.PrimaryButton(c, "")
	} else {
		b = ui.Button(c, "")
	}
	return b.Label(label).Children(func() {
		ui.Icon(c, svg).FontSize(14)
		ui.Text(c, label).SingleLine()
	})
}

// pill is a short text on a tint of its color.
func pill(c *ui.Context, text string, color ui.Color) ui.Element {
	return ui.Row(c).Padding(2, 8).Radius(999).Background(color.Alpha(0.14)).Shrink(0).Children(func() {
		ui.Text(c, text).FontSize(11.5).FontWeight(600).TextColor(color).SingleLine()
	})
}

// dot is a small circle of a color, as the state of a connection.
func dot(c *ui.Context, color ui.Color) ui.Element {
	return ui.Box(c).Size(8, 8).Radius(4).Background(color).Shrink(0)
}

// bannedColor is the color of a count of bans: the danger's while some
// address is banned.
func bannedColor(t *ui.Theme, n int) ui.Color {
	if n > 0 {
		return t.Danger
	}
	return t.TextMuted
}

// stateColor and stateLabel tell the state of a server's connection and of
// fail2ban on it.
func stateColor(t *ui.Theme, sv *serverView) ui.Color {
	switch sv.state {
	case stateConnected:
		if sv.running() != nil {
			return t.Success
		}
		return t.Warning
	case stateFailed:
		return t.Danger
	case stateConnecting:
		return t.Accent
	}
	return t.TextMuted.Alpha(0.5)
}

func stateLabel(sv *serverView) string {
	switch sv.state {
	case stateConnecting:
		return "连接中…"
	case stateFailed:
		return "连接失败"
	case stateConnected:
		s := sv.f2b
		switch {
		case s == nil && sv.readErr != "":
			return "读取 fail2ban 失败"
		case s == nil:
			return "已连接"
		case !s.Installed:
			return "未安装 fail2ban"
		case !s.Running:
			return "fail2ban 未运行"
		}
		return "fail2ban 运行中"
	}
	return "未连接"
}

func (a *App) sidebar(c *ui.Context, servers []*serverView) {
	t := c.Theme()
	ui.Column(c).Width(236).Shrink(0).Background(t.Surface).BorderWidth(0, 1, 0, 0).BorderColor(t.Border).Children(func() {
		ui.Row(c).Height(max(c.TitleBar().Height, 12)).Shrink(0).DragWindow()
		ui.Row(c).Padding(2, 12, 10, 16).Gap(8).AlignItems(ui.Center).DragWindow().Children(func() {
			ui.Icon(c, iconShieldCheck).FontSize(20).TextColor(t.Accent)
			ui.Text(c, "RuleLens").FontSize(16).Bold().Grow(1)
			iconButton(c, iconPlus, "添加服务器").OnClick(a.NewServer)
		})
		// Servers gather by group, those without one under "服务器".
		var groups []string
		for _, sv := range servers {
			if !slices.Contains(groups, sv.srv.Group) {
				groups = append(groups, sv.srv.Group)
			}
		}
		page := a.page
		if ui.Sidebar(c, &page, func() {
			ui.SidebarItem(c, pageOverview, iconOverview, "概览").Children(func() {
				if len(servers) > 0 {
					ui.Badge(c, fmt.Sprint(len(servers)))
				}
			})
			for _, g := range groups {
				open := a.groupsOpen[g]
				if open == nil {
					open = new(bool)
					*open = true
					a.groupsOpen[g] = open
				}
				title := g
				if title == "" {
					title = "服务器"
				}
				ui.SidebarSection(c, title, open, func() {
					for _, sv := range servers {
						if sv.srv.Group != g {
							continue
						}
						ui.SidebarItem(c, sv.srv.ID, iconServer, sv.srv.Title()).Tooltip(sv.srv.Address() + " · " + stateLabel(sv)).Children(func() {
							if s := sv.running(); s != nil && s.Banned() > 0 {
								ui.Text(c, fmt.Sprint(s.Banned())).FontSize(11.5).TextColor(t.Danger).FontFeatures("tnum").Tooltip("当前封禁的 IP")
							}
							dot(c, stateColor(t, sv))
						})
					}
				})
			}
		}).Grow(1).Label("服务器列表").Changed() || page != a.page {
			a.page = page
			if sv := a.current(); sv != nil && sv.state == stateIdle {
				a.connect(sv)
			}
		}
		connected := 0
		for _, sv := range servers {
			if sv.state == stateConnected {
				connected++
			}
		}
		ui.Text(c, fmt.Sprintf("%d 台服务器 · %d 台已连接", len(servers), connected)).FontSize(12).TextColor(t.TextMuted).Padding(10, 16, 14)
	})
}

// card is a panel of the page.
func card(c *ui.Context) ui.Element {
	t := c.Theme()
	return ui.Column(c).Padding(16).Gap(10).Radius(10).Background(t.Background).Border(1, t.Border).
		Shadow(0, 1, 3, 0, ui.RGBA(0, 0, 0, 0.05))
}

func (a *App) overview(c *ui.Context, servers []*serverView) {
	t := c.Theme()
	ui.Column(c).Grow(1).MinHeight(0).Padding(4, 28, 0).Gap(16).Children(func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, "概览").FontSize(24).Bold()
				ui.Text(c, "每台服务器上 fail2ban 的规则（jail）与封禁情况").TextColor(t.TextMuted)
			})
			if len(servers) > 0 {
				a.refreshSelect(c)
				labeledButton(c, false, iconRefresh, "全部连接 / 刷新").OnClick(a.refreshAll)
			}
			labeledButton(c, true, iconPlus, "添加服务器").OnClick(a.NewServer)
		})
		if len(servers) == 0 {
			a.welcome(c)
			return
		}
		running, jails, banned := 0, 0, 0
		for _, sv := range servers {
			if s := sv.running(); s != nil {
				running++
				jails += len(s.Jails)
				banned += s.Banned()
			}
		}
		ui.Row(c).Gap(12).Children(func() {
			stat(c, "服务器", fmt.Sprint(len(servers)), t.Text)
			stat(c, "fail2ban 运行中", fmt.Sprint(running), t.Success)
			stat(c, "规则（jail）", fmt.Sprint(jails), t.Accent)
			stat(c, "当前封禁 IP", fmt.Sprint(banned), bannedColor(t, banned))
		})
		ui.Scroll(c).Grow(1).Padding(0, 0, 24).Children(func() {
			ui.Row(c).Wrap().Gap(14).AlignItems(ui.Start).Children(func() {
				for _, sv := range servers {
					a.serverCard(c.Key(sv.srv.ID), sv)
				}
			})
		})
	})
}

func stat(c *ui.Context, label, value string, color ui.Color) {
	statNote(c, label, value, color, "")
}

// statNote is a stat with a note under its value, saying what it counts.
func statNote(c *ui.Context, label, value string, color ui.Color, note string) {
	t := c.Theme()
	card(c).Grow(1).Basis(0).Gap(4).Children(func() {
		ui.Text(c, label).FontSize(12).TextColor(t.TextMuted)
		ui.Text(c, value).FontSize(26).Bold().TextColor(color).FontFeatures("tnum")
		if note != "" {
			ui.Text(c, note).FontSize(11.5).TextColor(t.TextMuted).MaxLines(2)
		}
	})
}

// open shows the page of a server, connecting to it unless it is.
func (a *App) open(sv *serverView) {
	a.page = sv.srv.ID
	if sv.state == stateIdle {
		a.connect(sv)
	}
}

func (a *App) serverCard(c *ui.Context, sv *serverView) {
	t := c.Theme()
	cc := card(c).Width(372).Cursor(ui.CursorPointer)
	if cc.Hovered() {
		cc.Border(1, t.Accent.Alpha(0.6))
	}
	if cc.Clicked() {
		a.open(sv)
	}
	cc.Label(sv.srv.Title()).Children(func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, iconServer).FontSize(16).TextColor(t.TextMuted)
			ui.Text(c, sv.srv.Title()).FontSize(15).Bold().SingleLine().Grow(1)
			if sv.srv.Group != "" {
				pill(c, sv.srv.Group, t.Accent)
			}
		})
		ui.Text(c, sv.srv.Address()).FontSize(12).TextColor(t.TextMuted).SingleLine()
		ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
			dot(c, stateColor(t, sv))
			ui.Text(c, stateLabel(sv)).FontSize(13).Grow(1)
			if sv.state == stateConnecting || sv.busy != "" {
				ui.Spinner(c).Label("进行中")
			}
			if s := sv.running(); s != nil {
				ui.Text(c, fmt.Sprintf("%s · fail2ban %s", sv.info.OS, s.Version)).FontSize(12).TextColor(t.TextMuted).SingleLine()
			}
		})
		switch s := sv.status(); {
		case sv.state == stateFailed:
			ui.Text(c, sv.err).FontSize(12).TextColor(t.Danger).MaxLines(2)
		case sv.state == stateConnected && s == nil && sv.readErr != "":
			ui.Text(c, sv.readErr).FontSize(12).TextColor(t.Danger).MaxLines(2)
		case s != nil && s.Running:
			jailSummary(c, s)
		case s != nil && s.Problem != "":
			ui.Text(c, s.Problem).FontSize(12).TextColor(t.Warning).MaxLines(2)
		}
	})
}

// jailSummary lists the jails of a server in short, on its card.
func jailSummary(c *ui.Context, s *fail2ban.Status) {
	t := c.Theme()
	if len(s.Jails) == 0 {
		ui.Text(c, "没有启用的规则（jail）").FontSize(12).TextColor(t.TextMuted)
		return
	}
	ui.Column(c).Radius(8).Background(t.Surface).Children(func() {
		for i, j := range s.Jails {
			row := ui.Row(c.Key(j.Name)).Padding(7, 10).Gap(8).AlignItems(ui.Center)
			if i > 0 {
				row.BorderWidth(1, 0, 0, 0).BorderColor(t.Border)
			}
			row.Children(func() {
				ui.Column(c).Grow(1).MinWidth(0).Gap(2).Children(func() {
					ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
						ui.Text(c, j.Name).FontSize(13).FontWeight(600).SingleLine()
						ui.Text(c, portsLabel(j)).FontSize(12).Font("monospace").TextColor(t.TextMuted).SingleLine()
					})
					ui.Text(c, triggerLabel(j)+" → "+banPhrase(j)).FontSize(11.5).TextColor(t.TextMuted).SingleLine()
				})
				pill(c, fmt.Sprintf("封禁 %d", j.CurrentlyBanned), bannedColor(t, j.CurrentlyBanned))
			})
		}
	})
}

func (a *App) welcome(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Grow(1).Center().Gap(14).Children(func() {
		ui.Icon(c, iconShieldCheck).FontSize(56).TextColor(t.Accent)
		ui.Text(c, "添加第一台服务器").FontSize(20).Bold()
		ui.Text(c, "RuleLens 通过 SSH 连接服务器，查看每台服务器上 fail2ban 的规则（jail）：\n监控的端口与日志、触发条件、封禁时长，以及当前被封禁的 IP。\n经你确认后，也可以解封 IP，新增、修改或停用规则。").
			TextColor(t.TextMuted).TextAlign(ui.Center).MaxWidth(500)
		labeledButton(c, true, iconPlus, "添加服务器").OnClick(a.NewServer)
	})
}

func (a *App) serverPage(c *ui.Context, sv *serverView) {
	t := c.Theme()
	ui.Column(c).Grow(1).MinHeight(0).Padding(4, 28, 20).Gap(16).Children(func() {
		a.serverHeader(c, sv)
		retry := func() {
			labeledButton(c, true, iconRefresh, "刷新").Disabled(sv.busy != "").OnClick(func() { a.refresh(sv) })
		}
		switch sv.state {
		case stateIdle:
			message(c, iconPlug, "尚未连接", "连接后读取这台服务器上 fail2ban 的规则。", func() {
				labeledButton(c, true, iconPlug, "连接").OnClick(func() { a.connect(sv) })
			})
		case stateConnecting:
			ui.Column(c).Grow(1).Center().Gap(12).Children(func() {
				ui.Spinner(c).Size(28, 28).Label("连接中")
				ui.Text(c, "正在连接 "+sv.srv.Address()+" …").TextColor(t.TextMuted)
			})
		case stateFailed:
			message(c, iconAlert, "连接失败", sv.err, func() {
				ui.Row(c).Gap(8).Children(func() {
					labeledButton(c, false, iconEdit, "编辑服务器").OnClick(func() { a.editServer(sv) })
					labeledButton(c, true, iconRefresh, "重试").OnClick(func() { a.connect(sv) })
				})
			})
		case stateConnected:
			s := sv.f2b
			switch {
			case s == nil:
				text := "读取 fail2ban 需要 root 权限，请检查该用户能否执行 sudo。"
				if sv.readErr != "" {
					text = sv.readErr
				}
				message(c, iconAlert, "未能读取 fail2ban", text, retry)
			case !s.Installed:
				message(c, iconShieldOff, "服务器未安装 fail2ban", "这台服务器上没有找到 fail2ban-client。\n安装并启动 fail2ban 后点击刷新，例如 Ubuntu / Debian：sudo apt install fail2ban", retry)
			case !s.Running:
				message(c, iconShieldOff, "fail2ban 未运行", s.Problem+"\n\n可在服务器上执行 sudo systemctl start fail2ban 启动后点击刷新。", retry)
			default:
				summary(c, s)
				a.tabs(c, sv, s)
			}
		}
	})
}

// message is a page that says one thing, with what to do about it.
func message(c *ui.Context, svg *ui.SVG, title, text string, actions func()) {
	t := c.Theme()
	ui.Column(c).Grow(1).Center().Gap(12).Children(func() {
		ui.Icon(c, svg).FontSize(40).TextColor(t.TextMuted)
		ui.Text(c, title).FontSize(18).Bold()
		ui.Text(c, text).TextColor(t.TextMuted).TextAlign(ui.Center).MaxWidth(560).Selectable()
		actions()
	})
}

func (a *App) serverHeader(c *ui.Context, sv *serverView) {
	t := c.Theme()
	ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
		ui.Column(c).Grow(1).MinWidth(0).Gap(4).Children(func() {
			ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Text(c, sv.srv.Title()).FontSize(24).Bold().SingleLine()
				dot(c, stateColor(t, sv))
				ui.Text(c, stateLabel(sv)).TextColor(t.TextMuted).SingleLine()
			})
			ui.Row(c).Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
				ui.Text(c, sv.srv.Address()).FontSize(13).TextColor(t.TextMuted).Selectable()
				if sv.state == stateConnected {
					pill(c, sv.info.OS.String(), t.TextMuted)
					if s := sv.f2b; s != nil && s.Version != "" {
						pill(c, "fail2ban "+s.Version, t.TextMuted)
					}
					if sv.info.Root {
						pill(c, "root", t.Warning)
					}
				}
				if sv.srv.Note != "" {
					ui.Text(c, sv.srv.Note).FontSize(13).TextColor(t.TextMuted).SingleLine()
				}
			})
		})
		if sv.busy != "" {
			ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
				ui.Spinner(c).Label(sv.busy + "中")
				ui.Text(c, sv.busy+"中…").TextColor(t.TextMuted).SingleLine()
			})
		} else if sv.state == stateConnected && !sv.loadedAt.IsZero() {
			ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
				if sv.readErr != "" {
					// What was read shows still, the last reading failed.
					ui.Icon(c, iconAlert).FontSize(13).TextColor(t.Warning).Tooltip(sv.readErr)
					ui.Text(c, "刷新失败").FontSize(12).TextColor(t.Warning).SingleLine().Tooltip(sv.readErr)
				}
				ui.Text(c, "更新于 "+ago(a.now(), sv.loadedAt)).FontSize(12).TextColor(t.TextMuted).SingleLine()
			})
			c.After(30 * time.Second)
		}
		if sv.state == stateConnected {
			a.refreshSelect(c)
		}
		iconButton(c, iconRefresh, "刷新").Disabled(sv.busy != "" || sv.state == stateConnecting).OnClick(func() { a.refresh(sv) })
		ui.Button(c, "").Label("更多操作").Tooltip("更多操作").Padding(5, 7).Children(func() {
			ui.Icon(c, iconMore).FontSize(15)
		}).Menu(func(m *ui.Menu) {
			if m.Item("编辑服务器…").Chosen() {
				a.editServer(sv)
			}
			if sv.state == stateConnected {
				if m.Item("断开连接").Chosen() {
					a.disconnect(sv)
				}
			} else if m.Item("连接").Disabled(sv.state == stateConnecting).Chosen() {
				a.connect(sv)
			}
			m.Separator()
			if m.Item("删除服务器…").Chosen() {
				a.requestDeleteServer(sv)
			}
		})
	})
}

// summary is the row of cards over a server's tabs.
func summary(c *ui.Context, s *fail2ban.Status) {
	t := c.Theme()
	failed := 0
	for _, j := range s.Jails {
		failed += j.CurrentlyFailed
	}
	ui.Row(c).Gap(12).AlignItems(ui.Stretch).Children(func() {
		card(c).Grow(1.2).Basis(0).Gap(4).Children(func() {
			ui.Text(c, "fail2ban").FontSize(12).TextColor(t.TextMuted)
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, iconShieldCheck).FontSize(20).TextColor(t.Success)
				ui.Text(c, "运行中").FontSize(18).Bold().TextColor(t.Success)
				ui.Text(c, s.Version).FontSize(12).TextColor(t.TextMuted)
			})
		})
		stat(c, "规则（jail）", fmt.Sprint(len(s.Jails)), t.Accent)
		// fail2ban counts the bans since it started, those ended too: the
		// notes tell, as the two counts often differ.
		statNote(c, "当前封禁 IP", fmt.Sprint(s.Banned()), bannedColor(t, s.Banned()), "此刻仍在封禁中")
		statNote(c, "累计封禁", fmt.Sprint(s.TotalBanned()), t.Text, "启动以来，含已解封")
		color := t.TextMuted
		if failed > 0 {
			color = t.Warning
		}
		statNote(c, "当前失败记录", fmt.Sprint(failed), color, "尚未达到封禁条件")
	})
}

func (a *App) tabs(c *ui.Context, sv *serverView, s *fail2ban.Status) {
	log := sv.conn.Log()
	ui.Tabs(c, &sv.tab, fmt.Sprintf("规则 (%d)", len(s.Jails)), fmt.Sprintf("封禁 IP (%d)", s.Banned()), "防火墙中的封禁", fmt.Sprintf("操作日志 (%d)", len(log))).Label("视图")
	switch sv.tab {
	case 0:
		a.rulesTab(c, sv, s)
	case 1:
		a.bansTab(c, sv, s)
	case 2:
		firewallTab(c, s)
	case 3:
		a.logTab(c, sv, log)
	}
}

// jailColumns are the columns of the jails' table.
var jailColumns = []ui.TableColumn{
	{Title: "规则", Width: 124, Sortable: true},
	{Title: "端口", Width: 104},
	{Title: "触发条件", Width: 108},
	{Title: "封禁时长", Width: 92, Sortable: true},
	{Title: "当前封禁", Width: 76, Align: ui.End, Sortable: true},
	{Title: "累计封禁", Width: 76, Align: ui.End, Sortable: true},
}

func (a *App) rulesTab(c *ui.Context, sv *serverView, s *fail2ban.Status) {
	t := c.Theme()
	stopped := s.Stopped()
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
		b := labeledButton(c, false, iconPlus, "新增规则").Disabled(sv.busy != "" || !s.Config.Read).OnClick(func() { a.newRule(sv) })
		if !s.Config.Read {
			b.Tooltip("无法读取规则配置：" + s.Config.Problem)
		}
		ui.Text(c, "规则写入 /etc/fail2ban/jail.d/，经 fail2ban-client -t 校验后重新加载生效，失败自动还原。").FontSize(12.5).TextColor(t.TextMuted).MinWidth(0).SingleLine()
	})
	if len(s.Jails) == 0 && len(stopped) == 0 {
		ui.Column(c).Grow(1).Center().Gap(8).Radius(8).Border(1, t.Border).Children(func() {
			ui.Icon(c, iconShield).FontSize(32).TextColor(t.TextMuted)
			ui.Text(c, "没有启用的规则（jail）").FontSize(15).Bold()
			ui.Text(c, "fail2ban 在运行，但没有启用任何 jail。点击「新增规则」启用预置规则（如 sshd），或自定义一条。").TextColor(t.TextMuted)
		})
		return
	}
	jails := jailRows(s, sv.jailSort)
	// The jails stopped have no state: they come last.
	for _, name := range stopped {
		jails = append(jails, fail2ban.Jail{Name: name})
	}
	sel := slices.IndexFunc(jails, func(j fail2ban.Jail) bool { return j.Name == sv.jail })
	if sel < 0 {
		sel = 0
	}
	// The table takes a choice at the row it chose last for its choice of
	// then, moved, which it follows: a jail chosen here, as one just
	// created, is chosen after a frame of none.
	chosen := sel
	if sel == sv.jailRow && sv.jailShown != "" && jails[sel].Name != sv.jailShown {
		chosen = -1
		c.Invalidate()
	}
	ui.SplitPercent(c, &a.split, func() {
		sv.jails.Key = func(i int) any { return jails[i].Name }
		sv.jails.Label = func(i int) string { return jails[i].Name }
		sv.jails.Selected = &chosen
		sv.jails.Sort = &sv.jailSort
		ui.Table(c, &sv.jails, jailColumns, len(jails), func(row, col int) {
			j := jails[row]
			// The chosen row is on the accent color.
			muted, banned := t.TextMuted, bannedColor(t, j.CurrentlyBanned)
			if row == chosen {
				muted, banned = t.AccentText, t.AccentText
			}
			// A jail stopped says so where its ports would show.
			off := slices.Contains(stopped, j.Name)
			switch {
			case off && col == 1:
				pill(c, "已停用", muted)
				return
			case off && col > 1:
				ui.Text(c, "—").TextColor(muted)
				return
			}
			switch col {
			case 0:
				ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
					name := ui.Text(c, j.Name).FontWeight(600).SingleLine()
					if off {
						name.TextColor(muted)
					}
					if l := overrideLabel(s.Config.Overrides[j.Name]); l != "" && !off {
						ui.Icon(c, iconEdit).FontSize(11).TextColor(muted).Tooltip(l)
					}
					if j.Problem != "" {
						ui.Icon(c, iconAlert).FontSize(12).TextColor(t.Warning).Tooltip(j.Problem)
					}
				})
			case 1:
				ui.Text(c, portsLabel(j)).Font("monospace").SingleLine().Tooltip(strings.Join(j.Protocols(), ", "))
			case 2:
				ui.Text(c, triggerLabel(j)).SingleLine()
			case 3:
				ui.Text(c, banTimeLabel(j)).SingleLine()
			case 4:
				ui.Text(c, fmt.Sprint(j.CurrentlyBanned)).FontFeatures("tnum").TextColor(banned).FontWeight(600)
			case 5:
				ui.Text(c, fmt.Sprint(j.TotalBanned)).FontFeatures("tnum").TextColor(muted)
			}
		}).Fill().Label("fail2ban 规则")
		if chosen >= 0 && chosen < len(jails) {
			sel = chosen
			sv.jail = jails[sel].Name
		}
		sv.jailRow, sv.jailShown = chosen, sv.jail
	}, func() {
		switch {
		case sel >= len(jails):
		case slices.Contains(stopped, jails[sel].Name):
			a.stoppedDetail(c, sv, s, jails[sel].Name)
		default:
			a.jailDetail(c, sv, s, jails[sel])
		}
	}).Grow(1).MinHeight(0)
}

// jailDetail shows everything of a jail: what it watches, when it bans, how,
// and the patterns of its filter.
func (a *App) jailDetail(c *ui.Context, sv *serverView, s *fail2ban.Status, j fail2ban.Jail) {
	t := c.Theme()
	now := a.now()
	ui.Scroll(c.Key("detail:"+j.Name)).Fill().Padding(4, 4, 4, 16).Children(func() {
		ui.Column(c).Gap(14).Children(func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
				ui.Text(c, j.Name).FontSize(18).Bold().Selectable()
				pill(c, fmt.Sprintf("当前封禁 %d", j.CurrentlyBanned), bannedColor(t, j.CurrentlyBanned))
			})
			a.ruleActions(c, sv, s, j.Name, false)
			if j.Problem != "" {
				ui.Text(c, "部分信息读取失败："+j.Problem).FontSize(12).TextColor(t.Warning)
			}
			ui.Text(c, fmt.Sprintf("%s内失败 %d 次的来源 IP 将被%s。", durationLabel(j.FindTime), j.MaxRetry, banPhrase(j))).TextColor(t.TextMuted)
			ui.Grid(c).ColumnTracks(ui.FitContent(), ui.Fr(1)).GapX(14).GapY(8).Children(func() {
				field := func(label, value string, mono bool) {
					ui.Text(c, label).FontSize(12.5).TextColor(t.TextMuted)
					v := ui.Text(c, value).FontSize(12.5).Selectable()
					if mono {
						v.Font("monospace")
					}
				}
				ports := portsLabel(j)
				if p := j.Protocols(); len(p) > 0 {
					ports += "（" + strings.Join(p, ", ") + "）"
				}
				field("端口", ports, true)
				field("触发条件", fmt.Sprintf("%s内失败 %d 次", durationLabel(j.FindTime), j.MaxRetry), false)
				field("封禁时长", banDurationSentence(j), false)
				actions := make([]string, len(j.Actions))
				for i, act := range j.Actions {
					actions[i] = act.Name
				}
				field("封禁动作", orDash(strings.Join(actions, "\n")), true)
				field("日志来源", sourceLabel(j), true)
				field("忽略 IP", orDash(strings.Join(j.IgnoreIP, "  ")), true)
				field("失败记录", fmt.Sprintf("当前 %d · 启动以来 %d", j.CurrentlyFailed, j.TotalFailed), false)
				field("封禁次数", fmt.Sprintf("当前 %d · 启动以来 %d（含已解封）", j.CurrentlyBanned, j.TotalBanned), false)
				if l := overrideLabel(s.Config.Overrides[j.Name]); l != "" {
					field("配置", l+"\n"+fail2ban.OverridePath(j.Name), false)
				}
			})
			section(c, fmt.Sprintf("当前封禁的 IP（%d）", len(j.Bans)), func() {
				if len(j.Bans) == 0 {
					ui.Text(c, "没有").FontSize(12.5).TextColor(t.TextMuted)
					return
				}
				ui.Column(c).Radius(8).Background(t.Surface).Children(func() {
					for i, b := range j.Bans {
						if i == 50 {
							ui.Text(c, fmt.Sprintf("… 以及另外 %d 个，见“封禁 IP”页", len(j.Bans)-50)).FontSize(12).TextColor(t.TextMuted).Padding(6, 10)
							break
						}
						ui.Row(c.Key(b.IP)).Padding(4, 6, 4, 10).Gap(8).AlignItems(ui.Center).Children(func() {
							ui.Text(c, b.IP).Font("monospace").FontSize(12.5).Grow(1).Selectable()
							ui.Text(c, remainingLabel(b, now)).FontSize(12).TextColor(t.TextMuted).FontFeatures("tnum")
							ui.Button(c, "解封").Label("解封 "+b.IP).Tooltip("解封 "+b.IP).Padding(1, 8).FontSize(12).Disabled(sv.busy != "").
								OnClick(func() { a.requestUnban(sv, []banRow{{Ban: b, Jail: j.Name}}) })
						})
					}
				})
			})
			section(c, fmt.Sprintf("匹配规则 failregex（%d）", len(j.FailRegex)), func() {
				ui.Text(c, "日志中匹配以下任一正则的行记为一次失败，<HOST> 处为来源 IP。").FontSize(12).TextColor(t.TextMuted)
				patterns(c, j.FailRegex)
			})
			if len(j.IgnoreRegex) > 0 {
				section(c, fmt.Sprintf("忽略规则 ignoreregex（%d）", len(j.IgnoreRegex)), func() {
					patterns(c, j.IgnoreRegex)
				})
			}
		})
	})
}

// banPhrase says what the jail does to a source: "封禁 1 小时", "永久封禁".
func banPhrase(j fail2ban.Jail) string {
	if j.Permanent() {
		return "永久封禁"
	}
	return "封禁 " + banTimeLabel(j)
}

// banDurationSentence says how long the jail bans for.
func banDurationSentence(j fail2ban.Jail) string {
	if j.Permanent() {
		return "永久"
	}
	s := durationLabel(j.BanTime)
	if j.BanIncrement {
		s += "，再次被封时递增"
		if j.BanMaxTime > 0 {
			s += "，最长 " + durationLabel(j.BanMaxTime)
		}
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// section is a titled part of a jail's details.
func section(c *ui.Context, title string, body func()) {
	ui.Column(c).Gap(8).Children(func() {
		ui.Text(c, title).FontSize(13.5).Bold()
		body()
	})
}

// patterns lists regular expressions, readably.
func patterns(c *ui.Context, res []string) {
	t := c.Theme()
	if len(res) == 0 {
		ui.Text(c, "没有").FontSize(12.5).TextColor(t.TextMuted)
		return
	}
	ui.Column(c).Gap(6).Children(func() {
		for i, re := range res {
			ui.Row(c.Key(i)).Gap(8).Padding(6, 10).Radius(6).Background(t.Surface).AlignItems(ui.Start).Children(func() {
				ui.Text(c, fmt.Sprint(i+1)).FontSize(11.5).TextColor(t.TextMuted).FontFeatures("tnum").Width(18).Shrink(0)
				ui.Text(c, fail2ban.Readable(re)).Font("monospace").FontSize(11.5).Grow(1).MinWidth(0).Selectable()
			})
		}
	})
}

// banColumns are the columns of the bans' table.
var banColumns = []ui.TableColumn{
	{Title: "IP", Width: 220, Sortable: true},
	{Title: "规则", Width: 140, Sortable: true},
	{Title: "封禁时间", Width: 150, Sortable: true},
	{Title: "剩余", Width: 120, Sortable: true},
	{Title: "解封时间"},
}

func (a *App) bansTab(c *ui.Context, sv *serverView, s *fail2ban.Status) {
	t := c.Theme()
	now := a.now()
	rows := banRows(s, sv.filter, sv.banSort, now)
	// The choice that shows: a filter hiding some leaves them alone.
	var chosen []banRow
	for _, r := range rows {
		if sv.banChosen.Has(r.Key()) {
			chosen = append(chosen, r)
		}
	}
	busy := sv.busy != ""
	unban := func() {
		if !busy {
			a.requestUnban(sv, chosen)
		}
	}
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
		label := "解封"
		if len(chosen) > 0 {
			label = fmt.Sprintf("解封 %d 项", len(chosen))
		}
		labeledButton(c, false, iconUnlock, label).Disabled(busy || len(chosen) == 0).OnClick(unban)
		ui.Text(c, "仍在封禁中的来源 IP；到期自动解封后不再列出。Cmd/Ctrl 或 Shift 点击可多选。").FontSize(12.5).TextColor(t.TextMuted).MinWidth(0).SingleLine()
		ui.Spacer(c)
		ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, iconSearch).FontSize(14).TextColor(t.TextMuted)
			ui.TextInput(c, &sv.filter).Placeholder("筛选 IP 或规则…").Label("筛选封禁").Width(240)
		})
	})
	if len(rows) == 0 {
		ui.Column(c).Grow(1).Center().Gap(8).Radius(8).Border(1, t.Border).Children(func() {
			if sv.filter != "" {
				ui.Text(c, "没有匹配的 IP").FontSize(15).Bold()
				ui.Text(c, "换个关键词试试，或清空筛选。").TextColor(t.TextMuted)
				return
			}
			ui.Icon(c, iconBan).FontSize(32).TextColor(t.TextMuted)
			ui.Text(c, "当前没有被封禁的 IP").FontSize(15).Bold()
			if n := s.TotalBanned(); n > 0 {
				ui.Text(c, fmt.Sprintf("fail2ban 启动以来共封禁 %d 次，均已到期自动解封。", n)).TextColor(t.TextMuted)
			}
		})
		return
	}
	sv.bans.Key = func(i int) any { return rows[i].Key() }
	sv.bans.Label = func(i int) string { return rows[i].IP }
	sv.bans.Sort = &sv.banSort
	sv.bans.Selection = &sv.banChosen
	if sv.bans.Shortcut(c, 0, ui.KeyDelete) || sv.bans.Shortcut(c, 0, ui.KeyBackspace) {
		unban()
	}
	ui.Table(c, &sv.bans, banColumns, len(rows), func(row, col int) {
		r := rows[row]
		// Chosen rows are on the accent color.
		muted, permanent := t.TextMuted, t.Danger
		if sv.banChosen.Has(r.Key()) {
			muted, permanent = t.AccentText, t.AccentText
		}
		switch col {
		case 0:
			ui.Text(c, r.IP).Font("monospace").SingleLine()
		case 1:
			ui.Text(c, r.Jail).SingleLine()
		case 2:
			ui.Text(c, timeLabel(r.Start, now)).FontFeatures("tnum").SingleLine()
		case 3:
			l := ui.Text(c, remainingLabel(r.Ban, now)).FontFeatures("tnum").SingleLine()
			if r.Permanent {
				l.TextColor(permanent)
			}
		case 4:
			end := "—"
			if r.Permanent {
				end = "不解封"
			} else if !r.End.IsZero() {
				end = timeLabel(r.End, now)
			}
			ui.Text(c, end).TextColor(muted).FontFeatures("tnum").SingleLine()
		}
	}).Grow(1).Label("封禁的 IP")
	c.After(time.Minute) // the time left
}

func firewallTab(c *ui.Context, s *fail2ban.Status) {
	t := c.Theme()
	ui.Text(c, "fail2ban 封禁时在防火墙中创建的链、表与集合（iptables / nftables / ipset），即实际生效的封禁规则。").FontSize(12.5).TextColor(t.TextMuted)
	if s.Firewall == "" {
		ui.Column(c).Grow(1).Center().Gap(8).Radius(8).Border(1, t.Border).Children(func() {
			ui.Icon(c, iconShield).FontSize(32).TextColor(t.TextMuted)
			ui.Text(c, "防火墙中没有 fail2ban 的规则").FontSize(15).Bold()
			ui.Text(c, "规则在第一次封禁时创建；使用其他封禁动作（如 hostsdeny、route）时这里也会为空。").TextColor(t.TextMuted)
		})
		return
	}
	ui.Scroll(c).Grow(1).Padding(14).Radius(8).Background(t.Surface).Children(func() {
		ui.Text(c, s.Firewall).Font("monospace").FontSize(12.5).NoWrap().Selectable()
	})
}

func (a *App) logTab(c *ui.Context, sv *serverView, log []session.Entry) {
	t := c.Theme()
	sv.logList.FollowEnd = true
	ui.List(c, &sv.logList, len(log), func(i int) {
		e := log[i]
		ui.Column(c).Gap(4).Padding(10, 12).BorderWidth(0, 0, 1, 0).BorderColor(t.Border).Children(func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				color, status := t.Success, "成功"
				if !e.OK() {
					color, status = t.Danger, fmt.Sprintf("退出码 %d", e.ExitCode)
					if e.Err != "" {
						status = "失败"
					}
				}
				dot(c, color)
				ui.Text(c, e.Time.Format("15:04:05")).FontSize(12).TextColor(t.TextMuted).FontFeatures("tnum")
				if e.Privileged {
					pill(c, "sudo", t.Warning)
				}
				ui.Text(c, status).FontSize(12).TextColor(color)
				ui.Spacer(c)
				ui.Text(c, fmt.Sprintf("%d ms", e.Duration.Milliseconds())).FontSize(12).TextColor(t.TextMuted)
			})
			ui.Text(c, e.Command).Font("monospace").FontSize(12).MaxLines(6).Selectable()
			out := e.Output
			if e.Err != "" {
				out = strings.TrimSpace(e.Err + "\n" + out)
			}
			if out != "" {
				ui.Text(c, out).Font("monospace").FontSize(11.5).TextColor(t.TextMuted).MaxLines(8).Selectable()
			}
		})
	}).Grow(1).Radius(8).Background(t.Surface).Label("操作日志").Children(func() {
		if len(log) == 0 {
			ui.Text(c, "还没有执行过命令").TextColor(t.TextMuted).Padding(16)
		}
	})
}
