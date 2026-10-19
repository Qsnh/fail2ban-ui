package gui

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/egoist/mygo/ui"

	"github.com/rulelens/rulelens/internal/sshx"
	"github.com/rulelens/rulelens/internal/store"
)

// alert is a question with buttons, each with its action (nil to cancel).
// The last button is the default, unless cancelDefault puts the focus on
// the first, for answers that cannot be undone.
type alert struct {
	id             int
	title, message string
	buttons        []string
	actions        []func()
	cancelDefault  bool
}

// ask asks a question once those asked before are answered.
func (a *App) ask(al alert) {
	a.alertID++
	al.id = a.alertID
	a.alerts = append(a.alerts, al)
}

// alertDialog shows the first question, wider than ui.AlertDialog so that
// the longer answers fit. Escape or a click outside cancels.
func (a *App) alertDialog(c *ui.Context) {
	if len(a.alerts) == 0 {
		return
	}
	t := c.Theme()
	al := a.alerts[0]
	open, chosen := true, -1
	ui.Modal(c.Key(al.id), &open, func() {
		ui.Column(c).Width(460).Gap(12).Children(func() {
			ui.Text(c, al.title).FontSize(16).Bold()
			ui.Text(c, al.message).TextColor(t.TextMuted).Selectable()
			ui.Row(c).Gap(8).Justify(ui.End).Wrap().Margin(8, 0, 0, 0).Children(func() {
				for i, label := range al.buttons {
					var b ui.Element
					if i == len(al.buttons)-1 {
						b = ui.PrimaryButton(c, label)
					} else {
						b = ui.Button(c, label)
					}
					if i == 0 && al.cancelDefault || i == len(al.buttons)-1 && !al.cancelDefault {
						b.AutoFocus()
					}
					if b.Clicked() {
						chosen = i
					}
				}
			})
		})
	})
	if chosen < 0 && open {
		return
	}
	a.alerts = a.alerts[1:]
	if chosen >= 0 && chosen < len(al.actions) && al.actions[chosen] != nil {
		al.actions[chosen]()
	}
}

// authMethods are the ways to sign in, in the order of the form's segments.
var authMethods = []sshx.AuthMethod{sshx.AuthPassword, sshx.AuthKey, sshx.AuthAgent}

// serverForm is the dialog adding or editing a server.
type serverForm struct {
	open bool
	// editing is the ID of the server edited, "" for a new one.
	editing    string
	name, host string
	port, user string
	auth       int
	password   string
	keyPath    string
	passphrase string
	sudo       string
	group      string
	note       string
	// saved tells which secrets the vault holds already, which empty
	// fields keep.
	saved store.Secrets
	err   string
}

// NewServer opens the dialog adding a server.
func (a *App) NewServer() {
	a.serverForm = serverForm{open: true, port: "22", user: "root"}
}

func (a *App) editServer(sv *serverView) {
	s := sv.srv
	f := serverForm{
		open: true, editing: s.ID,
		name: s.Name, host: s.Host, port: strconv.Itoa(s.Port), user: s.User,
		keyPath: s.KeyPath, group: s.Group, note: s.Note,
	}
	f.auth = max(slices.Index(authMethods, s.Auth), 0)
	if sec, err := a.vault.Get(s.ID); err == nil {
		f.saved = sec
	}
	a.serverForm = f
}

func savedHint(saved string, hint string) string {
	if saved != "" {
		return "已保存，留空则不修改"
	}
	return hint
}

// server returns the server of the form, checked, with its secrets.
func (f *serverForm) server() (store.Server, store.Secrets, error) {
	port, err := strconv.Atoi(strings.TrimSpace(f.port))
	if err != nil {
		return store.Server{}, store.Secrets{}, fmt.Errorf("端口 %q 不是数字", f.port)
	}
	s := store.Server{
		ID:      f.editing,
		Name:    strings.TrimSpace(f.name),
		Host:    strings.TrimSpace(f.host),
		Port:    port,
		User:    strings.TrimSpace(f.user),
		Auth:    authMethods[f.auth],
		KeyPath: strings.TrimSpace(f.keyPath),
		Group:   strings.TrimSpace(f.group),
		Note:    strings.TrimSpace(f.note),
	}
	if s.Auth != sshx.AuthKey {
		s.KeyPath = ""
	}
	if err := s.Validate(); err != nil {
		return store.Server{}, store.Secrets{}, err
	}
	keep := func(typed, saved string) string {
		if typed != "" {
			return typed
		}
		return saved
	}
	sec := store.Secrets{SudoPassword: keep(f.sudo, f.saved.SudoPassword)}
	switch s.Auth {
	case sshx.AuthPassword:
		sec.Password = keep(f.password, f.saved.Password)
		if sec.Password == "" {
			return store.Server{}, store.Secrets{}, fmt.Errorf("请填写登录密码")
		}
	case sshx.AuthKey:
		sec.Passphrase = keep(f.passphrase, f.saved.Passphrase)
	}
	return s, sec, nil
}

func (a *App) saveServer() {
	f := &a.serverForm
	s, sec, err := f.server()
	if err != nil {
		f.err = err.Error()
		return
	}
	isNew := s.ID == ""
	if isNew {
		s.ID = store.NewID()
	}
	if err := a.vault.Set(s.ID, sec); err != nil {
		f.err = "保存密码失败：" + err.Error()
		return
	}
	if err := a.inv.Put(s); err != nil {
		f.err = "保存服务器失败：" + err.Error()
		return
	}
	f.open = false
	a.servers()
	sv := a.views[s.ID]
	a.page = s.ID
	if isNew {
		a.toast("已添加 " + s.Title())
		if !a.vault.Persistent() && (sec.Password != "" || sec.Passphrase != "" || sec.SudoPassword != "") {
			a.toasts = append(a.toasts, ui.Toast{Title: "系统钥匙串不可用", Description: "密码仅在本次运行中保存，重启后需重新填写。", Type: "error"})
		}
	} else {
		a.toast("已保存 " + s.Title())
	}
	// A new address or new credentials take a new connection.
	a.connect(sv)
}

func (a *App) serverDialog(c *ui.Context) {
	f := &a.serverForm
	t := c.Theme()
	ui.Modal(c, &f.open, func() {
		ui.Column(c).Width(520).Gap(14).Children(func() {
			title := "添加服务器"
			if f.editing != "" {
				title = "编辑服务器"
			}
			ui.Text(c, title).FontSize(18).Bold()
			ui.Form(c, func() {
				ui.Field(c, "名称", func() {
					ui.TextInput(c, &f.name).Placeholder("例如 web-01（可选）").Label("服务器名称").AutoFocus()
				})
				ui.Field(c, "主机", func() {
					ui.Row(c).Gap(8).Children(func() {
						ui.TextInput(c, &f.host).Placeholder("IP 或域名").Label("主机地址").Grow(1)
						ui.Text(c, "端口").TextColor(t.TextMuted)
						ui.TextInput(c, &f.port).Label("SSH 端口").Width(72)
					})
				})
				ui.Field(c, "用户名", func() {
					ui.TextInput(c, &f.user).Placeholder("root 或可 sudo 的用户").Label("登录用户名")
				})
				ui.Field(c, "认证方式", func() {
					ui.Segmented(c, &f.auth, "密码", "私钥", "SSH Agent").Label("认证方式")
				})
				switch authMethods[f.auth] {
				case sshx.AuthPassword:
					ui.Field(c, "密码", func() {
						ui.TextInput(c, &f.password).Password().Placeholder(savedHint(f.saved.Password, "登录密码")).Label("登录密码")
					})
				case sshx.AuthKey:
					ui.Field(c, "私钥文件", func() {
						ui.Row(c).Gap(8).Children(func() {
							ui.TextInput(c, &f.keyPath).Placeholder("~/.ssh/id_ed25519").Label("私钥文件路径").Grow(1)
							if a.pickFile != nil && ui.Button(c, "选择…").Clicked() {
								if p, err := a.pickFile("选择 SSH 私钥"); err == nil && p != "" {
									f.keyPath = p
								}
							}
						})
					})
					ui.Field(c, "私钥口令", func() {
						ui.TextInput(c, &f.passphrase).Password().Placeholder(savedHint(f.saved.Passphrase, "未加密的私钥留空")).Label("私钥口令")
					})
				case sshx.AuthAgent:
					ui.Field(c, "", func() {
						ui.Text(c, "使用本机 ssh-agent（SSH_AUTH_SOCK）中已加载的密钥。").TextColor(t.TextMuted)
					})
				}
				ui.Field(c, "sudo 密码", func() {
					hint := "非 root 用户执行 sudo 时使用；留空则用登录密码"
					if authMethods[f.auth] != sshx.AuthPassword {
						hint = "非 root 用户执行 sudo 时使用；NOPASSWD 可留空"
					}
					ui.TextInput(c, &f.sudo).Password().Placeholder(savedHint(f.saved.SudoPassword, hint)).Label("sudo 密码")
				})
				ui.Field(c, "分组", func() {
					ui.TextInput(c, &f.group).Placeholder("例如 生产、测试（可选）").Label("服务器分组")
				})
				ui.Field(c, "备注", func() {
					ui.TextInput(c, &f.note).Placeholder("可选").Label("服务器备注")
				})
			})
			if f.err != "" {
				ui.Text(c, f.err).TextColor(t.Danger)
			}
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "取消").Clicked() {
					f.open = false
				}
				label := "添加并连接"
				if f.editing != "" {
					label = "保存并重新连接"
				}
				if ui.PrimaryButton(c, label).Clicked() {
					a.saveServer()
				}
			})
		})
	})
}
