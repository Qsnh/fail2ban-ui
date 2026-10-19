// Package gui is RuleLens's window: native UI that MyGo draws on the GPU,
// listing the servers of the inventory and the rules of fail2ban on each.
package gui

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/rulelens/rulelens/internal/fail2ban"
	"github.com/rulelens/rulelens/internal/remote"
	"github.com/rulelens/rulelens/internal/session"
	"github.com/rulelens/rulelens/internal/sshx"
	"github.com/rulelens/rulelens/internal/store"
)

// pageOverview is the page of every server; the other pages are the IDs
// of servers.
const pageOverview = "overview"

// connState is how far the connection to a server got.
type connState int

const (
	stateIdle connState = iota
	stateConnecting
	stateConnected
	stateFailed
)

// serverView is a server with its connection, fail2ban on it as last read,
// and the state of its page.
type serverView struct {
	srv store.Server
	// conn is the connection while connected, and info what it learned.
	conn  session.Conn
	info  session.Info
	state connState
	err   string
	// f2b is fail2ban as last read, and readErr why it could not be read
	// since the connection was made.
	f2b     *fail2ban.Status
	readErr string
	// gen counts the connections made and dropped: work started on one
	// leaves the state alone once another took its place.
	gen int
	// busy names the operation running, "" when none is; queued are the
	// operations asked for meanwhile, which run after it.
	busy   string
	queued []func()
	// loadedAt is when fail2ban was last read, and checkedAt when it was
	// last read or failed to be, from which the next reading is due.
	loadedAt  time.Time
	checkedAt time.Time

	// The page: its tab; the jails' table, its order and the jail shown;
	// the bans' filter, table, order and choice; and the log's list.
	tab      int
	jails    ui.ListState
	jailSort ui.SortOrder
	jail     string
	// jailRow is the row the table chose last, which showed jailShown.
	jailRow   int
	jailShown string
	filter    string
	bans      ui.ListState
	banSort   ui.SortOrder
	banChosen ui.Selection[string]
	logList   ui.ListState

	// history is the bans fail2ban made, lifted too, as last read for its
	// tab, historyErr why it could not be read when it never was, and
	// historyLoading whether a reading runs or waits. shownTab is the tab
	// shown last: showing the history's reads it again.
	history        *fail2ban.History
	historyErr     string
	historyLoading bool
	shownTab       int
	// The history's tab: by address or ban by ban, its filter, the tables
	// and their orders, the address chosen, and the rows as last listed.
	histMode   int
	histFilter string
	histIPs    ui.ListState
	histIPSort ui.SortOrder
	histChosen string
	histList   ui.ListState
	histSort   ui.SortOrder
	histMemo   historyMemo
}

// The tabs of a server's page.
const (
	tabRules = iota
	tabBans
	tabHistory
	tabFirewall
	tabLog
)

// status returns fail2ban of a server connected, nil otherwise.
func (sv *serverView) status() *fail2ban.Status {
	if sv.state != stateConnected {
		return nil
	}
	return sv.f2b
}

// running returns fail2ban of a server connected where it runs, nil
// otherwise.
func (sv *serverView) running() *fail2ban.Status {
	if s := sv.status(); s != nil && s.Running {
		return s
	}
	return nil
}

// Options are what the window needs.
type Options struct {
	Inventory *store.Inventory
	Vault     store.Vault
	Dialer    session.Dialer
	// Async runs work off the UI thread, then the function work returns
	// on it, as through mygo.Window.Update. Nil runs both at once, as
	// tests want.
	Async func(work func() func())
	// PickFile asks the user for a file, as a private key; nil hides the
	// buttons that would.
	PickFile func(title string) (string, error)
	// Now is the clock, time.Now when nil.
	Now func() time.Time
	// Settings are the user's, which SaveSettings saves as they change;
	// nil saves nothing.
	Settings     store.Settings
	SaveSettings func(store.Settings) error
}

// App is the state of the window.
type App struct {
	inv      *store.Inventory
	vault    store.Vault
	dialer   session.Dialer
	async    func(work func() func())
	pickFile func(title string) (string, error)
	now      func() time.Time

	settings     store.Settings
	saveSettings func(store.Settings) error

	page       string
	views      map[string]*serverView
	groupsOpen map[string]*bool
	// split is the share of the rules' tab its table takes, in percent.
	split float32

	serverForm serverForm
	ruleForm   ruleForm
	ruleSeq    int
	// alerts are the questions to ask, the first showing.
	alerts  []alert
	alertID int
	toasts  []ui.Toast
}

// New returns the window's state.
func New(o Options) *App {
	a := &App{
		inv:          o.Inventory,
		vault:        o.Vault,
		dialer:       o.Dialer,
		async:        o.Async,
		pickFile:     o.PickFile,
		now:          o.Now,
		settings:     o.Settings,
		saveSettings: o.SaveSettings,
		page:         pageOverview,
		views:        map[string]*serverView{},
		groupsOpen:   map[string]*bool{},
		split:        60,
	}
	if a.async == nil {
		a.async = func(work func() func()) { work()() }
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.vault == nil {
		a.vault = &store.MemoryVault{}
	}
	return a
}

// servers returns the views of the inventory's servers, in its order. It
// notices connections that died, as the keepalive closes them.
func (a *App) servers() []*serverView {
	list := a.inv.List()
	out := make([]*serverView, 0, len(list))
	seen := map[string]bool{}
	for _, s := range list {
		sv := a.views[s.ID]
		if sv == nil {
			sv = &serverView{srv: s}
			a.views[s.ID] = sv
		}
		sv.srv = s
		seen[s.ID] = true
		if sv.state == stateConnected && sv.busy == "" && !sv.conn.Alive() {
			a.drop(sv, stateFailed, "连接已断开，请重新连接")
		}
		out = append(out, sv)
	}
	for id, sv := range a.views {
		if !seen[id] {
			a.drop(sv, stateIdle, "")
			delete(a.views, id)
		}
	}
	return out
}

func (a *App) current() *serverView {
	if a.page == pageOverview {
		return nil
	}
	return a.views[a.page]
}

// Close closes the connections, as the app quits.
func (a *App) Close() {
	for _, sv := range a.views {
		if sv.conn != nil {
			sv.conn.Close()
		}
	}
}

func (a *App) toast(title string) {
	a.toasts = append(a.toasts, ui.Toast{Title: title, Type: "success"})
}

func (a *App) toastError(title string, err error) {
	a.toasts = append(a.toasts, ui.Toast{Title: title, Description: err.Error(), Type: "error", Timeout: 8 * time.Second})
}

// safe runs work, turning a panic into an error, so that a bug in reading
// a server does not take the window down.
func safe(work func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("内部错误：%v", r)
		}
	}()
	return work()
}

// drop closes the server's connection, if any, and forgets what it read:
// work still running on it will leave the state alone.
func (a *App) drop(sv *serverView, state connState, err string) {
	if sv.conn != nil {
		sv.conn.Close()
	}
	sv.gen++
	sv.conn, sv.info, sv.f2b, sv.readErr = nil, session.Info{}, nil, ""
	sv.state, sv.err = state, err
	sv.busy, sv.queued = "", nil
	sv.banChosen.Clear()
	sv.history, sv.historyErr, sv.historyLoading, sv.histMemo = nil, "", false, historyMemo{}
}

// readTimeout bounds a reading of fail2ban.
const readTimeout = time.Minute

// connect connects to the server, then reads fail2ban on it.
func (a *App) connect(sv *serverView) {
	if sv.state == stateConnecting {
		return
	}
	a.drop(sv, stateConnecting, "")
	gen, srv := sv.gen, sv.srv
	a.async(func() func() {
		var conn session.Conn
		var st *fail2ban.Status
		var readErr error
		err := safe(func() error {
			sec, err := a.vault.Get(srv.ID)
			if err != nil {
				return fmt.Errorf("读取保存的密码失败：%w", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second+readTimeout)
			defer cancel()
			conn, err = a.dialer.Dial(ctx, srv, sec)
			if err != nil {
				return err
			}
			st, readErr = fail2ban.Read(ctx, conn.Exec(), a.now())
			return nil
		})
		return func() {
			if a.views[srv.ID] != sv || sv.gen != gen {
				// The server was deleted, or connected anew, meanwhile.
				if conn != nil {
					conn.Close()
				}
				return
			}
			var unknown *sshx.UnknownHostError
			switch {
			case errors.As(err, &unknown):
				sv.state = stateIdle
				a.askTrust(sv, unknown)
			case err != nil:
				sv.state, sv.err = stateFailed, err.Error()
			default:
				sv.conn, sv.info, sv.state = conn, conn.Info(), stateConnected
				a.loaded(sv, st, readErr, false)
			}
		}
	})
}

// loaded takes a reading of fail2ban on the server. A failure keeps what
// was read before, and tells unless quiet, as automatic readings are: the
// page says it still.
func (a *App) loaded(sv *serverView, st *fail2ban.Status, err error, quiet bool) {
	sv.checkedAt = a.now()
	if err != nil {
		sv.readErr = err.Error()
		if sv.f2b != nil && !quiet {
			a.toastError(sv.srv.Title()+"：读取 fail2ban 失败", err)
		}
		return
	}
	sv.f2b, sv.readErr, sv.loadedAt = st, "", a.now()
	// Bans lifted meanwhile leave the choice.
	keys := map[string]bool{}
	for _, j := range st.Jails {
		for _, b := range j.Bans {
			keys[banRow{Ban: b, Jail: j.Name}.Key()] = true
		}
	}
	for key := range sv.banChosen.All() {
		if !keys[key] {
			sv.banChosen.Remove(key)
		}
	}
}

// askTrust asks whether to trust the key of a server met for the first time.
func (a *App) askTrust(sv *serverView, e *sshx.UnknownHostError) {
	msg := fmt.Sprintf("首次连接 %s（%s），无法确认这台服务器的身份。\n\n主机指纹：%s\n\n请与服务器上 ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub 的输出核对，一致后再信任。",
		sv.srv.Title(), e.Hostport, sshx.Fingerprint(e.Key))
	a.ask(alert{title: "确认主机指纹", message: msg, buttons: []string{"取消", "信任并连接"}, actions: []func(){nil, func() {
		if err := a.dialer.Trust(e.Hostport, e.Key); err != nil {
			a.toastError("保存主机指纹失败", err)
			return
		}
		a.connect(sv)
	}}})
}

func (a *App) disconnect(sv *serverView) {
	a.drop(sv, stateIdle, "")
}

// job is an operation on a server connected: work, if any, then a reading
// of fail2ban.
type job struct {
	// label names the job while it runs, as "解封"; done tells it went
	// well, "" for nothing.
	label, done string
	work        func(ctx context.Context, x remote.Executor) error
	// quiet keeps a reading that fails from telling, as automatic ones.
	quiet bool
	// after, when set, takes the outcome of the work, once fail2ban is
	// read again, and tells of its failure instead of a toast.
	after func(err error)
}

// run runs a job on a server connected. While another runs, it waits for
// it.
func (a *App) run(sv *serverView, j job) {
	if sv.state != stateConnected {
		a.toastError(j.label+"未执行", fmt.Errorf("%s 未连接", sv.srv.Title()))
		return
	}
	if sv.busy != "" {
		sv.queued = append(sv.queued, func() { a.run(sv, j) })
		return
	}
	sv.busy = j.label
	gen, conn := sv.gen, sv.conn
	a.async(func() func() {
		var st *fail2ban.Status
		var readErr error
		err := safe(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
			defer cancel()
			var err error
			if j.work != nil {
				err = j.work(ctx, conn.Exec())
			}
			// Read even when the work failed, which may have done some.
			st, readErr = fail2ban.Read(ctx, conn.Exec(), a.now())
			return err
		})
		return func() {
			if sv.gen != gen {
				return // the connection was dropped meanwhile
			}
			sv.busy = ""
			if !conn.Alive() {
				a.drop(sv, stateFailed, "连接已断开，请重新连接")
				return
			}
			if err != nil && j.after == nil {
				a.toastError(fmt.Sprintf("%s：%s失败", sv.srv.Title(), j.label), err)
			}
			a.loaded(sv, st, readErr, j.quiet)
			if err == nil && readErr == nil && j.done != "" {
				a.toast(j.done)
			}
			if j.after != nil {
				j.after(err)
			}
			if len(sv.queued) > 0 {
				next := sv.queued[0]
				sv.queued = sv.queued[1:]
				next()
			}
		}
	})
}

// read reads fail2ban on a server connected again, and the history of its
// bans while the page shows it, unless an operation runs, which reads
// fail2ban as it ends.
func (a *App) read(sv *serverView, quiet bool) {
	if sv.state != stateConnected || sv.busy != "" {
		return
	}
	if a.historyShown(sv) {
		a.loadHistory(sv, quiet)
		return
	}
	a.run(sv, job{label: "刷新", quiet: quiet})
}

// autoRefresh reads fail2ban again on the servers connected whose reading
// is due, as the settings say, and returns how long until the next is, 0
// for never. Servers not connected are left alone: connecting again and
// again with a password since changed would have fail2ban ban this
// computer.
func (a *App) autoRefresh(servers []*serverView) time.Duration {
	every := a.settings.RefreshEvery()
	if every <= 0 {
		return 0
	}
	now := a.now()
	next := every
	for _, sv := range servers {
		if sv.state != stateConnected || sv.busy != "" {
			continue
		}
		due := sv.checkedAt.Add(every)
		if !now.Before(due) {
			a.read(sv, true)
			continue
		}
		next = min(next, due.Sub(now))
	}
	return next
}

// setRefresh sets how often fail2ban is read again, and saves it.
func (a *App) setRefresh(secs int) {
	a.settings.RefreshSeconds = secs
	if a.saveSettings != nil {
		if err := a.saveSettings(a.settings); err != nil {
			a.toastError("保存设置失败", err)
		}
	}
}

// requestUnban asks to lift the bans of rows, then lifts them. An address
// some other jail bans as well stays banned there unless chosen too: the
// question offers to lift those bans as well.
func (a *App) requestUnban(sv *serverView, rows []banRow) {
	s := sv.running()
	if s == nil || len(rows) == 0 {
		return
	}
	chosen := map[string]bool{}
	for _, r := range rows {
		chosen[r.Key()] = true
	}
	var others []banRow
	for _, j := range s.Jails {
		for _, b := range j.Bans {
			r := banRow{Ban: b, Jail: j.Name}
			if !chosen[r.Key()] && slices.ContainsFunc(rows, func(c banRow) bool { return c.IP == b.IP }) {
				others = append(others, r)
			}
		}
	}
	unban := func(rows []banRow) func() {
		us := unbannings(rows)
		ips := map[string]bool{}
		for _, r := range rows {
			ips[r.IP] = true
		}
		return func() {
			a.run(sv, job{
				label: "解封",
				work: func(ctx context.Context, x remote.Executor) error {
					return fail2ban.Unban(ctx, x, us)
				},
				done: fmt.Sprintf("已在 %s 上解封 %d 个 IP", sv.srv.Title(), len(ips)),
			})
		}
	}
	msg := fmt.Sprintf("将在 %s 上解封以下 %d 项：\n", sv.srv.Title(), len(rows))
	for i, r := range rows {
		if i == 8 {
			msg += fmt.Sprintf("… 以及另外 %d 项\n", len(rows)-8)
			break
		}
		msg += fmt.Sprintf("• %s（%s）\n", r.IP, r.Jail)
	}
	cmd, err := fail2ban.UnbanCommand(unbannings(rows))
	if err != nil {
		a.toastError("无法解封", err)
		return
	}
	msg += "\n将执行：sudo " + cmd
	al := alert{
		title:   fmt.Sprintf("解封 %d 项？", len(rows)),
		buttons: []string{"取消", "解封"}, actions: []func(){nil, unban(rows)},
	}
	if len(rows) == 1 {
		al.title = fmt.Sprintf("解封 %s？", rows[0].IP)
	}
	if len(others) > 0 {
		msg += "\n\n注意：所选 IP 还被其他 jail 封禁，只解封所选的项后仍无法访问："
		for _, r := range others {
			msg += fmt.Sprintf("\n• %s（%s）", r.IP, r.Jail)
		}
		al.buttons = []string{"取消", "仅解封所选", "在所有 jail 中解封"}
		al.actions = []func(){nil, unban(rows), unban(append(slices.Clone(rows), others...))}
	}
	al.message = msg
	a.ask(al)
}

// unbannings gathers rows by jail, in their order.
func unbannings(rows []banRow) []fail2ban.Unbanning {
	var us []fail2ban.Unbanning
	for _, r := range rows {
		i := slices.IndexFunc(us, func(u fail2ban.Unbanning) bool { return u.Jail == r.Jail })
		if i < 0 {
			us = append(us, fail2ban.Unbanning{Jail: r.Jail})
			i = len(us) - 1
		}
		if !slices.Contains(us[i].IPs, r.IP) {
			us[i].IPs = append(us[i].IPs, r.IP)
		}
	}
	return us
}

// refresh reads fail2ban on the server again, connecting first unless it
// is connected.
func (a *App) refresh(sv *serverView) {
	switch sv.state {
	case stateConnecting:
		// It reads fail2ban as it connects.
	case stateConnected:
		a.read(sv, false)
	default:
		a.connect(sv)
	}
}

// refreshAll connects to every server, or reads fail2ban on those
// connected again.
func (a *App) refreshAll() {
	for _, sv := range a.servers() {
		a.refresh(sv)
	}
}

func (a *App) requestDeleteServer(sv *serverView) {
	a.ask(alert{
		title:   fmt.Sprintf("删除服务器“%s”？", sv.srv.Title()),
		message: "将从 RuleLens 中移除这台服务器及其保存的密码，不会改动服务器上的任何配置。",
		buttons: []string{"取消", "删除服务器"},
		actions: []func(){nil, func() {
			if err := a.inv.Delete(sv.srv.ID); err != nil {
				a.toastError("删除失败", err)
				return
			}
			a.vault.Delete(sv.srv.ID)
			if a.page == sv.srv.ID {
				a.page = pageOverview
			}
			a.servers()
			a.toast("已删除 " + sv.srv.Title())
		}},
	})
}
