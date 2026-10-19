package gui

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/rulelens/rulelens/internal/fail2ban"
	"github.com/rulelens/rulelens/internal/remote"
)

// The views of the history: by address, or ban by ban.
const (
	historyByIP = iota
	historyByBan
)

// loadHistory reads the history of the bans on a server connected, and
// fail2ban with it. A failure keeps the history read before, and tells
// unless quiet, as automatic readings are; without one, the tab says it.
func (a *App) loadHistory(sv *serverView, quiet bool) {
	if sv.state != stateConnected || sv.historyLoading {
		return
	}
	sv.historyLoading = true
	label := "读取封禁历史"
	if quiet {
		label = "刷新"
	}
	var h *fail2ban.History
	a.run(sv, job{
		label: label,
		quiet: quiet,
		work: func(ctx context.Context, x remote.Executor) error {
			var err error
			h, err = fail2ban.ReadHistory(ctx, x, a.now())
			return err
		},
		after: func(err error) {
			sv.historyLoading = false
			switch {
			case err == nil:
				sv.history, sv.historyErr = h, ""
			case sv.history == nil:
				sv.historyErr = err.Error()
			case !quiet:
				a.toastError(sv.srv.Title()+"：读取封禁历史失败", err)
			}
		},
	})
}

// historyShown reports whether the page shows the history of the server.
func (a *App) historyShown(sv *serverView) bool {
	return a.page == sv.srv.ID && sv.tab == tabHistory && sv.running() != nil
}

// ipHistory is an address the history has: how many times which jails
// banned it, the first and the last time, zero when its bans began before
// the history, and whether a ban is in effect.
type ipHistory struct {
	IP          string
	Bans        int
	Jails       []string
	First, Last time.Time
	Active      bool
}

// historyMemo keeps what the history's tab shows while what it comes from
// stays, as the tab builds again and again.
type historyMemo struct {
	h      *fail2ban.History
	s      *fail2ban.Status
	merged []fail2ban.PastBan

	query     string
	mode      int
	sort      ui.SortOrder
	ready     bool
	matched   int // addresses among the bans matching the query
	bans      []fail2ban.PastBan
	keys      []string
	addresses []ipHistory
}

// historyRows returns what the history's tab lists: the bans of the
// history matching its filter, with what s says of those in effect, ban by
// ban or by address as the tab says, sorted.
func (sv *serverView) historyRows(s *fail2ban.Status) *historyMemo {
	m := &sv.histMemo
	if m.h != sv.history || m.s != s {
		*m = historyMemo{h: sv.history, s: s, merged: sv.history.Merged(s)}
	}
	sort := sv.histSort
	if sv.histMode == historyByIP {
		sort = sv.histIPSort
	}
	if m.ready && m.query == sv.histFilter && m.mode == sv.histMode && m.sort == sort {
		return m
	}
	m.ready, m.query, m.mode, m.sort = true, sv.histFilter, sv.histMode, sort
	q := strings.ToLower(strings.TrimSpace(sv.histFilter))
	var bans []fail2ban.PastBan
	ips := map[string]bool{}
	for _, b := range m.merged {
		if q == "" || strings.Contains(strings.ToLower(b.IP+" "+b.Jail), q) {
			bans = append(bans, b)
			ips[b.IP] = true
		}
	}
	m.matched = len(ips)
	m.bans, m.keys, m.addresses = nil, nil, nil
	if sv.histMode == historyByIP {
		m.bans = bans
		m.addresses = byAddress(bans, sort)
		return m
	}
	m.bans = sortPastBans(bans, sort)
	// Keys for the rows, unique even for bans the log tells alike.
	seen := map[string]int{}
	m.keys = make([]string, len(m.bans))
	for i, b := range m.bans {
		k := fmt.Sprintf("%s %d %d", b.Key(), b.Start.UnixNano(), b.End.UnixNano())
		seen[k]++
		if n := seen[k]; n > 1 {
			k += fmt.Sprintf(" #%d", n)
		}
		m.keys[i] = k
	}
	return m
}

// when is when a ban began, or ended for one begun before the history.
func when(b fail2ban.PastBan) time.Time {
	if b.Start.IsZero() {
		return b.End
	}
	return b.Start
}

// banLength is how long a ban lasts: for ever, or until it ended or
// ends; 0 when not told.
func banLength(b fail2ban.PastBan) time.Duration {
	switch {
	case b.Permanent:
		return 1<<63 - 1
	case b.Start.IsZero() || b.End.IsZero():
		return 0
	}
	return b.End.Sub(b.Start)
}

// sortPastBans sorts bans as the table says, the latest first unless it
// says otherwise.
func sortPastBans(bans []fail2ban.PastBan, sort ui.SortOrder) []fail2ban.PastBan {
	cmp := func(x, y fail2ban.PastBan) int {
		switch sort.Column {
		case "IP":
			return compareIPs(x.IP, y.IP)
		case "规则":
			return strings.Compare(x.Jail, y.Jail)
		case "解封时间":
			// Bans for ever end last.
			if x.Permanent != y.Permanent {
				return compareBools(x.Permanent, y.Permanent)
			}
			return x.End.Compare(y.End)
		case "时长":
			return compare(banLength(x), banLength(y))
		case "状态":
			return compareBools(x.Active, y.Active)
		}
		return when(x).Compare(when(y))
	}
	slices.SortStableFunc(bans, cmp)
	if sort.Descending || sort.Column == "" {
		slices.Reverse(bans)
	}
	return bans
}

// byAddress gathers bans by address, sorted as the table says, the
// address banned last first unless it says otherwise.
func byAddress(bans []fail2ban.PastBan, sort ui.SortOrder) []ipHistory {
	var out []ipHistory
	index := map[string]int{}
	for _, b := range bans {
		i, ok := index[b.IP]
		if !ok {
			i = len(out)
			index[b.IP] = i
			out = append(out, ipHistory{IP: b.IP})
		}
		r := &out[i]
		r.Bans++
		if !slices.Contains(r.Jails, b.Jail) {
			r.Jails = append(r.Jails, b.Jail)
		}
		if t := b.Start; !t.IsZero() {
			if r.First.IsZero() || t.Before(r.First) {
				r.First = t
			}
			if t.After(r.Last) {
				r.Last = t
			}
		}
		r.Active = r.Active || b.Active
	}
	for i := range out {
		slices.Sort(out[i].Jails)
	}
	cmp := func(x, y ipHistory) int {
		switch sort.Column {
		case "IP":
			return compareIPs(x.IP, y.IP)
		case "封禁次数":
			return compare(x.Bans, y.Bans)
		case "首次封禁":
			return x.First.Compare(y.First)
		case "状态":
			return compareBools(x.Active, y.Active)
		}
		return x.Last.Compare(y.Last)
	}
	slices.SortStableFunc(out, cmp)
	if sort.Descending || sort.Column == "" {
		slices.Reverse(out)
	}
	return out
}

func compareBools(a, b bool) int {
	switch {
	case a == b:
		return 0
	case b:
		return -1
	}
	return 1
}

// historySource says where the history comes from, how far back it goes,
// and what it lacks.
func historySource(h *fail2ban.History) string {
	var s string
	switch h.Source {
	case fail2ban.SourceFile:
		log := h.Target
		if len(h.Files) > 0 {
			log = h.Files[len(h.Files)-1]
		}
		s = "记录来自 fail2ban 日志 " + log
		if n := len(h.Files) - 1; n > 0 {
			s += fmt.Sprintf(" 及 %d 个轮转的旧日志", n)
		}
	case fail2ban.SourceJournal:
		s = "记录来自 systemd 日志（fail2ban）"
	case fail2ban.SourceDB:
		s = fmt.Sprintf("fail2ban 的日志不在文件中（logtarget 为 %s），记录来自 fail2ban 数据库：只保留最近 %s，且不含手动解封的封禁", h.Target, durationLabel(h.PurgeAge))
	}
	if !h.Since.IsZero() {
		s += "，最早一条记录于 " + h.Since.Format("2006-01-02 15:04")
	}
	if h.Truncated {
		s += fmt.Sprintf("；共 %d 条记录，只读取了最近 %d 条", h.Count, fail2ban.HistoryLimit)
	}
	return s + "。"
}

// historyColumns are the columns of the history ban by ban, and
// addressColumns those of the history by address.
var (
	historyColumns = []ui.TableColumn{
		{Title: "IP", Width: 200, Sortable: true},
		{Title: "规则", Width: 120, Sortable: true},
		{Title: "封禁时间", Width: 140, Sortable: true},
		{Title: "解封时间", Width: 160, Sortable: true},
		{Title: "时长", Width: 110, Sortable: true},
		{Title: "状态", Sortable: true},
	}
	addressColumns = []ui.TableColumn{
		{Title: "IP", Width: 180, Sortable: true},
		{Title: "封禁次数", Width: 84, Align: ui.End, Sortable: true},
		{Title: "规则", Width: 220},
		{Title: "首次封禁", Width: 140, Sortable: true},
		{Title: "最近封禁", Width: 140, Sortable: true},
		{Title: "状态", Sortable: true},
	}
)

// historyTab lists the addresses fail2ban banned, those lifted too, as
// far back as its log goes.
func (a *App) historyTab(c *ui.Context, sv *serverView, s *fail2ban.Status) {
	t := c.Theme()
	if sv.history == nil && sv.historyErr == "" && !sv.historyLoading {
		a.loadHistory(sv, false)
	}
	h := sv.history
	retry := func() {
		labeledButton(c, false, iconRefresh, "重试").Disabled(sv.busy != "").OnClick(func() { a.loadHistory(sv, false) })
	}
	boxed := func(body func()) {
		ui.Column(c).Grow(1).Center().Gap(8).Radius(8).Border(1, t.Border).Padding(16).Children(body)
	}
	switch {
	case h == nil && sv.historyErr != "":
		boxed(func() {
			ui.Icon(c, iconAlert).FontSize(32).TextColor(t.TextMuted)
			ui.Text(c, "未能读取封禁历史").FontSize(15).Bold()
			ui.Text(c, sv.historyErr).TextColor(t.TextMuted).TextAlign(ui.Center).MaxWidth(560).Selectable()
			retry()
		})
		return
	case h == nil:
		boxed(func() {
			ui.Spinner(c).Size(24, 24).Label("读取中")
			ui.Text(c, "正在读取封禁历史…").TextColor(t.TextMuted)
		})
		return
	case h.Source == "":
		boxed(func() {
			ui.Icon(c, iconHistory).FontSize(32).TextColor(t.TextMuted)
			ui.Text(c, "未能读取封禁历史").FontSize(15).Bold()
			ui.Text(c, h.Problem).TextColor(t.TextMuted).TextAlign(ui.Center).MaxWidth(560).Selectable()
			retry()
		})
		return
	}
	m := sv.historyRows(s)
	ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
		ui.Segmented(c, &sv.histMode, "按 IP", "按次").Label("历史视图")
		count := "共"
		if strings.TrimSpace(m.query) != "" {
			count = "匹配"
		}
		ui.Text(c, fmt.Sprintf("%s %d 个 IP，封禁 %d 次", count, m.matched, len(m.bans))).FontSize(12.5).TextColor(t.TextMuted).FontFeatures("tnum").SingleLine()
		ui.Spacer(c)
		ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, iconSearch).FontSize(14).TextColor(t.TextMuted)
			ui.TextInput(c, &sv.histFilter).Placeholder("筛选 IP 或规则…").Label("筛选历史").Width(240)
		})
	})
	// The rows are those of the view and the filter of then: those the
	// controls take now show next.
	if sv.histMode != m.mode || sv.histFilter != m.query {
		c.Invalidate()
	}
	note := historySource(h)
	if m.mode == historyByIP && len(m.addresses) > 0 {
		note += "双击 IP 查看它的每次封禁。"
	}
	ui.Text(c, note).FontSize(12).TextColor(t.TextMuted).MaxLines(2).Selectable()
	if len(h.Problems) > 0 {
		ui.Text(c, "部分记录读取失败："+strings.Join(h.Problems, "；")).FontSize(12).TextColor(t.Warning).MaxLines(2).Selectable()
	}
	if len(m.bans) == 0 {
		boxed(func() {
			if strings.TrimSpace(m.query) != "" {
				ui.Text(c, "没有匹配的记录").FontSize(15).Bold()
				ui.Text(c, "换个关键词试试，或清空筛选。").TextColor(t.TextMuted)
				return
			}
			ui.Icon(c, iconHistory).FontSize(32).TextColor(t.TextMuted)
			ui.Text(c, "没有封禁记录").FontSize(15).Bold()
			ui.Text(c, "fail2ban 还没有封禁过 IP，或封禁的记录已随旧日志删除。").TextColor(t.TextMuted)
		})
		return
	}
	now := a.now()
	if m.mode == historyByIP {
		a.addressTable(c, sv, m.addresses)
	} else {
		bansTable(c, sv, m.bans, m.keys, now)
	}
	c.After(time.Minute) // the bans ending
}

// addressTable lists the addresses of the history; a double click on one
// lists its bans.
func (a *App) addressTable(c *ui.Context, sv *serverView, rows []ipHistory) {
	t := c.Theme()
	now := a.now()
	chosen := slices.IndexFunc(rows, func(r ipHistory) bool { return r.IP == sv.histChosen })
	sv.histIPs.Key = func(i int) any { return rows[i].IP }
	sv.histIPs.Label = func(i int) string { return rows[i].IP }
	sv.histIPs.Sort = &sv.histIPSort
	sv.histIPs.Selected = &chosen
	submitted := ui.Table(c, &sv.histIPs, addressColumns, len(rows), func(row, col int) {
		r := rows[row]
		// The chosen row is on the accent color.
		muted, banned := t.TextMuted, t.Danger
		if row == chosen {
			muted, banned = t.AccentText, t.AccentText
		}
		switch col {
		case 0:
			ui.Text(c, r.IP).Font("monospace").SingleLine()
		case 1:
			ui.Text(c, fmt.Sprint(r.Bans)).FontFeatures("tnum").FontWeight(600)
		case 2:
			jails := strings.Join(r.Jails, ", ")
			ui.Text(c, jails).SingleLine().Tooltip(jails)
		case 3:
			ui.Text(c, timeLabel(r.First, now)).FontFeatures("tnum").TextColor(muted).SingleLine()
		case 4:
			ui.Text(c, timeLabel(r.Last, now)).FontFeatures("tnum").SingleLine()
		case 5:
			if r.Active {
				pill(c, "封禁中", banned)
			} else {
				ui.Text(c, "已解封").TextColor(muted).SingleLine()
			}
		}
	}).Grow(1).Label("封禁过的 IP").Submitted()
	if chosen >= 0 && chosen < len(rows) {
		sv.histChosen = rows[chosen].IP
		if submitted {
			sv.histFilter, sv.histMode = sv.histChosen, historyByBan
		}
	}
}

// bansTable lists the bans of the history, one by one, keyed by keys.
func bansTable(c *ui.Context, sv *serverView, rows []fail2ban.PastBan, keys []string, now time.Time) {
	t := c.Theme()
	sv.histList.Key = func(i int) any { return keys[i] }
	sv.histList.Label = func(i int) string { return rows[i].IP }
	sv.histList.Sort = &sv.histSort
	ui.Table(c, &sv.histList, historyColumns, len(rows), func(row, col int) {
		b := rows[row]
		switch col {
		case 0:
			ui.Text(c, b.IP).Font("monospace").SingleLine()
		case 1:
			ui.Text(c, b.Jail).SingleLine()
		case 2:
			if b.Start.IsZero() {
				ui.Text(c, "早于记录").TextColor(t.TextMuted).SingleLine().Tooltip("这次封禁开始于最早的一条记录之前")
				return
			}
			ui.Text(c, timeLabel(b.Start, now)).FontFeatures("tnum").SingleLine()
		case 3:
			switch {
			case b.Active && b.Permanent:
				ui.Text(c, "不解封").TextColor(t.Danger).SingleLine()
			case b.Active && !b.End.IsZero():
				ui.Text(c, "预计 "+timeLabel(b.End, now)).FontFeatures("tnum").TextColor(t.TextMuted).SingleLine()
			case b.End.IsZero():
				ui.Text(c, "—").TextColor(t.TextMuted).Tooltip("记录中没有解封的时间")
			default:
				ui.Text(c, timeLabel(b.End, now)).FontFeatures("tnum").SingleLine()
			}
		case 4:
			l := "—"
			if b.Permanent {
				l = "永久"
			} else if d := banLength(b); d > 0 {
				l = durationLabel(d)
			}
			ui.Text(c, l).FontFeatures("tnum").TextColor(t.TextMuted).SingleLine()
		case 5:
			if b.Active {
				pill(c, "封禁中", t.Danger)
			} else {
				ui.Text(c, "已解封").TextColor(t.TextMuted).SingleLine()
			}
		}
	}).Grow(1).Label("封禁记录")
}
