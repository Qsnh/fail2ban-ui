// RuleLens shows the rules of fail2ban on servers, read over SSH, in a native
// window that MyGo draws on the GPU.
//
//	go tool mygo dev     # develop with live reload
//	go tool mygo build   # package the app
package main

import (
	"log"
	"path/filepath"

	"github.com/egoist/mygo"
	// MyGo's own strings, as its menus and controls show them, in Chinese.
	_ "github.com/egoist/mygo/locales/zh-Hans"
	"github.com/egoist/mygo/ui"

	"github.com/rulelens/rulelens/internal/gui"
	"github.com/rulelens/rulelens/internal/session"
	"github.com/rulelens/rulelens/internal/sshx"
	"github.com/rulelens/rulelens/internal/store"
)

func main() {
	app := mygo.App
	// The name decides the user data directory, so it comes first.
	app.SetName("RuleLens")
	// The app is written in Chinese: MyGo's own menus and controls follow.
	app.SetLanguages("zh-Hans")

	dir, err := app.Path(mygo.PathUserData)
	if err != nil {
		log.Fatal(err)
	}
	inv, err := store.Open(filepath.Join(dir, "servers.json"))
	if err != nil {
		log.Fatal(err)
	}
	hostKeys := sshx.NewHostKeys(filepath.Join(dir, "known_hosts"), sshx.UserKnownHosts())
	settingsPath := filepath.Join(dir, "settings.json")
	settings, err := store.LoadSettings(settingsPath)
	if err != nil {
		// A damaged file leaves the defaults, which saving replaces it with.
		log.Print(err)
	}

	var win *mygo.Window
	a := gui.New(gui.Options{
		Inventory: inv,
		Vault:     store.NewKeychainVault(mygo.Secrets, mygo.ErrSecretNotFound),
		Dialer:    &session.SSHDialer{HostKeys: hostKeys},
		Settings:  settings,
		SaveSettings: func(s store.Settings) error {
			return store.SaveSettings(settingsPath, s)
		},
		// SSH work runs on goroutines, and its results reach the view on
		// the main thread.
		Async: func(work func() func()) {
			go func() {
				apply := work()
				win.Update(apply)
			}()
		},
		PickFile: func(title string) (string, error) {
			paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
				Parent:          win,
				Title:           title,
				DefaultPath:     sshx.ExpandHome("~/.ssh"),
				ShowHiddenFiles: true,
			})
			if err != nil || len(paths) == 0 {
				return "", err
			}
			return paths[0], nil
		},
	})

	app.WhenReady(func() {
		app.SetMenu(mygo.NewMenu([]*mygo.MenuItem{
			{Role: mygo.RoleAppMenu},
			{Label: "服务器", Submenu: []*mygo.MenuItem{
				{Label: "添加服务器…", Accelerator: "CmdOrCtrl+N", Click: func(*mygo.MenuItem, *mygo.Window) {
					win.Update(a.NewServer)
				}},
				{Label: "刷新", Accelerator: "CmdOrCtrl+R", Click: func(*mygo.MenuItem, *mygo.Window) {
					win.Update(a.Refresh)
				}},
				mygo.Separator(),
				{Role: mygo.RoleClose},
			}},
			{Role: mygo.RoleEditMenu},
			{Role: mygo.RoleWindowMenu},
		}))
		win = mygo.NewWindow(mygo.WindowOptions{
			Title:          "RuleLens",
			Width:          1280,
			Height:         820,
			MinWidth:       980,
			MinHeight:      620,
			StateKey:       "main",
			TitleBarStyle:  mygo.TitleBarHidden,
			TitleBarHeight: 40,
			Content:        ui.View(a.View),
		})
	})
	app.OnQuit(a.Close)
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
