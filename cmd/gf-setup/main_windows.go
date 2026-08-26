//go:build windows

// Command gf-setup is the graphical Windows installer for the gf client. It
// shows a small window with Install and Uninstall buttons; it installs gf.exe
// (and the git-remote-gf.exe helper) for the current user and adds it to the
// per-user PATH — no administrator rights, no UAC.
//
// Flags (used by Add/Remove Programs and scripts; normal launch is GUI):
//
//	--uninstall   remove gf (the Add/Remove Programs UninstallString)
//	--silent      no UI at all (QuietUninstallString / scripted install)
//
// The --silent paths report failure through the EXIT CODE (0 = installed,
// 1 = failed). That is the only channel available: this binary is built for
// the GUI subsystem (-H=windowsgui), so it has no console to print to, and
// install.ps1 has nothing else to check.
package main

import (
	"flag"
	"os"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"github.com/ghostfork/gf/internal/version"
	"github.com/ghostfork/gf/internal/wininstall"
)

func main() {
	uninstall := flag.Bool("uninstall", false, "uninstall gf")
	silent := flag.Bool("silent", false, "no user interface")
	flag.Parse()

	switch {
	case *silent && *uninstall:
		if _, err := wininstall.Uninstall(); err != nil {
			os.Exit(1)
		}
	case *silent:
		if err := headlessInstall(); err != nil {
			os.Exit(1)
		}
	case *uninstall:
		// Add/Remove Programs → Uninstall: confirm + act via message boxes,
		// no main window needed.
		if walk.MsgBox(nil, "Uninstall Ghostfork",
			"Remove gf and its PATH entry for your account?",
			walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes {
			dir, err := wininstall.Uninstall()
			if err != nil {
				walk.MsgBox(nil, "Ghostfork", "Uninstall finished with a warning:\n"+err.Error(),
					walk.MsgBoxOK|walk.MsgBoxIconWarning)
			} else {
				walk.MsgBox(nil, "Ghostfork", "gf was removed from\n"+dir+"\nand from your PATH.",
					walk.MsgBoxOK|walk.MsgBoxIconInformation)
			}
		}
	default:
		runGUI()
	}
}

// headlessInstall performs the install with no UI, returning the first error
// that stopped it. Every failure must surface: the caller turns a non-nil
// error into a non-zero exit code, which is all install.ps1 has to go on.
// Swallowing them here made a failed scripted install look like a success.
func headlessInstall() error {
	dir, err := wininstall.DefaultInstallDir()
	if err != nil {
		return err
	}
	payload, err := gfPayload()
	if err != nil {
		return err
	}
	self, _ := os.Executable()
	return wininstall.Install(payload, self, dir, version.Version)
}

func runGUI() {
	var mw *walk.MainWindow
	var statusLabel *walk.Label
	var logBox *walk.TextEdit
	var installBtn, uninstallBtn *walk.PushButton

	logln := func(s string) {
		if logBox != nil {
			logBox.AppendText(s + "\r\n")
		}
	}

	refresh := func() {
		st, _ := wininstall.Detect()
		if st.Installed {
			loc := st.Location
			if loc == "" {
				loc = "(unknown location)"
			}
			statusLabel.SetText("Installed  •  " + loc)
			installBtn.SetText("Reinstall / Upgrade")
			installBtn.SetEnabled(true)
			uninstallBtn.SetEnabled(true)
		} else {
			statusLabel.SetText("Not installed")
			installBtn.SetText("Install")
			installBtn.SetEnabled(true)
			uninstallBtn.SetEnabled(false)
		}
	}

	onInstall := func() {
		installBtn.SetEnabled(false)
		uninstallBtn.SetEnabled(false)
		defer refresh()

		dir, err := wininstall.DefaultInstallDir()
		if err != nil {
			logln("Error: " + err.Error())
			return
		}
		payload, err := gfPayload()
		if err != nil {
			logln("Error: " + err.Error())
			return
		}
		self, _ := os.Executable()
		logln("Installing to " + dir + " …")
		if err := wininstall.Install(payload, self, dir, version.Version); err != nil {
			logln("Install failed: " + err.Error())
			walk.MsgBox(mw, "Ghostfork", "Install failed:\n"+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
			return
		}
		logln("Done.")
		walk.MsgBox(mw, "Ghostfork",
			"gf installed to:\n"+dir+"\n\nOpen a NEW terminal (so the PATH change applies), then run:\n"+
				"    gf login --server https://app.ghostfork.io --username <you>",
			walk.MsgBoxOK|walk.MsgBoxIconInformation)
	}

	onUninstall := func() {
		if walk.MsgBox(mw, "Uninstall Ghostfork",
			"Remove gf and its PATH entry for your account?",
			walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
			return
		}
		installBtn.SetEnabled(false)
		uninstallBtn.SetEnabled(false)
		defer refresh()

		dir, err := wininstall.Uninstall()
		if err != nil {
			logln("Uninstall warning: " + err.Error())
		}
		logln("Removed from " + dir + " and from PATH.")
		walk.MsgBox(mw, "Ghostfork",
			"gf was removed.\nYour identity key (created by 'gf login') was left untouched.",
			walk.MsgBoxOK|walk.MsgBoxIconInformation)
	}

	subtitle := "Zero-trust encrypted Git remote — command-line client (gf " + version.Version + ")"

	err := MainWindow{
		AssignTo: &mw,
		Title:    "Ghostfork Installer",
		MinSize:  Size{Width: 500, Height: 340},
		Size:     Size{Width: 500, Height: 360},
		Layout:   VBox{Margins: Margins{Left: 20, Top: 18, Right: 20, Bottom: 18}, Spacing: 10},
		Children: []Widget{
			Label{Text: "Ghostfork", Font: Font{Family: "Segoe UI", PointSize: 18, Bold: true}},
			Label{
				Text:      subtitle,
				TextColor: walk.RGB(0x6b, 0x6b, 0x6b),
				Font:      Font{Family: "Segoe UI", PointSize: 9},
			},
			Label{
				Text: "Installs gf and the git-remote-gf helper for your user account and " +
					"adds them to your PATH. No administrator rights required.",
				Font: Font{Family: "Segoe UI", PointSize: 9},
			},
			VSpacer{Size: 6},
			Composite{
				Layout: HBox{MarginsZero: true, Spacing: 6},
				Children: []Widget{
					Label{Text: "Status:", Font: Font{Family: "Segoe UI", PointSize: 9, Bold: true}},
					Label{AssignTo: &statusLabel, Text: "…", Font: Font{Family: "Segoe UI", PointSize: 9}},
					HSpacer{},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true, Spacing: 8},
				Children: []Widget{
					PushButton{AssignTo: &installBtn, Text: "Install", MinSize: Size{Width: 160, Height: 36}, OnClicked: onInstall},
					PushButton{AssignTo: &uninstallBtn, Text: "Uninstall", MinSize: Size{Width: 160, Height: 36}, OnClicked: onUninstall},
					HSpacer{},
					PushButton{Text: "Close", MinSize: Size{Width: 90, Height: 36}, OnClicked: func() { mw.Close() }},
				},
			},
			TextEdit{AssignTo: &logBox, ReadOnly: true, VScroll: true},
		},
	}.Create()
	if err != nil {
		walk.MsgBox(nil, "Ghostfork", "Could not start the installer UI:\n"+err.Error(),
			walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	refresh()
	mw.Run()
}
