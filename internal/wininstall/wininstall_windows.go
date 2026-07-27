//go:build windows

package wininstall

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	// AppName is the display name shown in Add/Remove Programs.
	AppName = "Ghostfork"
	// Publisher is shown in Add/Remove Programs.
	Publisher = "Ghostfork"

	envKey       = `Environment`
	uninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall\Ghostfork`

	gfExe      = "gf.exe"
	helperExe  = "git-remote-gf.exe" // byte-for-byte copy of gf.exe (argv0 dispatch)
	setupExe   = "gf-setup.exe"      // installer copies itself here for uninstall
	dirPerm    = 0o755
	filePerm   = 0o755
	installEnv = "LOCALAPPDATA"
)

// Status describes whether gf is currently installed and where.
type Status struct {
	Installed bool
	Location  string
}

// DefaultInstallDir is the per-user install location:
// %LOCALAPPDATA%\Programs\ghostfork (falls back to os.UserConfigDir).
func DefaultInstallDir() (string, error) {
	if base := os.Getenv(installEnv); base != "" {
		return filepath.Join(base, "Programs", "ghostfork"), nil
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine install directory: %w", err)
	}
	return filepath.Join(cfg, "ghostfork"), nil
}

// Detect reports whether gf is installed, from the Add/Remove Programs entry.
func Detect() (Status, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, uninstallKey, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return Status{Installed: false}, nil
	}
	if err != nil {
		return Status{}, err
	}
	defer k.Close()
	loc, _, _ := k.GetStringValue("InstallLocation")
	return Status{Installed: true, Location: loc}, nil
}

// Install writes gf.exe + git-remote-gf.exe into dir, copies the running
// installer there (for the uninstall entry), puts dir on the user PATH, and
// registers Add/Remove Programs. Idempotent (safe to re-run to upgrade).
func Install(payload []byte, selfExe, dir, version string) error {
	if len(payload) == 0 {
		return errors.New("no gf.exe payload to install")
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	for _, name := range []string{gfExe, helperExe} {
		if err := writeFileAtomic(filepath.Join(dir, name), payload); err != nil {
			return fmt.Errorf("writing %s: %w", name, err)
		}
	}
	uninstaller := filepath.Join(dir, setupExe)
	if selfExe != "" {
		if b, err := os.ReadFile(selfExe); err == nil {
			_ = writeFileAtomic(uninstaller, b)
		}
	}
	if err := addUserPath(dir); err != nil {
		return fmt.Errorf("updating PATH: %w", err)
	}
	if err := writeUninstallEntry(dir, uninstaller, version); err != nil {
		return fmt.Errorf("registering uninstall entry: %w", err)
	}
	broadcastEnvChange()
	return nil
}

// Uninstall removes gf from PATH, deletes the Add/Remove Programs entry and the
// binaries, and schedules removal of the install directory (which may hold the
// still-running installer). Returns the directory it acted on.
func Uninstall() (dir string, err error) {
	st, _ := Detect()
	dir = st.Location
	if dir == "" {
		if dir, err = DefaultInstallDir(); err != nil {
			return "", err
		}
	}
	if e := removeUserPath(dir); e != nil {
		err = e
	}
	_ = deleteUninstallEntry()
	for _, name := range []string{gfExe, helperExe} {
		_ = os.Remove(filepath.Join(dir, name))
	}
	scheduleDirRemoval(dir)
	broadcastEnvChange()
	return dir, err
}

// ── PATH (HKCU\Environment) ─────────────────────────────────────────────────

func addUserPath(dir string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, envKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	cur, _, err := k.GetStringValue("Path")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	next, changed := addToPath(cur, dir)
	if !changed {
		return nil
	}
	return k.SetExpandStringValue("Path", next)
}

func removeUserPath(dir string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, envKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	cur, _, err := k.GetStringValue("Path")
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	next, changed := removeFromPath(cur, dir)
	if !changed {
		return nil
	}
	return k.SetExpandStringValue("Path", next)
}

// ── Add/Remove Programs (HKCU Uninstall) ────────────────────────────────────

func writeUninstallEntry(dir, uninstaller, version string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, uninstallKey, registry.WRITE)
	if err != nil {
		return err
	}
	defer k.Close()
	_ = k.SetStringValue("DisplayName", AppName)
	if version != "" {
		_ = k.SetStringValue("DisplayVersion", version)
	}
	_ = k.SetStringValue("Publisher", Publisher)
	_ = k.SetStringValue("InstallLocation", dir)
	_ = k.SetStringValue("DisplayIcon", filepath.Join(dir, gfExe))
	if uninstaller != "" {
		_ = k.SetStringValue("UninstallString", quote(uninstaller)+" --uninstall")
		_ = k.SetStringValue("QuietUninstallString", quote(uninstaller)+" --uninstall --silent")
	}
	_ = k.SetDWordValue("NoModify", 1)
	_ = k.SetDWordValue("NoRepair", 1)
	return nil
}

func deleteUninstallEntry() error {
	return registry.DeleteKey(registry.CURRENT_USER, uninstallKey)
}

// ── Windows plumbing ────────────────────────────────────────────────────────

// broadcastEnvChange tells the shell the environment changed so new processes
// pick up the PATH edit without a logoff. Best-effort.
func broadcastEnvChange() {
	const (
		hwndBroadcast   = 0xffff
		wmSettingChange = 0x001A
		smtoAbortIfHung = 0x0002
	)
	user32 := windows.NewLazySystemDLL("user32.dll")
	proc := user32.NewProc("SendMessageTimeoutW")
	env, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}
	_, _, _ = proc.Call(uintptr(hwndBroadcast), uintptr(wmSettingChange), 0,
		uintptr(unsafe.Pointer(env)), uintptr(smtoAbortIfHung), 5000, 0)
}

// scheduleDirRemoval deletes dir after this process exits (the installer copied
// itself into dir and can't delete a running image), via a short detached cmd.
func scheduleDirRemoval(dir string) {
	const detachedProcess = 0x00000008
	cmd := exec.Command("cmd", "/c", "timeout /t 2 /nobreak >nul & rmdir /s /q "+quote(dir))
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true, CreationFlags: detachedProcess}
	_ = cmd.Start()
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, filePerm); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func quote(s string) string { return `"` + s + `"` }
