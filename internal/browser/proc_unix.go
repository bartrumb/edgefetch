//go:build unix

package browser

import (
	"os/exec"
	"syscall"
)

func configureBrowserProcGroup(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killBrowserProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if pid := cmd.Process.Pid; pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}
