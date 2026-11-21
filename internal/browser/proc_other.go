//go:build !unix

package browser

import "os/exec"

func configureBrowserProcGroup(_ *exec.Cmd) {}

func killBrowserProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}
