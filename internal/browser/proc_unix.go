//go:build unix

package browser

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
)

func hardenUserDataDir(userDir string) error {
	return os.Chmod(userDir, 0o700)
}

func configureBrowserProcGroup(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func startBrowserPipeProcess(bin string, args []string, env []string) (*exec.Cmd, *os.File, *os.File, io.ReadCloser, error) {
	toChromeRead, toChromeWrite, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	fromChromeRead, fromChromeWrite, err := os.Pipe()
	if err != nil {
		_ = toChromeRead.Close()
		_ = toChromeWrite.Close()
		return nil, nil, nil, nil, err
	}

	cmd := exec.Command(bin, args...)
	cmd.Env = env
	cmd.ExtraFiles = []*os.File{toChromeRead, fromChromeWrite}
	configureBrowserProcGroup(cmd)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = toChromeRead.Close()
		_ = toChromeWrite.Close()
		_ = fromChromeRead.Close()
		_ = fromChromeWrite.Close()
		return nil, nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = toChromeRead.Close()
		_ = toChromeWrite.Close()
		_ = fromChromeRead.Close()
		_ = fromChromeWrite.Close()
		return nil, nil, nil, nil, fmt.Errorf("start chromium: %w", err)
	}
	// Close child-side pipe ends in the parent immediately so EOF propagates cleanly if Chromium exits.
	_ = toChromeRead.Close()
	_ = fromChromeWrite.Close()
	return cmd, toChromeWrite, fromChromeRead, stderr, nil
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
