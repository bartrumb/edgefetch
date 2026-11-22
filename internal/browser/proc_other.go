//go:build !unix && !windows

package browser

import (
	"errors"
	"io"
	"os"
	"os/exec"
)

func hardenUserDataDir(userDir string) error {
	return os.Chmod(userDir, 0o700)
}

func configureBrowserProcGroup(_ *exec.Cmd) {}

func startBrowserPipeProcess(_ string, _ []string, _ []string) (*exec.Cmd, *os.File, *os.File, io.ReadCloser, error) {
	return nil, nil, nil, nil, errors.New("browser pipe process unsupported on this platform")
}

func killBrowserProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}
