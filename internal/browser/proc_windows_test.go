//go:build windows

package browser

import (
	"context"
	"io"
	"net/url"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

var (
	procIsProcessInJob = modKernel32.NewProc("IsProcessInJob")
)

const handleFlagInherit = 0x00000001

func TestR7WindowsHandleInheritanceScopedAndSuspendedJobObject(t *testing.T) {
	bin := FindChromeBinary()
	if bin == "" {
		t.Skip("no headless Chromium/Chrome binary installed on Windows")
	}

	// Create an explicitly inheritable pipe in the parent Go process (`InheritHandle: 1`),
	// clear inherit on the read end, and keep the write end inheritable while spawning Chrome!
	var sa syscall.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.InheritHandle = 1

	var leakRead, leakWrite syscall.Handle
	if err := syscall.CreatePipe(&leakRead, &leakWrite, &sa, 0); err != nil {
		t.Fatalf("CreatePipe: %v", err)
	}
	defer func() {
		if leakRead != syscall.InvalidHandle {
			_ = syscall.CloseHandle(leakRead)
		}
		if leakWrite != syscall.InvalidHandle {
			_ = syscall.CloseHandle(leakWrite)
		}
	}()
	if err := syscall.SetHandleInformation(leakRead, handleFlagInherit, 0); err != nil {
		t.Fatalf("SetHandleInformation(leakRead): %v", err)
	}

	r := NewRenderer(bin, func(*url.URL) error { return nil }, "EdgeFetchTest/2.7.0", 1, nil)
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := r.ensureBrowser(ctx); err != nil {
		t.Fatalf("ensureBrowser on Windows failed: %v", err)
	}

	r.mu.Lock()
	var pid int
	if r.cmd != nil && r.cmd.Process != nil {
		pid = r.cmd.Process.Pid
	}
	r.mu.Unlock()
	if pid <= 0 {
		t.Fatalf("expected live Chrome pid > 0, got %d", pid)
	}

	// 1. Verify Chrome was attached to our kill-on-close Job Object at launch (`CREATE_SUSPENDED` -> `AssignProcessToJobObject` -> `ResumeThread`).
	rawJob, ok := winJobHandles.Load(pid)
	if !ok {
		t.Fatalf("SECURITY: expected winJobHandles entry for Chrome pid %d", pid)
	}
	jobHandle := rawJob.(syscall.Handle)
	procHandle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		t.Fatalf("OpenProcess(%d): %v", pid, err)
	}
	defer syscall.CloseHandle(procHandle)

	var inJob int32
	ret, _, callErr := procIsProcessInJob.Call(uintptr(procHandle), uintptr(jobHandle), uintptr(unsafe.Pointer(&inJob)))
	if ret == 0 || inJob == 0 {
		t.Fatalf("SECURITY: expected Chrome pid %d to belong to kill-on-close Job Object (ret=%d inJob=%d err=%v)", pid, ret, inJob, callErr)
	}

	// 2. Close ONLY the parent's write handle while Chrome (and its child processes) remain running!
	// If `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` leaked `leakWrite` into Chrome, `ReadFile` on `leakRead` would hang until Chrome exits.
	_ = syscall.CloseHandle(leakWrite)
	leakWrite = syscall.InvalidHandle

	eofCh := make(chan error, 1)
	go func(rh syscall.Handle) {
		var buf [16]byte
		var n uint32
		rErr := syscall.ReadFile(rh, buf[:], &n, nil)
		eofCh <- rErr
	}(leakRead)

	select {
	case rErr := <-eofCh:
		if rErr != syscall.ERROR_BROKEN_PIPE && rErr != io.EOF && rErr != nil {
			t.Fatalf("unexpected ReadFile error on uninherited pipe: %v", rErr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SECURITY (R7 Low #1): live Chromium child process inherited unrelated parent OS handle (pipe write end remained open >500ms)!")
	}
}
