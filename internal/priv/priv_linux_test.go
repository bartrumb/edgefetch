//go:build linux

package priv

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
)

const prGetNoNewPrivs = 39 // Linux <sys/prctl.h> PR_GET_NO_NEW_PRIVS

func TestNoNewPrivsUsesAllThreadsSyscallAcrossLockedThreads(t *testing.T) {
	src, err := os.ReadFile("priv_linux.go")
	if err != nil {
		t.Fatalf("read priv_linux.go: %v", err)
	}
	if !strings.Contains(string(src), "syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, prSetNoNewPriv, 1, 0, 0, 0, 0)") {
		t.Fatal("A10 BUG: priv_linux.go must apply PR_SET_NO_NEW_PRIVS via syscall.AllThreadsSyscall6 with zeroed arg3..arg5 across all OS threads")
	}

	// Under `go test -race` (CGO_ENABLED=1), Go's runtime returns ENOTSUP for AllThreadsSyscall6 because libc owns
	// pthreads, whereas production EdgeFetch builds with CGO_ENABLED=0. When ENOTSUP is returned in-process, compile
	// and execute this exact multi-thread kernel test with CGO_ENABLED=0 so CI always verifies real kernel behavior!
	if os.Getenv("EDGEFETCH_TEST_NOCGO_CHILD") != "1" {
		_, _, probeErrno := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, prGetNoNewPrivs, 0, 0, 0, 0, 0)
		if errors.Is(probeErrno, syscall.EOPNOTSUPP) || errors.Is(probeErrno, syscall.ENOTSUP) {
			bin := filepath.Join(t.TempDir(), "priv.test")
			buildCmd := exec.Command("go", "test", "-c", "-o", bin, ".")
			buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if out, err := buildCmd.CombinedOutput(); err != nil {
				t.Fatalf("build CGO_ENABLED=0 priv.test: %v\n%s", err, out)
			}
			runCmd := exec.Command(bin, "-test.run=^TestNoNewPrivsUsesAllThreadsSyscallAcrossLockedThreads$", "-test.v")
			runCmd.Env = append(os.Environ(), "EDGEFETCH_TEST_NOCGO_CHILD=1")
			if out, err := runCmd.CombinedOutput(); err != nil {
				t.Fatalf("CGO_ENABLED=0 multi-thread NO_NEW_PRIVS kernel check failed: %v\n%s", err, out)
			}
			return
		}
	}

	const numThreads = 3
	ready := make(chan struct{}, numThreads)
	check := make(chan struct{})
	results := make(chan uintptr, numThreads)
	var wg sync.WaitGroup

	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready <- struct{}{}
			<-check
			r1, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prGetNoNewPrivs, 0, 0, 0, 0, 0)
			if errno != 0 {
				t.Errorf("prctl(PR_GET_NO_NEW_PRIVS): %v", errno)
				return
			}
			results <- r1
		}()
	}

	for i := 0; i < numThreads; i++ {
		<-ready
	}
	if _, _, errno := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, prSetNoNewPriv, 1, 0, 0, 0, 0); errno != 0 {
		t.Fatalf("AllThreadsSyscall6(PR_SET_NO_NEW_PRIVS): %v", errno)
	}
	close(check)
	wg.Wait()
	close(results)

	for got := range results {
		if got != 1 {
			t.Fatalf("expected PR_GET_NO_NEW_PRIVS == 1 on locked peer OS thread, got %d", got)
		}
	}
}
