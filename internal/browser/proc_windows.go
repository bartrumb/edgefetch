//go:build windows

package browser

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	modKernel32                           = syscall.NewLazyDLL("kernel32.dll")
	procCreateProcessW                    = modKernel32.NewProc("CreateProcessW")
	procResumeThread                      = modKernel32.NewProc("ResumeThread")
	procInitializeProcThreadAttributeList = modKernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = modKernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList     = modKernel32.NewProc("DeleteProcThreadAttributeList")
	procCreateJobObjectW                  = modKernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject           = modKernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject          = modKernel32.NewProc("AssignProcessToJobObject")

	winJobHandles sync.Map // pid (int) -> syscall.Handle (JobObject)
)

const (
	createSuspended                  = 0x00000004
	createUnicodeEnvironment         = 0x00000400
	extendedStartupInfoPresent       = 0x00080000
	createNoWindow                   = 0x08000000
	procThreadAttributeHandleList    = 0x00020002
	jobObjectExtendedLimitInfoClass  = 9
	jobObjectLimitKillOnJobCloseFlag = 0x00002000
	ucrtFOpen                        = 0x01
	ucrtFPipe                        = 0x08
	ucrtFDev                         = 0x40
)

type startupInfoW struct {
	Cb            uint32
	Reserved      *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	CbReserved2   uint16
	LpReserved2   *byte
	StdInput      syscall.Handle
	StdOutput     syscall.Handle
	StdErr        syscall.Handle
}

type startupInfoExW struct {
	StartupInfo   startupInfoW
	AttributeList uintptr
}

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectExtendedLimitInformation struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

func hardenUserDataDir(userDir string) error {
	if err := os.Chmod(userDir, 0o700); err != nil {
		return err
	}
	u, err := user.Current()
	if err != nil || strings.TrimSpace(u.Uid) == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Strip inherited %TEMP% ACEs and grant access exclusively to the current Windows user SID.
	c := exec.CommandContext(ctx, "icacls", userDir, "/inheritance:r", "/grant:r", "*"+strings.TrimSpace(u.Uid)+":(OI)(CI)F")
	_ = c.Run()
	return nil
}

func configureBrowserProcGroup(_ *exec.Cmd) {}

func putUintptrLE(b []byte, v uintptr) {
	if unsafe.Sizeof(v) == 8 {
		binary.LittleEndian.PutUint64(b, uint64(v))
	} else {
		binary.LittleEndian.PutUint32(b, uint32(v))
	}
}

func encodeWindowsEnvBlock(env []string) []uint16 {
	var b []uint16
	for _, entry := range env {
		if entry == "" || strings.IndexByte(entry, 0) >= 0 {
			continue
		}
		u, err := syscall.UTF16FromString(entry)
		if err != nil {
			continue
		}
		b = append(b, u...)
	}
	if len(b) == 0 {
		b = append(b, 0)
	}
	b = append(b, 0)
	return b
}

func attachKillOnCloseJob(procHandle syscall.Handle) (syscall.Handle, error) {
	job, _, createErr := procCreateJobObjectW.Call(0, 0)
	if job == 0 {
		if createErr != nil {
			return 0, fmt.Errorf("CreateJobObjectW: %w", createErr)
		}
		return 0, syscall.EINVAL
	}
	var info jobObjectExtendedLimitInformation
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobCloseFlag
	ok, _, setErr := procSetInformationJobObject.Call(
		job,
		jobObjectExtendedLimitInfoClass,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if ok == 0 {
		_ = syscall.CloseHandle(syscall.Handle(job))
		if setErr != nil {
			return 0, fmt.Errorf("SetInformationJobObject: %w", setErr)
		}
		return 0, syscall.EINVAL
	}
	assigned, _, assignErr := procAssignProcessToJobObject.Call(job, uintptr(procHandle))
	if assigned == 0 {
		_ = syscall.CloseHandle(syscall.Handle(job))
		if assignErr != nil {
			return 0, fmt.Errorf("AssignProcessToJobObject: %w", assignErr)
		}
		return 0, syscall.EINVAL
	}
	return syscall.Handle(job), nil
}

func deduplicateValidHandles(in []syscall.Handle) []syscall.Handle {
	out := make([]syscall.Handle, 0, len(in))
	for _, h := range in {
		if h == 0 || h == syscall.InvalidHandle {
			continue
		}
		dup := false
		for _, existing := range out {
			if existing == h {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, h)
		}
	}
	return out
}

// startBrowserPipeProcess spawns Chromium on Windows with `--remote-debugging-pipe` by populating UCRT's inherited
// low-level file descriptor table (`STARTUPINFOW.lpReserved2`) for FDs 0..4 (FD 3 = CDP read, FD 4 = CDP write),
// scoping handle inheritance strictly to those exact handles via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, and attaching a
// kill-on-close Job Object while `CREATE_SUSPENDED` BEFORE `ResumeThread` so zero child processes can escape the Job.
func startBrowserPipeProcess(bin string, args []string, env []string) (*exec.Cmd, *os.File, *os.File, io.ReadCloser, error) {
	var stderrRead, stderrWrite syscall.Handle
	if err := syscall.CreatePipe(&stderrRead, &stderrWrite, nil, 0); err != nil {
		return nil, nil, nil, nil, err
	}
	var toChromeRead, toChromeWrite syscall.Handle
	if err := syscall.CreatePipe(&toChromeRead, &toChromeWrite, nil, 0); err != nil {
		_ = syscall.CloseHandle(stderrRead)
		_ = syscall.CloseHandle(stderrWrite)
		return nil, nil, nil, nil, err
	}
	var fromChromeRead, fromChromeWrite syscall.Handle
	if err := syscall.CreatePipe(&fromChromeRead, &fromChromeWrite, nil, 0); err != nil {
		_ = syscall.CloseHandle(stderrRead)
		_ = syscall.CloseHandle(stderrWrite)
		_ = syscall.CloseHandle(toChromeRead)
		_ = syscall.CloseHandle(toChromeWrite)
		return nil, nil, nil, nil, err
	}
	hNull, err := syscall.Open("NUL", syscall.O_RDWR, 0)
	if err != nil {
		_ = syscall.CloseHandle(stderrRead)
		_ = syscall.CloseHandle(stderrWrite)
		_ = syscall.CloseHandle(toChromeRead)
		_ = syscall.CloseHandle(toChromeWrite)
		_ = syscall.CloseHandle(fromChromeRead)
		_ = syscall.CloseHandle(fromChromeWrite)
		return nil, nil, nil, nil, err
	}

	closeAllPipes := func() {
		_ = syscall.CloseHandle(hNull)
		_ = syscall.CloseHandle(stderrRead)
		_ = syscall.CloseHandle(stderrWrite)
		_ = syscall.CloseHandle(toChromeRead)
		_ = syscall.CloseHandle(toChromeWrite)
		_ = syscall.CloseHandle(fromChromeRead)
		_ = syscall.CloseHandle(fromChromeWrite)
	}

	var cmdParts []string
	cmdParts = append(cmdParts, syscall.EscapeArg(bin))
	for _, a := range args {
		cmdParts = append(cmdParts, syscall.EscapeArg(a))
	}
	cmdLineUTF16, err := syscall.UTF16PtrFromString(strings.Join(cmdParts, " "))
	if err != nil {
		closeAllPipes()
		return nil, nil, nil, nil, err
	}
	appUTF16, err := syscall.UTF16PtrFromString(bin)
	if err != nil {
		appUTF16 = nil
	}
	envBlock := encodeWindowsEnvBlock(env)

	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	reserved2 := make([]byte, 4+5+5*ptrSize)
	binary.LittleEndian.PutUint32(reserved2[0:4], 5)
	reserved2[4] = ucrtFOpen | ucrtFDev  // fd 0: NUL
	reserved2[5] = ucrtFOpen | ucrtFDev  // fd 1: NUL
	reserved2[6] = ucrtFOpen | ucrtFPipe // fd 2: stderrWrite
	reserved2[7] = ucrtFOpen | ucrtFPipe // fd 3: toChromeRead
	reserved2[8] = ucrtFOpen | ucrtFPipe // fd 4: fromChromeWrite
	handles := [5]syscall.Handle{hNull, hNull, stderrWrite, toChromeRead, fromChromeWrite}
	for idx, h := range handles {
		off := 9 + idx*ptrSize
		putUintptrLE(reserved2[off:off+ptrSize], uintptr(h))
	}

	inheritList := deduplicateValidHandles([]syscall.Handle{hNull, stderrWrite, toChromeRead, fromChromeWrite})
	var attrListSize uintptr
	_, _, _ = procInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))
	if attrListSize == 0 {
		closeAllPipes()
		return nil, nil, nil, nil, fmt.Errorf("InitializeProcThreadAttributeList returned zero size")
	}
	// Allocate pointer-aligned backing buffer for LPPROC_THREAD_ATTRIBUTE_LIST.
	attrWords := make([]uintptr, (attrListSize+unsafe.Sizeof(uintptr(0))-1)/unsafe.Sizeof(uintptr(0)))
	attrPtr := uintptr(unsafe.Pointer(&attrWords[0]))
	if ok, _, initErr := procInitializeProcThreadAttributeList.Call(attrPtr, 1, 0, uintptr(unsafe.Pointer(&attrListSize))); ok == 0 {
		closeAllPipes()
		return nil, nil, nil, nil, fmt.Errorf("InitializeProcThreadAttributeList: %w", initErr)
	}
	defer procDeleteProcThreadAttributeList.Call(attrPtr)

	if ok, _, updErr := procUpdateProcThreadAttribute.Call(
		attrPtr,
		0,
		procThreadAttributeHandleList,
		uintptr(unsafe.Pointer(&inheritList[0])),
		uintptr(len(inheritList))*unsafe.Sizeof(inheritList[0]),
		0,
		0,
	); ok == 0 {
		closeAllPipes()
		return nil, nil, nil, nil, fmt.Errorf("UpdateProcThreadAttribute(HANDLE_LIST): %w", updErr)
	}

	var siEx startupInfoExW
	siEx.StartupInfo.Cb = uint32(unsafe.Sizeof(siEx))
	siEx.StartupInfo.Flags = syscall.STARTF_USESTDHANDLES | syscall.STARTF_USESHOWWINDOW
	siEx.StartupInfo.ShowWindow = syscall.SW_HIDE
	siEx.StartupInfo.StdInput = hNull
	siEx.StartupInfo.StdOutput = hNull
	siEx.StartupInfo.StdErr = stderrWrite
	siEx.StartupInfo.CbReserved2 = uint16(len(reserved2))
	siEx.StartupInfo.LpReserved2 = &reserved2[0]
	siEx.AttributeList = attrPtr

	var pi syscall.ProcessInformation

	syscall.ForkLock.Lock()
	for _, h := range inheritList {
		_ = syscall.SetHandleInformation(h, syscall.HANDLE_FLAG_INHERIT, syscall.HANDLE_FLAG_INHERIT)
	}
	for _, h := range []syscall.Handle{stderrRead, toChromeWrite, fromChromeRead} {
		_ = syscall.SetHandleInformation(h, syscall.HANDLE_FLAG_INHERIT, 0)
	}
	r1, _, lastErr := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(appUTF16)),
		uintptr(unsafe.Pointer(cmdLineUTF16)),
		0,
		0,
		1, // bInheritHandles = TRUE (strictly bounded to inheritList via PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
		uintptr(createSuspended|extendedStartupInfoPresent|createUnicodeEnvironment|createNoWindow),
		uintptr(unsafe.Pointer(&envBlock[0])),
		0,
		uintptr(unsafe.Pointer(&siEx)),
		uintptr(unsafe.Pointer(&pi)),
	)
	// Keep `inheritList` alive past CreateProcessW so the GC cannot collect the backing slice early.
	_ = inheritList[0]
	var createErr error
	if r1 == 0 {
		if lastErr != nil {
			createErr = lastErr
		} else {
			createErr = syscall.EINVAL
		}
	}
	_ = syscall.CloseHandle(hNull)
	_ = syscall.CloseHandle(stderrWrite)
	_ = syscall.CloseHandle(toChromeRead)
	_ = syscall.CloseHandle(fromChromeWrite)
	syscall.ForkLock.Unlock()

	if createErr != nil {
		_ = syscall.CloseHandle(stderrRead)
		_ = syscall.CloseHandle(toChromeWrite)
		_ = syscall.CloseHandle(fromChromeRead)
		return nil, nil, nil, nil, fmt.Errorf("start chromium: %w", createErr)
	}

	pid := int(pi.ProcessId)
	job, jobErr := attachKillOnCloseJob(pi.Process)
	if jobErr != nil {
		_ = syscall.TerminateProcess(pi.Process, 1)
		_ = syscall.CloseHandle(pi.Thread)
		_ = syscall.CloseHandle(pi.Process)
		_ = syscall.CloseHandle(stderrRead)
		_ = syscall.CloseHandle(toChromeWrite)
		_ = syscall.CloseHandle(fromChromeRead)
		return nil, nil, nil, nil, fmt.Errorf("attach kill-on-close job before resume: %w", jobErr)
	}
	winJobHandles.Store(pid, job)

	resumed, _, resumeErr := procResumeThread.Call(uintptr(pi.Thread))
	_ = syscall.CloseHandle(pi.Thread)
	_ = syscall.CloseHandle(pi.Process)
	if uint32(resumed) == ^uint32(0) {
		if v, ok := winJobHandles.LoadAndDelete(pid); ok {
			_ = syscall.CloseHandle(v.(syscall.Handle))
		}
		_ = syscall.CloseHandle(stderrRead)
		_ = syscall.CloseHandle(toChromeWrite)
		_ = syscall.CloseHandle(fromChromeRead)
		return nil, nil, nil, nil, fmt.Errorf("ResumeThread: %w", resumeErr)
	}

	proc, findErr := os.FindProcess(pid)
	if findErr != nil {
		if v, ok := winJobHandles.LoadAndDelete(pid); ok {
			_ = syscall.CloseHandle(v.(syscall.Handle))
		}
		_ = syscall.CloseHandle(stderrRead)
		_ = syscall.CloseHandle(toChromeWrite)
		_ = syscall.CloseHandle(fromChromeRead)
		return nil, nil, nil, nil, findErr
	}

	fullArgs := make([]string, 0, len(args)+1)
	fullArgs = append(fullArgs, bin)
	fullArgs = append(fullArgs, args...)
	cmd := &exec.Cmd{
		Path:    bin,
		Args:    fullArgs,
		Env:     env,
		Process: proc,
	}
	return cmd,
		os.NewFile(uintptr(toChromeWrite), "cdp-to-chrome"),
		os.NewFile(uintptr(fromChromeRead), "cdp-from-chrome"),
		os.NewFile(uintptr(stderrRead), "chrome-stderr"),
		nil
}

func killBrowserProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	if v, ok := winJobHandles.LoadAndDelete(pid); ok {
		// Closing the Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE terminates the entire Chromium process tree.
		_ = syscall.CloseHandle(v.(syscall.Handle))
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}
