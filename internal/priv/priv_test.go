//go:build linux

package priv

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

func TestLockDownSecretPathsDataFirstSymlinkAndErrorFailClosed(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	optsPath := filepath.Join(dataDir, "options.json")
	if err := os.WriteFile(optsPath, []byte(`{"agent_token":"secret"}`), 0o644); err != nil {
		t.Fatalf("write options.json: %v", err)
	}

	var ops []string
	chownRec := func(p string, uid, gid int) error {
		ops = append(ops, "chown:"+filepath.Base(p))
		if uid != 0 || gid != 0 {
			t.Fatalf("unexpected chown uid=%d gid=%d", uid, gid)
		}
		return nil
	}
	chmodRec := func(p string, m os.FileMode) error {
		ops = append(ops, "chmod:"+filepath.Base(p))
		return os.Chmod(p, m)
	}

	// 1. Non-root is a clean no-op.
	if err := lockDownSecretPathsWith(65532, dataDir, chownRec, chmodRec, optsPath); err != nil || len(ops) != 0 {
		t.Fatalf("expected non-root no-op, got err=%v ops=%v", err, ops)
	}

	// 2. Root locks `/data` (0700) FIRST, before `options.json` (0600), even when `options.json` is absent.
	emptyData := filepath.Join(tmp, "empty-data")
	if err := os.MkdirAll(emptyData, 0o755); err != nil {
		t.Fatalf("mkdir empty-data: %v", err)
	}
	if err := lockDownSecretPathsWith(0, emptyData, chownRec, chmodRec, filepath.Join(emptyData, "options.json")); err != nil {
		t.Fatalf("expected missing options.json to still lock /data cleanly: %v", err)
	}
	if st, err := os.Stat(emptyData); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("expected empty-data mode 0700, got %v (err=%v)", st.Mode().Perm(), err)
	}

	// 3. Verify strict ordering: dataDir chown+chmod runs BEFORE options.json chown+chmod.
	ops = nil
	if err := lockDownSecretPathsWith(0, dataDir, chownRec, chmodRec, optsPath); err != nil {
		t.Fatalf("lockDownSecretPathsWith failed: %v", err)
	}
	wantOrder := "chown:data,chmod:data,chown:options.json,chmod:options.json"
	if got := strings.Join(ops, ","); got != wantOrder {
		t.Fatalf("lockdown ordering = %q, want %q", got, wantOrder)
	}
	if st, _ := os.Stat(dataDir); st.Mode().Perm() != 0o700 {
		t.Fatalf("expected dataDir 0700, got %o", st.Mode().Perm())
	}
	if st, _ := os.Stat(optsPath); st.Mode().Perm() != 0o600 {
		t.Fatalf("expected options.json 0600, got %o", st.Mode().Perm())
	}

	// 4. Symlinked options.json MUST fail closed with an error (while still locking /data to 0700 first!).
	_ = os.Remove(optsPath)
	outside := filepath.Join(tmp, "outside.json")
	_ = os.WriteFile(outside, []byte("{}"), 0o644)
	if err := os.Symlink(outside, optsPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_ = os.Chmod(dataDir, 0o755)
	if err := lockDownSecretPathsWith(0, dataDir, chownRec, chmodRec, optsPath); err == nil {
		t.Fatal("SECURITY: expected symlink options.json to fail closed with error")
	}
	if st, _ := os.Stat(dataDir); st.Mode().Perm() != 0o700 {
		t.Fatalf("expected /data locked to 0700 BEFORE symlink options.json error, got %o", st.Mode().Perm())
	}

	// 5. Chown or Chmod failure on existing path MUST fail closed.
	_ = os.Remove(optsPath)
	_ = os.WriteFile(optsPath, []byte("{}"), 0o600)
	boom := errors.New("simulated EPERM")
	if err := lockDownSecretPathsWith(0, dataDir, func(string, int, int) error { return boom }, chmodRec, optsPath); err == nil {
		t.Fatal("expected chown failure to return error")
	}
	if err := lockDownSecretPathsWith(0, dataDir, chownRec, func(string, os.FileMode) error { return boom }, optsPath); err == nil {
		t.Fatal("expected chmod failure to return error")
	}
}

func TestLockDownSecretPathsBranchesAndPublicEntrypoints(t *testing.T) {
	if os.Geteuid() != 0 {
		if err := LockDownSecretPaths("/nonexistent-edgefetch-test"); err != nil {
			t.Fatalf("LockDownSecretPaths non-root unexpected error: %v", err)
		}
		if err := LockDownSecretPathsStrict("/nonexistent-edgefetch-test"); err != nil {
			t.Fatalf("LockDownSecretPathsStrict non-root unexpected error: %v", err)
		}
	}

	tmp := t.TempDir()
	noopChown := func(string, int, int) error { return nil }
	noopChmod := func(string, os.FileMode) error { return os.Chmod(tmp, 0o700) }
	realChmod := func(p string, m os.FileMode) error { return os.Chmod(p, m) }
	_ = noopChmod

	// 1. dataDir == "" skips dataDir check, processes empty path, subdir (0700), and missing path.
	subDir := filepath.Join(tmp, "secrets-dir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("mkdir subDir: %v", err)
	}
	if err := lockDownSecretPathsWith(0, "", noopChown, realChmod, "", subDir, filepath.Join(tmp, "missing")); err != nil {
		t.Fatalf("dataDir=\"\" unexpected error: %v", err)
	}
	if st, err := os.Stat(subDir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("expected subDir mode 0700, got %o (err=%v)", st.Mode().Perm(), err)
	}

	// 2. dataDir missing (os.ErrNotExist) is tolerated cleanly.
	missingDir := filepath.Join(tmp, "no-such-data")
	if err := lockDownSecretPathsWith(0, missingDir, noopChown, realChmod, missingDir); err != nil {
		t.Fatalf("missing dataDir unexpected error: %v", err)
	}

	// 3. dataDir openNoFollowSecretFD non-ENOENT error (ENOTDIR via child under regular file).
	regFile := filepath.Join(tmp, "regfile")
	if err := os.WriteFile(regFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write regFile: %v", err)
	}
	if err := lockDownSecretPathsWith(0, filepath.Join(regFile, "child"), noopChown, realChmod); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("expected ENOTDIR error on dataDir, got %v", err)
	}

	// 4. dataDir is symlink -> fail closed.
	symDir := filepath.Join(tmp, "sym-data")
	if err := os.Symlink(subDir, symDir); err != nil {
		t.Fatalf("symlink symDir: %v", err)
	}
	if err := lockDownSecretPathsWith(0, symDir, noopChown, realChmod); err == nil || !strings.Contains(err.Error(), "refusing symlink secret directory") {
		t.Fatalf("expected symlink dataDir error, got %v", err)
	}

	// 5. dataDir is not a directory -> fail closed.
	if err := lockDownSecretPathsWith(0, regFile, noopChown, realChmod); err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Fatalf("expected non-directory dataDir error, got %v", err)
	}

	// 6. dataDir chmod failure -> fail closed.
	boom := errors.New("simulated EPERM")
	if err := lockDownSecretPathsWith(0, subDir, noopChown, func(string, os.FileMode) error { return boom }); err == nil || !strings.Contains(err.Error(), "chmod") {
		t.Fatalf("expected dataDir chmod error, got %v", err)
	}

	// 7. paths duplicate of dataDir skipped, and paths openNoFollowSecretFD non-ENOENT error (ENOTDIR).
	if err := lockDownSecretPathsWith(0, subDir, noopChown, realChmod, subDir); err != nil {
		t.Fatalf("duplicate dataDir in paths unexpected error: %v", err)
	}
	if err := lockDownSecretPathsWith(0, subDir, noopChown, realChmod, filepath.Join(regFile, "child")); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("expected paths ENOTDIR error, got %v", err)
	}

	// 8. paths chown and chmod failures (succeed on dataDir, fail on path).
	secretFile := filepath.Join(subDir, "secret.json")
	if err := os.WriteFile(secretFile, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write secretFile: %v", err)
	}
	if err := lockDownSecretPathsWith(0, subDir, func(p string, _, _ int) error {
		if p == secretFile {
			return boom
		}
		return nil
	}, realChmod, secretFile); err == nil || !strings.Contains(err.Error(), "chown") {
		t.Fatalf("expected paths chown error, got %v", err)
	}
	if err := lockDownSecretPathsWith(0, subDir, noopChown, func(p string, m os.FileMode) error {
		if p == secretFile {
			return boom
		}
		return os.Chmod(p, m)
	}, secretFile); err == nil || !strings.Contains(err.Error(), "chmod") {
		t.Fatalf("expected paths chmod error, got %v", err)
	}
}

func TestDropRootWithOrderingAndFailClosedVerification(t *testing.T) {
	if os.Geteuid() != 0 {
		if err := DropRoot(); err != nil {
			t.Fatalf("DropRoot non-root unexpected error: %v", err)
		}
	}

	newBaseDeps := func(ops *[]string) privDeps {
		curUID, curEUID, curGID, curEGID := 0, 0, 0, 0
		curGroups := []int{0}
		return privDeps{
			geteuid:   func() int { return curEUID },
			getuid:    func() int { return curUID },
			getegid:   func() int { return curEGID },
			getgid:    func() int { return curGID },
			getgroups: func() ([]int, error) { *ops = append(*ops, "getgroups"); return curGroups, nil },
			setNoNewPrivs: func() syscall.Errno {
				*ops = append(*ops, "prctl:NO_NEW_PRIVS")
				return 0
			},
			setgroups: func(g []int) error {
				*ops = append(*ops, "setgroups")
				curGroups = g
				return nil
			},
			setgid: func(id int) error {
				*ops = append(*ops, "setgid")
				curGID, curEGID = id, id
				return nil
			},
			setuid: func(id int) error {
				*ops = append(*ops, "setuid")
				curUID, curEUID = id, id
				return nil
			},
			setDumpableZero: func() syscall.Errno {
				*ops = append(*ops, "prctl:DUMPABLE=0")
				return 0
			},
		}
	}

	// 1. Happy path verifies exact call order and non-0 supplementary group acceptance.
	var ops []string
	deps := newBaseDeps(&ops)
	deps.getgroups = func() ([]int, error) {
		ops = append(ops, "getgroups")
		return []int{nonrootUID}, nil
	}
	if err := dropRootWith(deps); err != nil {
		t.Fatalf("dropRootWith happy path failed: %v", err)
	}
	wantOps := "prctl:NO_NEW_PRIVS,setgroups,setgid,setuid,prctl:DUMPABLE=0,getgroups"
	if got := strings.Join(ops, ","); got != wantOps {
		t.Fatalf("dropRootWith order = %q, want %q", got, wantOps)
	}

	// 2. Each step fails closed.
	boom := errors.New("boom")

	d := newBaseDeps(&ops)
	d.setNoNewPrivs = func() syscall.Errno { return syscall.EPERM }
	if err := dropRootWith(d); err == nil || !strings.Contains(err.Error(), "PR_SET_NO_NEW_PRIVS") {
		t.Fatalf("expected PR_SET_NO_NEW_PRIVS error, got %v", err)
	}

	d = newBaseDeps(&ops)
	d.setgroups = func([]int) error { return boom }
	if err := dropRootWith(d); err == nil || !strings.Contains(err.Error(), "setgroups") {
		t.Fatalf("expected setgroups error, got %v", err)
	}

	d = newBaseDeps(&ops)
	d.setgid = func(int) error { return boom }
	if err := dropRootWith(d); err == nil || !strings.Contains(err.Error(), "setgid") {
		t.Fatalf("expected setgid error, got %v", err)
	}

	d = newBaseDeps(&ops)
	d.setuid = func(int) error { return boom }
	if err := dropRootWith(d); err == nil || !strings.Contains(err.Error(), "setuid") {
		t.Fatalf("expected setuid error, got %v", err)
	}

	d = newBaseDeps(&ops)
	d.setDumpableZero = func() syscall.Errno { return syscall.EINVAL }
	if err := dropRootWith(d); err == nil || !strings.Contains(err.Error(), "PR_SET_DUMPABLE") {
		t.Fatalf("expected PR_SET_DUMPABLE error, got %v", err)
	}

	// 3. Post-drop UID/GID verification failures.
	d = newBaseDeps(&ops)
	d.setuid = func(int) error { return nil } // leaves uid/euid at 0
	if err := dropRootWith(d); err == nil || !strings.Contains(err.Error(), "did not transition to 65532") {
		t.Fatalf("expected uid/euid verification error, got %v", err)
	}

	// 4. getgroups error and group 0 still present error.
	d = newBaseDeps(&ops)
	d.getgroups = func() ([]int, error) { return nil, boom }
	if err := dropRootWith(d); err == nil || !strings.Contains(err.Error(), "verify supplementary groups") {
		t.Fatalf("expected getgroups error, got %v", err)
	}

	d = newBaseDeps(&ops)
	d.getgroups = func() ([]int, error) { return []int{nonrootUID, 0}, nil }
	if err := dropRootWith(d); err == nil || !strings.Contains(err.Error(), "supplementary group 0") {
		t.Fatalf("expected supplementary group 0 error, got %v", err)
	}
}

func TestLockDownSecretPathsRefusesHardlinksFIFOsAndSymlinkTOCTOU(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	victim := filepath.Join(tmp, "victim.json")
	if err := os.WriteFile(victim, []byte(`{"victim":true}`), 0o644); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	optsPath := filepath.Join(dataDir, "options.json")

	// 1. Hardlink (nlink == 2) MUST be refused before chown/chmod so victim mode stays 0644.
	if err := os.Link(victim, optsPath); err != nil {
		t.Fatalf("hardlink: %v", err)
	}
	noopChown := func(string, int, int) error { return nil }
	err := lockDownSecretPathsWith(0, dataDir, noopChown, nil, optsPath)
	if err == nil || !strings.Contains(err.Error(), "hardlinked") {
		t.Fatalf("SECURITY: expected hardlinked secret path to fail closed, got %v", err)
	}
	if vst, sErr := os.Stat(victim); sErr != nil || vst.Mode().Perm() != 0o644 {
		t.Fatalf("SECURITY: victim mode altered via hardlink: %v (err=%v)", vst.Mode().Perm(), sErr)
	}
	_ = os.Remove(optsPath)

	// 2. Named pipe (FIFO) MUST be refused without blocking (O_NONBLOCK).
	fifoPath := filepath.Join(dataDir, "fifo-secret")
	if err := syscall.Mkfifo(fifoPath, 0o644); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	if err := lockDownSecretPathsWith(0, dataDir, noopChown, nil, fifoPath); err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("SECURITY: expected FIFO secret path to fail closed without blocking, got %v", err)
	}
	_ = os.Remove(fifoPath)

	// 3. Symlinked dataDir MUST be refused.
	symData := filepath.Join(tmp, "sym-data")
	if err := os.Symlink(dataDir, symData); err != nil {
		t.Fatalf("symlink dataDir: %v", err)
	}
	if err := lockDownSecretPathsWith(0, symData, noopChown, nil); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("SECURITY: expected symlink dataDir to fail closed, got %v", err)
	}

	// 4. Tight file<->symlink TOCTOU swap race: using real Fchmod (chmodFn == nil), victim MUST NEVER become 0600!
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tmpReal := filepath.Join(dataDir, ".swap-real")
		tmpLink := filepath.Join(dataDir, ".swap-link")
		for !stop.Load() {
			_ = os.WriteFile(tmpReal, []byte("{}"), 0o644)
			_ = os.Rename(tmpReal, optsPath)
			_ = os.Remove(tmpLink)
			_ = os.Symlink(victim, tmpLink)
			_ = os.Rename(tmpLink, optsPath)
		}
	}()
	for i := 0; i < 400; i++ {
		_ = lockDownSecretPathsWith(0, "", noopChown, nil, optsPath)
		if vst, sErr := os.Stat(victim); sErr != nil || vst.Mode().Perm() != 0o644 {
			stop.Store(true)
			wg.Wait()
			t.Fatalf("SECURITY (TOCTOU): victim chmod'ed on trial %d (mode=%o err=%v)", i, vst.Mode().Perm(), sErr)
		}
	}
	stop.Store(true)
	wg.Wait()
}
