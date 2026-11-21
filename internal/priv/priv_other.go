//go:build !linux

package priv

// LockDownSecretPaths is a no-op on non-Linux development platforms (macOS / Windows).
func LockDownSecretPaths(_ ...string) error {
	return nil
}

// LockDownSecretPathsStrict is a no-op on non-Linux development platforms (macOS / Windows).
func LockDownSecretPathsStrict(_ ...string) error {
	return nil
}

// DropRoot is a no-op on non-Linux development platforms (macOS / Windows).
func DropRoot() error {
	return nil
}
