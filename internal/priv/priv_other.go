//go:build !linux

package priv

// DropRoot is a no-op on non-Linux development platforms (macOS / Windows).
func DropRoot() error {
	return nil
}
