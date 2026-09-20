//go:build !windows

package cli

// CreateTemp plus chmod(0600) supplies private owner access on POSIX-like
// platforms. Windows uses an explicit protected DACL in output_windows.go.
func restrictTempFile(string) error { return nil }
