package cli

import (
	"errors"
	"io"
	"os/exec"
	"runtime"
)

var errBrowserUnsupported = errors.New("browser_unsupported")

// openBrowser passes only the fixed loopback URL to a platform opener. It does
// not invoke a shell or use environment-provided command strings.
func openBrowser(url string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url)
	case "darwin":
		command = exec.Command("open", url)
	case "linux":
		command = exec.Command("xdg-open", url)
	default:
		return errBrowserUnsupported
	}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}
