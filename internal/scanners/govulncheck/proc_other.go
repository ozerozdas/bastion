//go:build !unix

package govulncheck

import "os/exec"

// setProcessGroup is a no-op where process groups are not available.
func setProcessGroup(*exec.Cmd) {}

// killProcessGroup kills the child. Platforms without process groups cannot
// also reach its grandchildren, so WaitDelay bounds the wait.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
