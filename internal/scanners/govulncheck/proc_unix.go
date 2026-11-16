//go:build unix

package govulncheck

import (
	"os/exec"
	"syscall"
)

// setProcessGroup puts the child in its own process group, so killing the
// group also kills the `go` toolchain's compilers and any subprocess it left.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup kills the child and everything in its process group.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Process.Kill()
}
