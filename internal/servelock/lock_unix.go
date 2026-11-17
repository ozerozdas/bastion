//go:build unix

package servelock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// tryLock takes a non-blocking exclusive flock on file. A contention is
// reported as errLocked; any other failure is a real error.
func tryLock(file *os.File) error {
	return flock(file, syscall.LOCK_EX, "flock")
}

// trySharedLock probes with a non-blocking shared flock, so concurrent probes
// do not conflict with each other. It conflicts only with serve's exclusive
// lock, which is reported as errLocked.
func trySharedLock(file *os.File) error {
	return flock(file, syscall.LOCK_SH, "flock shared")
}

func flock(file *os.File, how int, op string) error {
	if err := syscall.Flock(int(file.Fd()), how|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("%w: %w", errLocked, err)
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// unlock releases the flock held on file.
func unlock(file *os.File) error {
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("flock unlock: %w", err)
	}
	return nil
}
