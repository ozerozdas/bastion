//go:build windows

package servelock

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// lockedByteRange is the one-byte range LockFileEx locks. Every process uses
// the same range, so any call conflicts with a held lock.
const lockedByteRange = 1

// tryLock takes a non-blocking exclusive lock on file. A contention is
// reported as errLocked; any other failure is a real error.
func tryLock(file *os.File) error {
	return lockFileEx(file, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, "LockFileEx")
}

// trySharedLock probes with a non-blocking shared lock, so concurrent probes
// do not conflict with each other. It conflicts only with serve's exclusive
// lock, which is reported as errLocked.
func trySharedLock(file *os.File) error {
	return lockFileEx(file, windows.LOCKFILE_FAIL_IMMEDIATELY, "LockFileEx shared")
}

func lockFileEx(file *os.File, flags uint32, op string) error {
	overlapped := new(windows.Overlapped)
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		flags,
		0,
		lockedByteRange,
		0,
		overlapped,
	)
	if err == nil {
		return nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return fmt.Errorf("%w: %w", errLocked, err)
	}
	return fmt.Errorf("%s: %w", op, err)
}

// unlock releases the LockFileEx lock held on file.
func unlock(file *os.File) error {
	overlapped := new(windows.Overlapped)
	if err := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, lockedByteRange, 0, overlapped); err != nil {
		return fmt.Errorf("UnlockFileEx: %w", err)
	}
	return nil
}
