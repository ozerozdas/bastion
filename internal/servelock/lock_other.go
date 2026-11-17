//go:build !unix && !windows

package servelock

import "os"

// tryLock is a no-op where the platform has no file lock we use: serve still
// starts (with no mutual exclusion), and Held always reports no server. A
// `bastion mcp` on such a platform therefore refuses trigger_scan instead of
// risking a second scan manager. bastion ships linux, darwin and windows
// builds, so this is a compile fallback only.
func tryLock(*os.File) error { return nil }

// trySharedLock is a no-op for the same reason; nothing is held to detect.
func trySharedLock(*os.File) error { return nil }

// unlock is a no-op; nothing was locked.
func unlock(*os.File) error { return nil }
