package trivy

import (
	"errors"
	"slices"
	"testing"
)

// TestRemoteImageScanArgs pins the remote flags: the docker source is never
// enabled, and --platform appears only for the arm64 retry.
func TestRemoteImageScanArgs(t *testing.T) {
	args := remoteImageScanArgs("/cache", "")
	if !slices.Contains(args, "--image-src") || !slices.Contains(args, "remote") {
		t.Fatalf("args = %v, want --image-src remote", args)
	}
	if slices.Contains(args, "--platform") {
		t.Errorf("args = %v, want no --platform on the first attempt", args)
	}

	retry := remoteImageScanArgs("/cache", "linux/arm64")
	platform := slices.Index(retry, "--platform")
	if platform < 0 || platform+1 >= len(retry) || retry[platform+1] != "linux/arm64" {
		t.Errorf("retry args = %v, want --platform linux/arm64", retry)
	}
}

// TestArm64PlatformMissing recognises only Trivy's no-amd64-child error.
func TestArm64PlatformMissing(t *testing.T) {
	if arm64PlatformMissing(nil) {
		t.Error("nil error reported as a platform miss")
	}
	if !arm64PlatformMissing(errors.New("remote error: no child with platform linux/amd64 in index example")) {
		t.Error("platform error was not recognised")
	}
	if arm64PlatformMissing(errors.New("network unreachable")) {
		t.Error("unrelated error reported as a platform miss")
	}
}
