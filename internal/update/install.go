package update

import (
	"runtime"
	"strings"

	"golang.org/x/mod/semver"
)

// defaultGOOS is the build target, used when Config.GOOS is unset.
const defaultGOOS = runtime.GOOS

const (
	// brewCommand upgrades a Homebrew cask install.
	brewCommand = "brew upgrade ozerozdas/tap/bastion"
	// installCommand is the README one-liner for macOS and Linux.
	installCommand = "curl -fsSL https://raw.githubusercontent.com/ozerozdas/bastion/master/install.sh | sh"
)

// installCommandFor guesses how the binary was installed and returns the
// command that updates it. Windows has no shell one-liner, so it gets only the
// release link.
func installCommandFor(executablePath, goos string) string {
	if goos == "windows" {
		return ""
	}

	// Homebrew puts the binary under /homebrew/ or /linuxbrew/ and casks under
	// /Caskroom/. The path is compared case-insensitively on slash-normalised
	// input so a macOS path and a Linux path share the table.
	path := strings.ToLower(strings.ReplaceAll(executablePath, `\`, "/"))
	if strings.Contains(path, "/caskroom/") ||
		strings.Contains(path, "/homebrew/") ||
		strings.Contains(path, "/linuxbrew/") {
		return brewCommand
	}
	return installCommand
}

// validVersion reports whether v is a release version semver can compare.
func validVersion(v string) bool {
	return semver.IsValid(normalizeVersion(v))
}

// normalizeVersion gives a bare version its "v" prefix, so both release tags
// (`v0.1.2`) and GoReleaser's `.Version` (`0.1.2`) compare correctly.
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

// newerThan reports whether latest is a newer release than current. A version
// that is not valid semver (for example `dev`) is never newer.
func newerThan(current, latest string) bool {
	current = normalizeVersion(current)
	latest = normalizeVersion(latest)
	if !semver.IsValid(current) || !semver.IsValid(latest) {
		return false
	}
	return semver.Compare(latest, current) > 0
}
