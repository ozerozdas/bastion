#!/bin/sh
# Install bastion from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/ozerozdas/bastion/master/install.sh | sh
#
# Read it first — it is short. Environment:
#   BASTION_VERSION      tag to install (e.g. v0.1.0); default: latest release
#   BASTION_INSTALL_DIR  target directory; default: $HOME/.local/bin
#
# The archive is verified against the release's checksums.txt; a mismatch or a
# missing entry aborts the install. No sudo, no files outside the install dir
# and a temporary directory that is removed on exit.
set -eu

REPO="ozerozdas/bastion"
BIN="bastion"

err() {
	echo "install.sh: $*" >&2
	exit 1
}

need() {
	command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"
}

need uname
need curl
need tar
need awk

# --- version ---------------------------------------------------------------
version="${1:-${BASTION_VERSION:-}}"
if [ -z "$version" ]; then
	# Follow the /releases/latest redirect instead of the API: no token, no jq.
	url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest") ||
		err "cannot resolve the latest release (network or no release yet)"
	version="${url##*/}"
	[ -n "$version" ] && [ "$version" != "latest" ] || err "cannot resolve the latest release tag"
fi
case "$version" in
v*) ;;
*) version="v${version}" ;;
esac
# Archives are named with the version without its leading "v".
plain_version="${version#v}"

# --- platform --------------------------------------------------------------
os=$(uname -s)
case "$os" in
Darwin) os=darwin ;;
Linux) os=linux ;;
*) err "unsupported OS: $os (download a release manually: https://github.com/${REPO}/releases)" ;;
esac

arch=$(uname -m)
case "$arch" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) err "unsupported architecture: $arch" ;;
esac

archive="${BIN}_${plain_version}_${os}_${arch}.tar.gz"
base="https://github.com/${REPO}/releases/download/${version}"

# --- download --------------------------------------------------------------
tmp=$(mktemp -d) || err "cannot create a temporary directory"
trap 'rm -rf "$tmp"' EXIT INT TERM HUP

echo "Downloading ${archive} ..."
curl -fsSL --retry 3 -o "${tmp}/${archive}" "${base}/${archive}" ||
	err "download failed: ${base}/${archive}"
curl -fsSL --retry 3 -o "${tmp}/checksums.txt" "${base}/checksums.txt" ||
	err "download failed: ${base}/checksums.txt"

# --- verify ----------------------------------------------------------------
expected=$(awk -v f="$archive" '$2 == f { print $1; exit }' "${tmp}/checksums.txt")
[ -n "$expected" ] || err "${archive} is not listed in checksums.txt"

if command -v sha256sum >/dev/null 2>&1; then
	actual=$(sha256sum "${tmp}/${archive}" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
	actual=$(shasum -a 256 "${tmp}/${archive}" | awk '{ print $1 }')
else
	err "neither sha256sum nor shasum is available, cannot verify the download"
fi

[ "$actual" = "$expected" ] ||
	err "checksum mismatch for ${archive}: expected ${expected}, got ${actual}"

# --- install ---------------------------------------------------------------
tar -xzf "${tmp}/${archive}" -C "$tmp" || err "cannot extract ${archive}"
[ -f "${tmp}/${BIN}" ] || err "${BIN} not found in ${archive}"

install_dir="${BASTION_INSTALL_DIR:-${HOME}/.local/bin}"
mkdir -p "$install_dir" || err "cannot create ${install_dir}"
if command -v install >/dev/null 2>&1; then
	install -m 0755 "${tmp}/${BIN}" "${install_dir}/${BIN}"
else
	cp "${tmp}/${BIN}" "${install_dir}/${BIN}"
	chmod 0755 "${install_dir}/${BIN}"
fi

echo "Installed ${BIN} ${version} to ${install_dir}/${BIN}"

case ":${PATH}:" in
*":${install_dir}:"*) ;;
*) echo "Note: ${install_dir} is not in PATH; add it to your shell profile." ;;
esac
echo "Next: run '${BIN}' (it opens the UI in your browser)."
