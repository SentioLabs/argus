#!/usr/bin/env bash
#
# Bootstrap installer for argus. Downloads one release tarball, verifies it
# against the release's checksums.txt, and puts the binary on your PATH.
# Everything after that is handled by `argus self update`.
#
#   curl -fsSL https://raw.githubusercontent.com/sentiolabs/argus/main/scripts/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/sentiolabs/argus/main/scripts/install.sh | bash -s -- --tag=v0.7.0
#
# Options:
#   --tag=TAG          install a specific release tag instead of the latest stable
#
# Environment:
#   ARGUS_INSTALL_DIR  target directory (default: /usr/local/bin if writable, else ~/.local/bin)

set -euo pipefail

REPO="sentiolabs/argus"
TAG=""

usage() {
    sed -n '3,14s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" 2>/dev/null || echo "usage: install.sh [--tag=TAG]"
}

die() {
    echo "install.sh: $*" >&2
    exit 1
}

for arg in "$@"; do
    case "$arg" in
        --tag=*) TAG="${arg#--tag=}" ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $arg (try --help)" ;;
    esac
done

command -v curl >/dev/null || die "curl is required"
command -v tar >/dev/null || die "tar is required"

case "$(uname -s)" in
    Linux)  os=linux ;;
    Darwin) os=darwin ;;
    *)      die "unsupported operating system: $(uname -s)" ;;
esac
case "$(uname -m)" in
    x86_64|amd64)  arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *)             die "unsupported architecture: $(uname -m)" ;;
esac

if [ -z "$TAG" ]; then
    TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
    [ -n "$TAG" ] || die "could not determine the latest release"
fi

asset="argus_${TAG#v}_${os}_${arch}.tar.gz"
base="https://github.com/${REPO}/releases/download/${TAG}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "downloading ${asset}"
curl -fsSL -o "${tmp}/${asset}" "${base}/${asset}" || die "no asset ${asset} in release ${TAG}"
curl -fsSL -o "${tmp}/checksums.txt" "${base}/checksums.txt" || die "release ${TAG} has no checksums.txt"

if command -v sha256sum >/dev/null; then
    (cd "$tmp" && grep "  ${asset}\$" checksums.txt | sha256sum -c --quiet) || die "checksum mismatch for ${asset}"
else
    (cd "$tmp" && grep "  ${asset}\$" checksums.txt | shasum -a 256 -c --quiet) || die "checksum mismatch for ${asset}"
fi

tar -xzf "${tmp}/${asset}" -C "$tmp" argus

dir="${ARGUS_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
    if [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir="${HOME}/.local/bin"; fi
fi
mkdir -p "$dir"
install -m 0755 "${tmp}/argus" "${dir}/argus"

echo "installed argus ${TAG} to ${dir}/argus"
case ":${PATH}:" in
    *":${dir}:"*) ;;
    *) echo "note: ${dir} is not on your PATH" ;;
esac
echo "update later with: argus self update"
