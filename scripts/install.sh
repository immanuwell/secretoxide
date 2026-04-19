#!/usr/bin/env bash
set -eu

REPO="immanuwell/secretoxide"
BREW_TAP="immanuwell/secox"
BREW_FORMULA="immanuwell/secox/secox"
INSTALL_DIR="${HOME}/.local/bin"

# ── helpers ────────────────────────────────────────────────────────────────────

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
cyan()   { printf '\033[36m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n'  "$*"; }
die()    { red "error: $*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"
}

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$1"
    else
        die "neither curl nor wget found — install one and retry"
    fi
}

fetch_file() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        die "neither curl nor wget found — install one and retry"
    fi
}

# ── detect OS / arch ───────────────────────────────────────────────────────────

detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux)   os="linux"  ;;
        Darwin)  os="macos"  ;;
        *)       die "unsupported OS: $(uname -s)" ;;
    esac

    case "$(uname -m)" in
        x86_64 | amd64)          arch="x86_64"  ;;
        aarch64 | arm64)         arch="aarch64" ;;
        *)  die "unsupported architecture: $(uname -m)" ;;
    esac

    echo "${os}-${arch}"
}

# ── latest release version from GitHub API ────────────────────────────────────

latest_version() {
    fetch "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

# ── brew path ─────────────────────────────────────────────────────────────────

install_via_brew() {
    bold "Installing secox via Homebrew…"
    echo ""

    if ! brew tap | grep -q "^${BREW_TAP}$" 2>/dev/null; then
        cyan "  → brew tap ${BREW_TAP}"
        brew tap "${BREW_TAP}" "https://github.com/immanuwell/homebrew-secox.git"
    fi

    cyan "  → brew install ${BREW_FORMULA}"
    brew install "${BREW_FORMULA}"

    echo ""
    green "✓ secox installed via Homebrew"
    echo ""
    cyan "  secox --version"
    secox --version
}

# ── direct binary path ────────────────────────────────────────────────────────

install_binary() {
    local platform version artifact url tmp

    platform="$(detect_platform)"
    version="$(latest_version)"
    [ -n "$version" ] || die "could not determine latest release version"

    artifact="secox-${platform}"
    url="https://github.com/${REPO}/releases/download/${version}/${artifact}"

    bold "Installing secox ${version} (${platform})…"
    echo ""
    cyan "  → ${url}"
    echo ""

    mkdir -p "${INSTALL_DIR}"

    tmp="$(mktemp)"
    fetch_file "$url" "$tmp"
    chmod +x "$tmp"

    # Smoke-test before moving into place
    "$tmp" --version >/dev/null 2>&1 || die "downloaded binary failed smoke test — wrong architecture?"

    mv "$tmp" "${INSTALL_DIR}/secox"

    echo ""
    green "✓ secox ${version} installed → ${INSTALL_DIR}/secox"
    echo ""

    # PATH hint if needed
    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            bold "  Add ${INSTALL_DIR} to your PATH:"
            echo ""
            echo '    # bash / zsh'
            echo "    echo 'export PATH=\"\${HOME}/.local/bin:\${PATH}\"' >> ~/.bashrc"
            echo ""
            echo '    # fish'
            echo "    fish_add_path ~/.local/bin"
            echo ""
            ;;
    esac
}

# ── main ──────────────────────────────────────────────────────────────────────

main() {
    echo ""
    bold "secox installer"
    echo ""

    if command -v brew >/dev/null 2>&1; then
        install_via_brew
    else
        install_binary
    fi

    echo "  Run $(cyan 'secox init') to install the pre-commit hook in your repo."
    echo ""
}

main "$@"
