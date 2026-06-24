#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# dev.sh — Convenience script for local ssh-bw development.
#
# Usage:
#   scripts/dev.sh [command]
#
# Commands:
#   test         Run pytest (default)
#   build        Build pip package (wheel + sdist) into dist/
#   deb          Build .deb package via dpkg-buildpackage (output in parent)
#   all          test → build → deb (full pipeline)
#   clean        Remove build/dist/__pycache__ artifacts
#   help         Show this message
#
# Examples:
#   scripts/dev.sh test        # just run tests
#   scripts/dev.sh build       # build pip wheel
#   scripts/dev.sh deb         # build .deb package
#   scripts/dev.sh all         # full pipeline
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ---- colour helpers (copied from release.sh) --------------------------------
red()   { printf "\033[31m%s\033[0m\n" "$*" >&2; }
green() { printf "\033[32m%s\033[0m\n" "$*" >&2; }
blue()  { printf "\033[34m%s\033[0m\n" "$*" >&2; }

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
cmd_test() {
    blue "→ Running tests …"
    python3 -m pytest tests/ -v
    green "✓ All tests passed"
}

cmd_build() {
    blue "→ Building pip package …"
    if ! python3 -m build --help &>/dev/null; then
        blue "  Installing build …"
        python3 -m pip install build -q
    fi
    python3 -m build
    green "✓ Built:"
    ls -1 dist/
}

cmd_deb() {
    blue "→ Building .deb package …"
    if ! command -v dpkg-buildpackage &>/dev/null; then
        red "dpkg-buildpackage not found. Install it with:  sudo apt install devscripts"
        exit 1
    fi
    if ! command -v dch &>/dev/null; then
        red "dch (devscripts) is required.  Install it with:  sudo apt install devscripts"
        exit 1
    fi
    # Ensure debian/changelog has a valid entry; offer to run release.sh if missing.
    if [ ! -s debian/changelog ]; then
        red "debian/changelog is empty. Run scripts/release.sh first to create a release."
        exit 1
    fi
    dpkg-buildpackage -b -uc -us
    green "✓ .deb built  —  check ../ssh-bw_*.deb"
}

cmd_clean() {
    blue "→ Cleaning build artifacts …"
    rm -rf build/ dist/ *.egg-info .pytest_cache __pycache__
    find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
    find . -name '*.pyc' -delete
    green "✓ Clean"
}

cmd_help() {
    sed -n '/^#.*Usage:/,/^[^#]/p' "$0" | sed '1d;$d' | sed 's/^# //; s/^#$//'
    exit 0
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
case "${1:-help}" in
    test)    cmd_test ;;
    build)   cmd_build ;;
    deb)     cmd_deb ;;
    all)     cmd_test && cmd_build && cmd_deb ;;
    clean)   cmd_clean ;;
    help|-h|--help) cmd_help ;;
    *)
        red "Unknown command: $1"
        echo ""
        cmd_help
        ;;
esac
