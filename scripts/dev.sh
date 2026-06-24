#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# dev.sh — Convenience script for local ssh-bw development.
#
# Usage:
#   scripts/dev.sh [command]
#
# Commands:
#   setup        Install system build deps, create venv, install Python deps
#   test         Run pytest (uses venv if available, otherwise system)
#   run [args]   Run ssh-bw with arguments (e.g. sync --yes, list --type ssh)
#   build        Build pip package (wheel + sdist) into dist/
#   deb          Build .deb package via dpkg-buildpackage (output in parent)
#   all          setup → test → build → deb (full pipeline)
#   clean        Remove build/dist/__pycache__ artifacts and .venv
#   help         Show this message
#
# Environment:
#   UV           uv binary path ................................ (default: auto-detect)
#   VENV_PATH    virtual environment path ...................... (default: .venv)
#
# Examples:
#   scripts/dev.sh setup           # create .venv and install deps
#   scripts/dev.sh test            # run tests
#   scripts/dev.sh run sync --yes  # invoke ssh-bw sync --yes via venv
#   scripts/dev.sh build           # build pip wheel
#   scripts/dev.sh deb             # build .deb package
#   scripts/dev.sh all             # full pipeline
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ---- colour helpers ---------------------------------------------------------
red()   { printf "\033[31m%s\033[0m\n" "$*" >&2; }
green() { printf "\033[32m%s\033[0m\n" "$*" >&2; }
blue()  { printf "\033[34m%s\033[0m\n" "$*" >&2; }

# ---- defaults ---------------------------------------------------------------
VENV_PATH="${VENV_PATH:-.venv}"
UV="${UV:-"$(command -v uv 2>/dev/null || true)"}"

# ---- helpers ----------------------------------------------------------------
DEB_BUILD_DEPS=(
    debhelper
    devscripts
    dh-python
    python3-all
    python3-setuptools
    python3-cryptography
)

_check_sysdeps() {
    local missing=()
    for pkg in "${DEB_BUILD_DEPS[@]}"; do
        if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "ok installed"; then
            missing+=("$pkg")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        printf '%s\n' "${missing[@]}"
    fi
}

_install_sysdeps() {
    local missing=("$@")
    blue "→ Missing system packages: ${missing[*]}"
    blue "  Installing with sudo apt install …"
    sudo apt install -y "${missing[@]}"
    green "✓ System packages installed"
}

venv_python() {
    local py="$VENV_PATH/bin/python3"
    if [ ! -x "$py" ]; then
        py="$VENV_PATH/bin/python"
    fi
    if [ ! -x "$py" ]; then
        echo ""
        return
    fi
    echo "$py"
}

ensure_venv_msg() {
    blue "  Run 'scripts/dev.sh setup' first to create the virtual environment."
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
cmd_setup() {
    # ---- system-level build dependencies ------------------------------------
    local missing
    missing=$(_check_sysdeps)
    if [ -n "$missing" ]; then
        IFS=$'\n' read -ra missing_arr <<< "$missing"
        blue "→ The following system packages are needed for .deb packaging:"
        for pkg in "${missing_arr[@]}"; do
            blue "    - $pkg"
        done
        read -r -p "  Install with sudo? [y/N] " confirm
        if [[ $confirm =~ ^[yY] ]]; then
            _install_sysdeps "${missing_arr[@]}"
        else
            blue "  Skipping system packages. 'scripts/dev.sh deb' will fail until they are installed."
        fi
    else
        blue "→ All system build dependencies satisfied"
    fi

    # ---- Python virtual environment -----------------------------------------
    if [ -f "$VENV_PATH/bin/python3" ] || [ -f "$VENV_PATH/bin/python" ]; then
        blue "→ Virtual environment already exists at $VENV_PATH"
    else
        if [ -n "$UV" ]; then
            blue "→ Creating venv with uv …"
            "$UV" venv "$VENV_PATH" -p 3
        else
            blue "→ Creating venv with python3 -m venv …"
            python3 -m venv "$VENV_PATH"
        fi
        green "✓ Virtual environment created at $VENV_PATH"
    fi

    local py
    py="$(venv_python)"
    if [ -z "$py" ]; then
        red "Failed to locate python in $VENV_PATH"
        exit 1
    fi

    blue "→ Installing Python build/test dependencies …"
    if [ -n "$UV" ]; then
        "$UV" pip install --python "$py" build pytest setuptools 2>&1 | tail -3
    else
        "$py" -m pip install build pytest setuptools -q 2>&1 | tail -3
    fi

    blue "→ Installing project in editable mode …"
    if [ -n "$UV" ]; then
        "$UV" pip install --python "$py" --no-build-isolation -e . 2>&1 | tail -3
    else
        "$py" -m pip install --no-build-isolation -e . -q 2>&1 | tail -3
    fi

    green "✓ Setup complete. Use 'scripts/dev.sh test' to run tests."
}

cmd_test() {
    local py
    py="$(venv_python)"
    if [ -n "$py" ]; then
        blue "→ Running tests via $VENV_PATH …"
        "$py" -m pytest tests/ -v "$@"
    else
        blue "→ Running tests via system python …"
        python3 -m pytest tests/ -v "$@"
    fi
    green "✓ All tests passed"
}

cmd_run() {
    local py
    py="$(venv_python)"
    if [ -z "$py" ]; then
        red "Virtual environment not found at $VENV_PATH"
        ensure_venv_msg
        exit 1
    fi
    if [ $# -eq 0 ]; then
        "$py" -m ssh_bw --help
    else
        "$py" -m ssh_bw "$@"
    fi
}

cmd_build() {
    local py
    py="$(venv_python)"
    if [ -z "$py" ]; then
        red "Virtual environment not found at $VENV_PATH"
        ensure_venv_msg
        exit 1
    fi
    blue "→ Building pip package via $VENV_PATH …"
    "$py" -m build
    green "✓ Built:"
    ls -1 dist/
}

cmd_deb() {
    blue "→ Building .deb package …"
    local missing
    missing=$(_check_sysdeps)
    if [ -n "$missing" ]; then
        red "Missing build dependencies:"
        IFS=$'\n' read -ra missing_arr <<< "$missing"
        for pkg in "${missing_arr[@]}"; do
            red "    - $pkg"
        done
        blue "  Run 'scripts/dev.sh setup' to install them."
        exit 1
    fi
    if [ ! -s debian/changelog ]; then
        red "debian/changelog is empty. Run scripts/release.sh first to create a release."
        exit 1
    fi
    dpkg-buildpackage -b -uc -us
    green "✓ .deb built  —  check ../ssh-bw_*.deb"
}

cmd_clean() {
    blue "→ Cleaning build artifacts …"
    rm -rf build/ dist/ *.egg-info .pytest_cache
    find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
    find . -name '*.pyc' -delete
    if [ -d "$VENV_PATH" ]; then
        rm -rf "$VENV_PATH"
        green "✓ Removed $VENV_PATH"
    fi
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
    setup|bootstrap) cmd_setup ;;
    test)            shift; cmd_test "$@" ;;
    run)             shift; cmd_run "$@" ;;
    build)           cmd_build ;;
    deb)             cmd_deb ;;
    all)             cmd_setup && cmd_test && cmd_build && cmd_deb ;;
    clean)           cmd_clean ;;
    help|-h|--help)  cmd_help ;;
    *)
        red "Unknown command: $1"
        echo ""
        cmd_help
        ;;
esac
