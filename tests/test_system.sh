#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# System-level test for bwforgectl that exercises the REAL Bitwarden CLI (`bw`).
#
# Creates a temporary SSH key pair, imports it into the vault, lists, exports,
# verifies, updates, and finally deletes it.
#
# Usage:
#     bash tests/test_system.sh
#
# Credentials: set BW_EMAIL and BW_PASSWORD env vars, or you will be prompted.
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="__SSH_BW_TEST__"

PASS="\033[0;32mPASS\033[0m"
FAIL="\033[0;31mFAIL\033[0m"
INFO="\033[1;34mINFO\033[0m"
NC="\033[0m"

pass=0; fail=0

check() {
    local desc="$1"; shift
    if "$@"; then
        echo -e "  ${PASS}: ${desc}"; pass=$((pass + 1))
    else
        echo -e "  ${FAIL}: ${desc}"; fail=$((fail + 1))
    fi
}

# ---- paths & temp dirs -------------------------------------------------------
TMPDIR=$(mktemp -d /tmp/bwforgectl-system-test-XXXXXX)
SSH_DIR="${TMPDIR}/dotssh"
mkdir -p "$SSH_DIR"
KEY_NAME="testkey_ed25519_$$"
PRIV="${SSH_DIR}/${KEY_NAME}"
PUB="${PRIV}.pub"

STORE_PASSPHRASE="${PREFIX}-passphrase-$$"
OUT_DIR="${TMPDIR}/export"
mkdir -p "$OUT_DIR"

# Cleanup vault items and temp files on exit.
cleanup() {
    set +e
    rm -rf "$TMPDIR"
    if [ -n "${BW_SESSION+x}" ] && [ -n "$BW_SESSION" ]; then
        bw list items --session "$BW_SESSION" 2>/dev/null \
            | python3 -c "
import json, sys, subprocess, os
session = os.environ.get('BW_SESSION', '')
for item in json.load(sys.stdin):
    name = item.get('name', '')
    if name.startswith('${PREFIX}'):
        item_id = item.get('id', '')
        if item_id:
            subprocess.run(['bw', 'delete', 'item', item_id, '--session', session],
                         capture_output=True)
            print(f'  Cleaned up: {name} ({item_id})')
" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# ---- colours -------------------------------------------------------------
BW_BIN="$(which bw)"

# ---- resolve credentials -------------------------------------------------
EMAIL="${BW_EMAIL:-}"
PASSWORD="${BW_PASSWORD:-}"
if [ -z "$EMAIL" ]; then
    read -r -p "Bitwarden email: " EMAIL
fi
if [ -z "$PASSWORD" ]; then
    read -r -s -p "Bitwarden master password: " PASSWORD
    echo ""
fi

# ---- generate SSH key ----------------------------------------------------
echo -e "${INFO}Generating temporary SSH key pair …${NC}"
ssh-keygen -t ed25519 -C "${PREFIX}-test@example.com" -f "$PRIV" -N "" -q
check "SSH key pair generated" test -f "$PRIV" -a -f "$PUB"

# ---- unlock vault --------------------------------------------------------
echo -e "${INFO}Unlocking Bitwarden vault …${NC}"
BW_SESSION=$(bw unlock "$PASSWORD" --raw)
export BW_SESSION
check "vault unlocked" [ -n "$BW_SESSION" ]
bw sync --session "$BW_SESSION" > /dev/null
check "bw sync" true

# ==== CLI CONVENTIONS =====================================================
# General CLI args (--bw-path, --no-sync, etc.) go BEFORE the subcommand.
# Auth args (--email, --password, --use-stored, --store-passphrase, …)
# go AFTER the subcommand (they are defined on each subparser).
GLOBAL="--bw-path ${BW_BIN} --no-sync"
AUTH="--store-passphrase ${STORE_PASSPHRASE} --no-keyring --use-stored"

# ---- store credentials ---------------------------------------------------
echo -e "${INFO}Storing credentials …${NC}"
python -m bw_forge_ctl ${GLOBAL} \
    store-credentials --email "$EMAIL" --password "$PASSWORD" ${AUTH}
check "store-credentials via encrypted file" true

# ---- import (sync) -------------------------------------------------------
echo -e "${INFO}Importing SSH key …${NC}"
PYTHONPATH="$ROOT" python -m bw_forge_ctl ${GLOBAL} \
    sync --ssh-dir "$SSH_DIR" --name-prefix "${PREFIX}" --update --yes ${AUTH}
check "sync (import)" true

# ---- list ----------------------------------------------------------------
echo -e "${INFO}Listing vault items …${NC}"
LIST_OUT=$(PYTHONPATH="$ROOT" python -m bw_forge_ctl ${GLOBAL} \
    list --type ssh ${AUTH})
check "list contains test key" \
    bash -c "echo '$LIST_OUT' | grep -q '${PREFIX}${KEY_NAME}'"

# ---- list --json ---------------------------------------------------------
LIST_JSON=$(PYTHONPATH="$ROOT" python -m bw_forge_ctl ${GLOBAL} \
    list --type ssh --json ${AUTH})
check "list --json parses" \
    python3 -c "
import sys,json
d=json.loads(sys.stdin.read())
items=[i for i in d.get('ssh',[]) if '${PREFIX}' in i.get('name','')]
assert len(items)>=1
" <<< "$LIST_JSON"

# ---- output (export to files) --------------------------------------------
PYTHONPATH="$ROOT" python -m bw_forge_ctl ${GLOBAL} \
    output --type ssh --name "${PREFIX}${KEY_NAME}" --out-dir "$OUT_DIR" ${AUTH}
check "exported private key exists" test -f "${OUT_DIR}/${PREFIX}${KEY_NAME}"
check "exported public key exists" test -f "${OUT_DIR}/${PREFIX}${KEY_NAME}.pub"

# ---- verify exported content matches original ----------------------------
check "exported private key matches original" \
    diff "$PRIV" "${OUT_DIR}/${PREFIX}${KEY_NAME}"
check "exported public key matches original" \
    diff "$PUB" "${OUT_DIR}/${PREFIX}${KEY_NAME}.pub"

# ---- output to stdout ----------------------------------------------------
STDOUT_OUT=$(PYTHONPATH="$ROOT" python -m bw_forge_ctl ${GLOBAL} \
    output --type ssh --name "${PREFIX}${KEY_NAME}" --show-private ${AUTH})
check "output shows public key via stdout" \
    bash -c "echo '$STDOUT_OUT' | grep -q 'ssh-ed25519'"
check "output shows private key via stdout" \
    bash -c "echo '$STDOUT_OUT' | grep -q 'BEGIN OPENSSH PRIVATE KEY'"

# ---- sync again (should be unchanged) ------------------------------------
SYNC2_OUT=$(PYTHONPATH="$ROOT" python -m bw_forge_ctl ${GLOBAL} \
    sync --ssh-dir "$SSH_DIR" --name-prefix "${PREFIX}" --update --yes ${AUTH})
check "re-sync reports unchanged" \
    bash -c "echo '$SYNC2_OUT' | grep -q 'unchanged'"

# ---- delete --------------------------------------------------------------
DELETE_OUT=$(PYTHONPATH="$ROOT" python -m bw_forge_ctl ${GLOBAL} \
    delete --name "${PREFIX}${KEY_NAME}" --yes --permanent ${AUTH})
check "delete reports deleted" \
    bash -c "echo '$DELETE_OUT' | grep -q 'deleted'"

# ---- verify deleted ------------------------------------------------------
LIST_FINAL=$(PYTHONPATH="$ROOT" python -m bw_forge_ctl ${GLOBAL} \
    list --type ssh ${AUTH})
check "list after delete no longer contains test key" \
    bash -c "! echo '$LIST_FINAL' | grep -q '${PREFIX}${KEY_NAME}'"

# ===== Summary ===========================================================
echo ""
echo -e "${INFO}============================================${NC}"
echo -e "${INFO} Results: ${pass} passed, ${fail} failed     ${NC}"
echo -e "${INFO}============================================${NC}"
exit $fail
