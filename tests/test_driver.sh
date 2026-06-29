#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# End-to-end / smoke test driver for ssh_bw using the fake `bw` CLI.
#
# Run from the repository root:
#
#     FAKE_BW_VAULT=/tmp/test-vault.json bash tests/test_driver.sh
#     or simply:
#     bash tests/test_driver.sh
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

FAKE_BW="$ROOT/tests/fake-bw"
FAKE_BW_VAULT="${FAKE_BW_VAULT:-$(mktemp /tmp/bw-vault-XXXXXX.json)}"
SSH_DIR="$(mktemp -d /tmp/ssh-test-XXXXXX)"
PASS="testpw"
PASSPHRASE="storeme"

cleanup() { rm -f "$FAKE_BW_VAULT"; rm -rf "$SSH_DIR" /tmp/ssh-bw-export; }
trap cleanup EXIT

# Prepare a fake ~/.ssh
cat > "$SSH_DIR/id_ed25519" <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2g
FAKEKEYDATA1234567890==
-----END OPENSSH PRIVATE KEY-----
EOF
chmod 600 "$SSH_DIR/id_ed25519"
cat > "$SSH_DIR/id_ed25519.pub" <<'EOF'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMMu2ws76gNisO5t30kw7eShE8AIZjqouXmCf0jJqJ31 tester@example.com
EOF

export FAKE_BW_VAULT FAKE_BW_PASSWORD="$PASS"

# CLI convention: global args (--bw-path, --no-sync) BEFORE subcommand;
# auth args (--email, --password, --store-passphrase, …) AFTER subcommand.
GLOBAL="--bw-path $FAKE_BW --no-sync"
AUTH="--store-passphrase $PASSPHRASE --no-keyring"

pass=0; fail=0

check() {
    local desc="$1"; shift
    if "$@"; then
        echo "  PASS: $desc"; pass=$((pass + 1))
    else
        echo "  FAIL: $desc"; fail=$((fail + 1))
    fi
}

echo ""
echo "=== ssh_bw End-to-End Driver (fake vault) ==="
echo "  vault: $FAKE_BW_VAULT"
echo "  ssh:   $SSH_DIR"
echo ""

# 1. help
python -m ssh_bw --help > /dev/null
check "--help works" true

# 2. store credentials (encrypted file)
python -m ssh_bw $GLOBAL \
    credential store --email test@example.com --password "$PASS" $AUTH
check "credential store (encrypted)" true

# 3. forget + re-store
python -m ssh_bw $GLOBAL credential forget $AUTH
check "credential forget" true

# 4. store again for later sync
python -m ssh_bw $GLOBAL \
    credential store --email test@example.com --password "$PASS" $AUTH
check "credential re-store" true

# 5. host list
output=$(python -m ssh_bw $GLOBAL host list --ssh-dir "$SSH_DIR" 2>&1)
check "host list contains key" \
    bash -c "echo '$output' | grep -q 'id_ed25519'"

# 6. sync host (push to vault)
output=$(python -m ssh_bw $GLOBAL \
    sync host --ssh-dir "$SSH_DIR" $AUTH --use-stored --yes 2>&1)
check "sync host (import)" \
    bash -c "echo '$output' | grep -q 'created'"

# 7. vault list --ssh
output=$(python -m ssh_bw $GLOBAL vault list --ssh $AUTH --use-stored 2>&1)
check "vault list --ssh contains key" \
    bash -c "echo '$output' | grep -q 'id_ed25519'"

# 8. vault list --json
output=$(python -m ssh_bw $GLOBAL vault list --json $AUTH --use-stored)
check "vault list --json parses" \
    python3 -c "import sys,json; d=json.loads(sys.stdin.read()); assert len(d['ssh']) > 0" <<< "$output"

# 9. vault output
mkdir -p /tmp/ssh-bw-export
python -m ssh_bw $GLOBAL \
    vault output --type ssh --name id_ed25519 --out-dir /tmp/ssh-bw-export $AUTH --use-stored
check "output file exists" test -f /tmp/ssh-bw-export/id_ed25519
check "output pub file exists" test -f /tmp/ssh-bw-export/id_ed25519.pub

# 10. sync host again (should be unchanged)
output=$(python -m ssh_bw $GLOBAL \
    sync host --ssh-dir "$SSH_DIR" $AUTH --use-stored --yes)
check "re-sync unchanged" \
    bash -c "echo '$output' | grep -q 'unchanged'"

# 11. vault delete
output=$(python -m ssh_bw $GLOBAL \
    vault delete --name id_ed25519 --yes $AUTH --use-stored)
check "vault delete" bash -c "echo '$output' | grep -q 'deleted'"

# 12. verify deletion
output=$(python -m ssh_bw $GLOBAL vault list --ssh $AUTH --use-stored)
check "vault list after delete empty" \
    bash -c "echo '$output' | grep -q 'SSH keys in vault (0)'"

# 13. host search
output=$(python -m ssh_bw $GLOBAL host search "SHA256" --ssh-dir "$SSH_DIR" 2>&1)
check "host search finds key" \
    bash -c "echo '$output' | grep -q 'match'"

# ----- summary -------------------------------------------------------------
echo ""
echo "=== Results: ${pass} passed, ${fail} failed ==="
exit $fail
