#!/bin/bash

# Usage: ./bw-ssh-import.sh "My SSH Key Name" ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.pub
# Requires `bw` and `jq`.

NAME=$1
PRIVATE_KEY_PATH=$2
PUBLIC_KEY_PATH=$3

if [[ -z "$NAME" || -z "$PRIVATE_KEY_PATH" || -z "$PUBLIC_KEY_PATH" ]]; then
  echo "Usage: $0 <item_name> <private_key_path> <public_key_path>"
  exit 1
fi

export BW_SESSION=$(bw unlock --raw)

bw sync --session "$BW_SESSION"

# -l: show fingerprint, -f: specify file
FINGERPRINT=$(ssh-keygen -lf "$PUBLIC_KEY_PATH" | awk '{print $2}')

# --arg to safely passes file contents
JSON_PAYLOAD=$(bw get template item --session "$BW_SESSION" | jq -c \
  --arg name "$NAME" \
  --arg priv "$(cat "$PRIVATE_KEY_PATH")" \
  --arg pub "$(cat "$PUBLIC_KEY_PATH")" \
  --arg fp "$FINGERPRINT" \
  '.type = 5 |
     .name = $name |
     .sshKey.privateKey = $priv |
     .sshKey.publicKey = $pub |
     .sshKey.keyFingerprint = $fp')

echo "$JSON_PAYLOAD" | bw encode --session "$BW_SESSION" | bw create item --session "$BW_SESSION"
