#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# release.sh — Build and release helper for ssh-bw
#
# Usage:
#   scripts/release.sh            # show current version and prompt for new one
#   scripts/release.sh 1.1.0      # bump to 1.1.0, tag, and optionally push
#
# Environment:
#   GIT_REMOTE         remote to push to (default: origin)
#   DEB_DISTRIBUTION   Debian/Ubuntu suite (default: noble)
#   DEB_URGENCY        changelog urgency (default: medium)
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

GIT_REMOTE="${GIT_REMOTE:-origin}"
DEB_DISTRIBUTION="${DEB_DISTRIBUTION:-noble}"
DEB_URGENCY="${DEB_URGENCY:-medium}"

# ---- colour helpers --------------------------------------------------------
red()   { printf "\033[31m%s\033[0m\n" "$*" >&2; }
green() { printf "\033[32m%s\033[0m\n" "$*" >&2; }
blue()  { printf "\033[34m%s\033[0m\n" "$*" >&2; }

# ---- checks ----------------------------------------------------------------
if ! git diff --quiet --exit-code; then
    red "Working tree has uncommitted changes. Commit or stash first."
    exit 1
fi
if ! git diff --cached --quiet --exit-code; then
    red "There are staged but uncommitted changes. Commit first."
    exit 1
fi

# shellcheck disable=SC2310
if ! command -v dch &>/dev/null; then
    red "dch (devscripts) is required.  Install it with:  sudo apt install devscripts"
    exit 1
fi

# ---- read current version --------------------------------------------------
CURRENT="$(python3 -c "from ssh_bw import __version__; print(__version__)")"

# ---- determine new version -------------------------------------------------
if [ $# -ge 1 ]; then
    NEW="$1"
else
    echo "Current version: ${CURRENT}"
    read -r -p "New version [${CURRENT}]: " input
    NEW="${input:-$CURRENT}"
fi

# Validate semver-ish format (X.Y.Z or X.Y.Z-devN etc.)
if ! [[ $NEW =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    red "Version must start with X.Y.Z (e.g. 1.1.0). Got: $NEW"
    exit 1
fi

if [ "$NEW" = "$CURRENT" ]; then
    blue "Version unchanged ($CURRENT). Bumping Debian revision …"
    DEB_REVISION="${NEW}-1"
else
    DEB_REVISION="${NEW}-1"
fi

echo ""
blue   "  Current version : ${CURRENT}"
green  "  New version     : ${NEW}"
green  "  Debian revision : ${DEB_REVISION}"
echo ""

# Confirm
read -r -p "Proceed with version bump? [y/N] " confirm
if ! [[ $confirm =~ ^[yY] ]]; then
    echo "Aborted."
    exit 0
fi

# ---- 1. Update Python package version files --------------------------------
blue "Updating ssh_bw/__init__.py …"
sed -i "s/^__version__ = \".*\"/__version__ = \"${NEW}\"/" ssh_bw/__init__.py

blue "Updating pyproject.toml …"
sed -i "s/^version = \".*\"/version = \"${NEW}\"/" pyproject.toml

blue "Updating setup.py …"
sed -i "s/version=\".*\"/version=\"${NEW}\"/" setup.py

# ---- 2. Update debian/changelog --------------------------------------------
blue "Updating debian/changelog …"
DEBFULLNAME="${DEBFULLNAME:-$(git config user.name || echo "developer")}"
DEBEMAIL="${DEBEMAIL:-$(git config user.email || echo "developer@example.com")}"
export DEBFULLNAME DEBEMAIL

if dch --version &>/dev/null; then
    dch -v "${DEB_REVISION}" -D "${DEB_DISTRIBUTION}" -u "${DEB_URGENCY}" \
        "Release version ${NEW}."
else
    # Fallback: prepend a manual entry
    DATE="$(date -R)"
    cat > /tmp/changelog.new <<EOF
ssh-bw (${DEB_REVISION}) ${DEB_DISTRIBUTION}; urgency=${DEB_URGENCY}

  * Release version ${NEW}.

 -- ${DEBFULLNAME} <${DEBEMAIL}>  ${DATE}

EOF
    cat debian/changelog >> /tmp/changelog.new
    mv /tmp/changelog.new debian/changelog
fi

# ---- 3. Commit -------------------------------------------------------------
blue "Committing version bump …"
git add -A
git commit -m "Bump version to ${NEW}"

# ---- 4. Create annotated tag -----------------------------------------------
TAG="v${NEW}"
if git rev-parse "$TAG" &>/dev/null; then
    red "Tag $TAG already exists locally. Delete it first if you want to re-tag."
    exit 1
fi

blue "Creating annotated tag ${TAG} …"
git tag -a "$TAG" -m "Release ${NEW}"

# ---- 5. Push ---------------------------------------------------------------
echo ""
blue "Changes committed and tagged locally."
echo ""
read -r -p "Push commit and tag ${TAG} to ${GIT_REMOTE}? [y/N] " push_confirm
if [[ $push_confirm =~ ^[yY] ]]; then
    blue "Pushing commit to ${GIT_REMOTE}/main …"
    git push "${GIT_REMOTE}" main
    blue "Pushing tag ${TAG} to ${GIT_REMOTE} …"
    git push "${GIT_REMOTE}" "$TAG"
    green "Done! The GitHub Actions workflow will build and publish the release."
else
    echo "Commit and tag are local. Push manually when ready:"
    echo "  git push ${GIT_REMOTE} main"
    echo "  git push ${GIT_REMOTE} ${TAG}"
fi
