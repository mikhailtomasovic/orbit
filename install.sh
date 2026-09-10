#!/usr/bin/env bash
# Orbit installer — https://github.com/mikhailtomasovic/orbit
set -euo pipefail

REPO="${ORBIT_REPO:-https://raw.githubusercontent.com/mikhailtomasovic/orbit/main}"
DEST="${ORBIT_HOME:-$HOME/.orbit}"

gold=$'\033[38;2;196;165;116m'
mute=$'\033[38;2;154;145;134m'
reset=$'\033[0m'
bold=$'\033[1m'

printf '%s\n' "$gold"
cat <<'EOF'
      .  o    .
   .        O      .
      .  ─────◯─────
   .     orbits        .
      .            .
EOF
printf '%s  %sORBIT%s  %sProtonVPN rotator%s\n\n' "$reset" "$bold$gold" "$reset" "$mute" "$reset"

command -v curl >/dev/null && command -v python3 >/dev/null || {
  echo "need curl and python3" >&2
  exit 1
}

mkdir -p "$DEST/tunnels"
printf '  %s↓%s  orbit.py\n' "$gold" "$reset"
curl -fsSL "$REPO/orbit.py" -o "$DEST/orbit.py"
printf '  %s↓%s  icon\n' "$gold" "$reset"
curl -fsSL "$REPO/assets/orbit-256.png" -o "$DEST/orbit.png"
chmod +x "$DEST/orbit.py"
export PATH="${XDG_BIN_HOME:-$HOME/.local/bin}:$PATH"
python3 "$DEST/orbit.py" setup
printf '\n  %sLaunch from the app menu, or:%s  orbit\n\n' "$gold" "$reset"
if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
  exec "${XDG_BIN_HOME:-$HOME/.local/bin}/orbit"
fi
