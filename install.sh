#!/usr/bin/env bash
# Orbit installer — https://github.com/mikhailtomasovic/orbit
set -euo pipefail

REPO="${ORBIT_REPO:-https://raw.githubusercontent.com/mikhailtomasovic/orbit/main}"
DEST="${ORBIT_HOME:-$HOME/.orbit}"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONS="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/256x256/apps"
PIXMAPS="${XDG_DATA_HOME:-$HOME/.local/share}/pixmaps"
BIN="${XDG_BIN_HOME:-$HOME/.local/bin}"

gold=$'\033[38;2;196;165;116m'
mute=$'\033[38;2;154;145;134m'
reset=$'\033[0m'
bold=$'\033[1m'

banner() {
  printf '%s\n' "${gold}"
  cat <<'EOF'
      .  o    .
   .        O      .
      .  ─────◯─────
   .     orbits        .
      .            .
EOF
  printf '%s\n' "${reset}"
  printf '  %sORBIT%s  %sProtonVPN rotator%s\n\n' "$bold$gold" "$reset" "$mute" "$reset"
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing  %s\n' "$1" >&2
    exit 1
  }
}

fetch() {
  local url="$1" out="$2"
  printf '  %s↓%s  %s\n' "$gold" "$reset" "$(basename "$out")"
  curl -fsSL "$url" -o "$out"
}

banner
need curl
need python3

mkdir -p "$DEST/tunnels" "$APPS" "$ICONS" "$PIXMAPS" "$BIN"

fetch "$REPO/orbit.py" "$DEST/orbit.py"
fetch "$REPO/assets/orbit-256.png" "$DEST/orbit.png"
cp "$DEST/orbit.png" "$ICONS/orbit.png"
cp "$DEST/orbit.png" "$PIXMAPS/orbit.png"

cat > "$BIN/orbit" <<EOF
#!/usr/bin/env bash
exec python3 "$DEST/orbit.py" "\$@"
EOF
chmod +x "$BIN/orbit" "$DEST/orbit.py"

printf '  %s✓%s  %s\n' "$gold" "$reset" "$DEST"
printf '  %s✓%s  icon\n' "$gold" "$reset"
printf '  %s✓%s  %s/orbit\n\n' "$gold" "$reset" "$BIN"

export PATH="$BIN:$PATH"
exec python3 "$DEST/orbit.py" install
