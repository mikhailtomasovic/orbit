#!/usr/bin/env bash
# Build Orbit.run (self-extracting, IntuneWin-style for desktops) and a .deb
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(tr -d ' \n' < "$ROOT/VERSION")"
DIST="$ROOT/dist"
STAGE="$DIST/payload"
DEB="$DIST/deb"
mkdir -p "$DIST"

rm -rf "$STAGE" "$DEB"
mkdir -p "$STAGE/assets"
cp "$ROOT/orbit.py" "$STAGE/orbit.py"
cp "$ROOT/install.sh" "$STAGE/install.sh"
cp "$ROOT/assets/orbit-256.png" "$STAGE/assets/orbit-256.png"
cp "$ROOT/assets/orbit.png" "$STAGE/orbit.png"
cp "$ROOT/VERSION" "$STAGE/VERSION"
cat > "$STAGE/setup.sh" <<'SETUP'
#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="${ORBIT_HOME:-$HOME/.orbit}"
BIN="${XDG_BIN_HOME:-$HOME/.local/bin}"
gold=$'\033[38;2;196;165;116m'
reset=$'\033[0m'
printf '%s\n  ORBIT  unpacking to %s\n%s\n' "$gold" "$DEST" "$reset"
mkdir -p "$DEST/tunnels" "$BIN"
cp "$HERE/orbit.py" "$DEST/orbit.py"
cp "$HERE/orbit.png" "$DEST/orbit.png"
chmod +x "$DEST/orbit.py"
python3 "$DEST/orbit.py" setup
printf '\n  %sLaunch:%s  Orbit in the app menu, or:  orbit\n\n' "$gold" "$reset"
if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
  exec "${BIN}/orbit"
fi
SETUP
chmod +x "$STAGE/setup.sh" "$STAGE/orbit.py"

# --- self-extracting .run ---
PAYLOAD="$DIST/payload.tar.gz"
tar -C "$STAGE" -czf "$PAYLOAD" .
STUB="$DIST/stub.sh"
cat > "$STUB" <<STUB
#!/usr/bin/env bash
# Orbit ${VERSION} — self-extracting installer (not an Intune package)
set -euo pipefail
gold=\$'\033[38;2;196;165;116m'
reset=\$'\033[0m'
printf '%s\n      ◯  ORBIT  %s\n' "\$gold" "\$reset"
TMP="\$(mktemp -d /tmp/orbit-unpack.XXXXXX)"
trap 'rm -rf "\$TMP"' EXIT
ARCHIVE_LINE=\$((LINENO + 8))
tail -n +\$ARCHIVE_LINE "\$0" | tar -xz -C "\$TMP"
bash "\$TMP/setup.sh"
exit \$?
# payload
STUB
# LINENO in stub is evaluated at runtime inside the extracted script... wait, the stub is the .run file itself.
# Fix: use a marker.

cat > "$STUB" <<'STUB'
#!/usr/bin/env bash
# Orbit self-extracting installer — double-click or: bash Orbit.run
set -euo pipefail
printf '\033[38;2;196;165;116m\n      ◯  ORBIT\033[0m\n'
TMP="$(mktemp -d /tmp/orbit-unpack.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
sed -n '/^__ORBIT_PAYLOAD__$/,$p' "$0" | tail -n +2 | tar -xz -C "$TMP"
bash "$TMP/setup.sh"
exit $?
__ORBIT_PAYLOAD__
STUB
RUN="$DIST/Orbit-${VERSION}.run"
cat "$STUB" "$PAYLOAD" > "$RUN"
chmod +x "$RUN"

# --- .deb (optional system package) ---
DEBROOT="$DEB/orbit"
mkdir -p "$DEBROOT/DEBIAN" \
  "$DEBROOT/opt/orbit/assets" \
  "$DEBROOT/usr/bin" \
  "$DEBROOT/usr/share/applications" \
  "$DEBROOT/usr/share/icons/hicolor/256x256/apps" \
  "$DEBROOT/usr/share/doc/orbit"
cp "$ROOT/orbit.py" "$DEBROOT/opt/orbit/orbit.py"
cp "$ROOT/assets/orbit-256.png" "$DEBROOT/opt/orbit/assets/orbit-256.png"
cp "$ROOT/assets/orbit-256.png" "$DEBROOT/usr/share/icons/hicolor/256x256/apps/orbit.png"
cp "$ROOT/LICENSE" "$DEBROOT/usr/share/doc/orbit/copyright"
cat > "$DEBROOT/usr/bin/orbit" <<'BIN'
#!/usr/bin/env bash
export ORBIT_HOME="${ORBIT_HOME:-$HOME/.orbit}"
mkdir -p "$ORBIT_HOME"
if [[ ! -f "$ORBIT_HOME/orbit.py" ]]; then
  cp /opt/orbit/orbit.py "$ORBIT_HOME/orbit.py"
  cp /opt/orbit/assets/orbit-256.png "$ORBIT_HOME/orbit.png" 2>/dev/null || true
  python3 "$ORBIT_HOME/orbit.py" setup
fi
if [[ $# -eq 0 ]]; then
  exec python3 "$ORBIT_HOME/orbit.py" gui
fi
exec python3 "$ORBIT_HOME/orbit.py" "$@"
BIN
chmod +x "$DEBROOT/usr/bin/orbit" "$DEBROOT/opt/orbit/orbit.py"
cat > "$DEBROOT/usr/share/applications/orbit.desktop" <<DESK
[Desktop Entry]
Type=Application
Name=Orbit
GenericName=VPN Rotator
Comment=ProtonVPN rotator — Levant, Eurasia, Stateside
Exec=/usr/bin/orbit
Icon=orbit
Terminal=false
StartupNotify=true
Categories=Network;Security;
Keywords=vpn;proton;wireguard;orbit;
DESK
cat > "$DEBROOT/DEBIAN/control" <<CTRL
Package: orbit
Version: ${VERSION}
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.10), python3-tk
Maintainer: Orbit <orbit@local>
Description: ProtonVPN rotator with clock, hotkeys, and a desktop GUI
 Orbit hops ProtonVPN cities on a timer or from the Orbit window.
CTRL
( cd "$DEB" && dpkg-deb --build orbit "orbit_${VERSION}_all.deb" >/dev/null )
mv "$DEB/orbit_${VERSION}_all.deb" "$DIST/orbit_${VERSION}_all.deb"

rm -rf "$STAGE" "$STUB" "$PAYLOAD" "$DEB"
ls -lh "$DIST"
echo "built $RUN"
echo "built $DIST/orbit_${VERSION}_all.deb"
