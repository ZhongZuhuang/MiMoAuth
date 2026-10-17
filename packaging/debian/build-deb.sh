#!/usr/bin/env bash
# Build a Debian package from the release binaries.
#   ./packaging/debian/build-deb.sh
# Output: dist/mimoauth_<version>_<arch>.deb
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(grep -m1 '^version' "$ROOT/Cargo.toml" | sed 's/.*"\(.*\)"/\1/')"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
PKG="mimoauth_${VERSION}_${ARCH}"
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

echo "[deb] building release binaries"
cargo build --release --workspace --manifest-path "$ROOT/Cargo.toml"

echo "[deb] staging $PKG"
mkdir -p "$STAGING/DEBIAN" \
         "$STAGING/usr/bin" \
         "$STAGING/usr/lib/systemd/user" \
         "$STAGING/etc/pam.d" \
         "$STAGING/usr/share/mimoauth/skills/mimoauth" \
         "$STAGING/usr/share/doc/mimoauth" \
         "$STAGING/usr/share/licenses/mimoauth"

cat > "$STAGING/DEBIAN/control" <<EOF
Package: mimoauth
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Depends: libgtk-4-1 (>= 4.10), libadwaita-1-0 (>= 1.4), libpam0g, dbus-user-session
Recommends: fprintd
Maintainer: MiMo Assistant <mimo@users.noreply.github.com>
Homepage: https://github.com/ZhongZuhuang/MiMoAuth
Description: polkit-style authorization framework for AI desktops
 Session daemon with GTK4 authentication agent (password + fingerprint),
 CLI toolchain (mimoauthctl) for AI agents, and optional sudo integration
 via PAM (pam_exec). Independent of polkit — works without it.
EOF

install -m 0755 "$ROOT/target/release/mimoauthd"    "$STAGING/usr/bin/mimoauthd"
install -m 0755 "$ROOT/target/release/mimoauthctl"  "$STAGING/usr/bin/mimoauthctl"
install -m 0755 "$ROOT/target/release/mimoauth-gui" "$STAGING/usr/bin/mimoauth-gui"
install -m 0755 "$ROOT/target/release/mimoauth-tui" "$STAGING/usr/bin/mimoauth-tui"
install -m 0644 "$ROOT/data/systemd/mimoauthd.service" "$STAGING/usr/lib/systemd/user/mimoauthd.service"
install -m 0644 "$ROOT/data/pam.d/mimoauth" "$STAGING/etc/pam.d/mimoauth"
install -m 0644 "$ROOT/data/pam.d/sudo-mimoauth" "$STAGING/usr/share/doc/mimoauth/sudo-mimoauth.howto"
install -m 0644 "$ROOT/skills/mimoauth/SKILL.md" "$STAGING/usr/share/mimoauth/skills/mimoauth/SKILL.md"
install -m 0644 "$ROOT/LICENSE" "$STAGING/usr/share/licenses/mimoauth/LICENSE"
install -m 0644 "$ROOT/README.md" "$STAGING/usr/share/doc/mimoauth/README.md"

# postinst: enable+start the user service for the invoking user (best-effort)
cat > "$STAGING/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ -n "${SUDO_USER:-}" ]; then
    sudo -u "$SUDO_USER" systemctl --user daemon-reload 2>/dev/null || true
    sudo -u "$SUDO_USER" systemctl --user enable --now mimoauthd.service 2>/dev/null || true
fi
# sudo integration is opt-in; see /usr/share/doc/mimoauth/sudo-mimoauth.howto
exit 0
EOF
chmod 0755 "$STAGING/DEBIAN/postinst"

mkdir -p "$ROOT/dist"
if command -v fakeroot >/dev/null 2>&1; then
    fakeroot dpkg-deb --build "$STAGING" "$ROOT/dist/$PKG.deb"
else
    dpkg-deb --build --root-owner-group "$STAGING" "$ROOT/dist/$PKG.deb"
fi
echo "[deb] done: $ROOT/dist/$PKG.deb"
dpkg-deb --info "$ROOT/dist/$PKG.deb" | head -12
