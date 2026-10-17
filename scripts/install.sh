#!/usr/bin/env bash
# MiMoAuth installer.
#   as normal user: builds binaries, installs to ~/.local/bin, user service,
#   config and agent skill; PAM pieces need root (script re-enters via sudo).
#   as root (sudo bash install.sh): installs ONLY the system PAM files, then
#   exits — cargo/rustup stay untouched under the invoking user's HOME.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${HOME}/.local/bin"
SYSTEMD_DIR="${HOME}/.config/systemd/user"
SKILL_DIR="${HOME}/.claude/skills/mimoauth"
CFG_DIR="${HOME}/.config/mimoauth"

log() { printf '[install] %s\n' "$*"; }

# --- sudo integration: "auth sufficient pam_exec.so ... pam-hook" ----------
install_sudo_pam() {
    local target=/etc/pam.d/sudo
    local ctl="${BIN_DIR}/mimoauthctl"
    # When running under sudo, the user's bin lives under SUDO_USER's home.
    if [[ -n "${SUDO_USER:-}" ]]; then
        ctl="/home/${SUDO_USER}/.local/bin/mimoauthctl"
    fi
    local line="auth sufficient pam_exec.so ${ctl} pam-hook"
    if grep -q 'mimoauthctl pam-hook' "$target" 2>/dev/null; then
        log "sudo PAM already integrated"
        return 0
    fi
    local tmp
    tmp="$(mktemp)"
    awk -v line="$line" '
        !done && /^auth[ \t]+include/ { print line; done=1 }
        { print }
    ' "$target" > "$tmp"
    cp -a "$target" "$target.bak-mimoauth"
    install -m 0644 "$tmp" "$target"
    rm -f "$tmp"
    log "integrated MiMoAuth into $target (backup: $target.bak-mimoauth)"
}

install_pam_pieces() {
    if [[ ! -d /etc/pam.d ]]; then
        log "no /etc/pam.d — skipping PAM pieces"
        return 0
    fi
    install -m 0644 "$ROOT/data/pam.d/mimoauth" /etc/pam.d/mimoauth
    log "installed /etc/pam.d/mimoauth"
    if [[ -f /etc/pam.d/sudo ]]; then
        install_sudo_pam
    fi
}

# --- root mode: system PAM files only ---------------------------------------
if [[ "$(id -u)" -eq 0 ]]; then
    log "root mode: installing system PAM pieces only"
    install_pam_pieces
    log "done. Run this script as your normal user once for the user-level parts."
    exit 0
fi

# --- user mode --------------------------------------------------------------
log "building release binaries"
cargo build --release --workspace --manifest-path "$ROOT/Cargo.toml"

log "installing binaries to $BIN_DIR"
mkdir -p "$BIN_DIR"
install -m 0755 "$ROOT/target/release/mimoauthd"    "$BIN_DIR/mimoauthd"
install -m 0755 "$ROOT/target/release/mimoauthctl"  "$BIN_DIR/mimoauthctl"
install -m 0755 "$ROOT/target/release/mimoauth-gui" "$BIN_DIR/mimoauth-gui"
install -m 0755 "$ROOT/target/release/mimoauth-tui" "$BIN_DIR/mimoauth-tui"

log "installing default config (only when missing)"
mkdir -p "$CFG_DIR"
if [[ ! -f "$CFG_DIR/rules.toml" ]]; then
    cat > "$CFG_DIR/rules.toml" <<'EOF'
# MiMoAuth policy rules — later rules override earlier ones (general first, specific later).
# effect: allow | auth_admin | auth_admin_keep | deny
default = "auth_admin"

[[rule]]
action = "org.mimoauth.session.*"
effect = "allow"

# Example: package installs need auth, cached for the keep timeout.
# [[rule]]
# action = "org.example.packagekit.*"
# effect = "auth_admin_keep"
EOF
    log "wrote $CFG_DIR/rules.toml"
fi

if command -v systemctl >/dev/null 2>&1; then
    log "installing systemd user service"
    mkdir -p "$SYSTEMD_DIR"
    install -m 0644 "$ROOT/data/systemd/mimoauthd.service" "$SYSTEMD_DIR/mimoauthd.service"
    systemctl --user daemon-reload
    systemctl --user enable mimoauthd.service
    systemctl --user restart mimoauthd.service
    log "mimoauthd service enabled and (re)started"
else
    log "no systemctl — installing XDG autostart fallback"
    mkdir -p "${HOME}/.config/autostart"
    sed "s|@BIN@|${BIN_DIR}|g" "$ROOT/data/autostart/mimoauthd.desktop" \
        > "${HOME}/.config/autostart/mimoauthd.desktop"
    log "wrote ~/.config/autostart/mimoauthd.desktop"
fi

if [[ -d "$(dirname "$SKILL_DIR")" && -f "$ROOT/skills/mimoauth/SKILL.md" ]]; then
    log "installing agent skill to $SKILL_DIR"
    mkdir -p "$SKILL_DIR"
    cp "$ROOT/skills/mimoauth/SKILL.md" "$SKILL_DIR/SKILL.md"
else
    log "skill source or ~/.claude/skills dir missing — skipping skill install"
fi

# PAM pieces need root: re-enter this script through sudo (password prompt
# appears in YOUR terminal), or run them manually later.
if [[ -d /etc/pam.d ]]; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo bash "$ROOT/scripts/install.sh"
    else
        log "SKIP system PAM (needs root). Install with:"
        log "  sudo bash $ROOT/scripts/install.sh"
    fi
fi

log "done. verify with: mimoauthctl ping"
