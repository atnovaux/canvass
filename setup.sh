#!/usr/bin/env bash
# canvass setup — one-command install on Kali/Ubuntu/Debian/macOS
# Run from the canvass repo root: ./setup.sh

set -eu  # exit on error, exit on undefined variable

# ---------- colors ----------
if [ -t 1 ]; then
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;34m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    RED="" ; GREEN="" ; YELLOW="" ; BLUE="" ; BOLD="" ; RESET=""
fi

ok()    { printf '%s[✓]%s %s\n' "$GREEN" "$RESET" "$1"; }
info()  { printf '%s[·]%s %s\n' "$BLUE" "$RESET" "$1"; }
warn()  { printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$1"; }
err()   { printf '%s[✗]%s %s\n' "$RED" "$RESET" "$1" >&2; }
step()  { printf '\n%s== %s ==%s\n' "$BOLD" "$1" "$RESET"; }

# ---------- config ----------
MIN_PY_MAJOR=3
MIN_PY_MINOR=10
AADOUTSIDER_DIR="${AADOUTSIDER_DIR:-$HOME/tools/AADOutsider-py}"
VENV_DIR="${VENV_DIR:-.venv}"

# ---------- helpers ----------
has() { command -v "$1" > /dev/null 2>&1; }

OS="unknown"
case "$(uname -s)" in
    Linux*)  OS="linux" ;;
    Darwin*) OS="mac" ;;
    *) OS="unknown" ;;
esac

install_hint() {
    # $1 = package name (as users usually know it)
    case "$OS" in
        linux) echo "  sudo apt install $1    # or: sudo dnf install $1" ;;
        mac)   echo "  brew install $1" ;;
        *)     echo "  install '$1' using your system package manager" ;;
    esac
}

# ---------- 1. banner ----------
cat <<'EOF'

  ___  __ _ _ ____   ____ _ ___ ___
 / __|/ _` | '_ \ \ / / _` / __/ __|
| (__| (_| | | | \ V / (_| \__ \__ \
 \___|\__,_|_| |_|\_/ \__,_|___/___/
   canvass setup — one-command install

EOF

# ---------- 2. verify Python ----------
step "Checking Python"

PY_CMD=""
for candidate in python3.12 python3.11 python3.10 python3; do
    if has "$candidate"; then
        ver=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
        major="${ver%%.*}"
        minor="${ver##*.}"
        if [ "$major" -ge "$MIN_PY_MAJOR" ] && [ "$minor" -ge "$MIN_PY_MINOR" ]; then
            PY_CMD="$candidate"
            ok "Found Python $ver at $(command -v "$candidate")"
            break
        fi
    fi
done

if [ -z "$PY_CMD" ]; then
    err "Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ not found. Install it first:"
    install_hint "python3" >&2
    exit 1
fi

# ---------- 3. verify git ----------
step "Checking git"
if has git; then
    ok "git present ($(git --version))"
else
    err "git not installed. Install it first:"
    install_hint "git" >&2
    exit 1
fi

# ---------- 4. verify pipx ----------
step "Checking pipx"
if has pipx; then
    ok "pipx present"
else
    warn "pipx not installed — needed for BBOT"
    printf "  Install it now? [Y/n] "
    read -r answer
    answer="${answer:-Y}"
    if [ "$answer" = "Y" ] || [ "$answer" = "y" ]; then
        case "$OS" in
            linux)
                if has apt; then
                    sudo apt update && sudo apt install -y pipx
                elif has dnf; then
                    sudo dnf install -y pipx
                else
                    err "No apt or dnf found. Install pipx manually: https://pipx.pypa.io"
                    exit 1
                fi
                pipx ensurepath
                ok "pipx installed. You may need to reopen your shell for PATH to update."
                ;;
            mac)
                if has brew; then
                    brew install pipx && pipx ensurepath
                else
                    err "Homebrew not installed. Install pipx manually: https://pipx.pypa.io"
                    exit 1
                fi
                ;;
            *)
                err "Unsupported OS — install pipx manually: https://pipx.pypa.io"
                exit 1
                ;;
        esac
    else
        err "pipx required for BBOT. Aborting."
        exit 1
    fi
fi

# ---------- 5. create venv ----------
step "Setting up Python virtualenv"
if [ -d "$VENV_DIR" ]; then
    info "Existing venv at $VENV_DIR — reusing"
else
    info "Creating venv at $VENV_DIR"
    "$PY_CMD" -m venv "$VENV_DIR"
    ok "venv created"
fi

# shellcheck disable=SC1091
. "$VENV_DIR/bin/activate"
ok "venv activated: $VIRTUAL_ENV"

# ---------- 6. install Python deps ----------
step "Installing canvass Python dependencies"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
ok "jinja2, dnspython installed"

# ---------- 7. install BBOT via pipx ----------
step "Installing BBOT (subdomain enumeration + takeover detection)"
# Ensure ~/.local/bin (where pipx puts shims) is on PATH for this script session
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) export PATH="$HOME/.local/bin:$PATH" ;;
esac

if pipx list --short 2>/dev/null | awk '{print $1}' | grep -qx 'bbot'; then
    ok "BBOT already installed via pipx"
    info "  (upgrade with: pipx upgrade bbot)"
else
    info "Installing BBOT — this takes 1-2 minutes"
    pipx install bbot
    ok "BBOT installed"
fi

# Smoke test BBOT
if has bbot; then
    bbot_ver=$(bbot --version 2>&1 | head -1 || echo "unknown")
    ok "BBOT CLI ready ($bbot_ver)"
else
    warn "BBOT installed but not on PATH. Run: pipx ensurepath"
    warn "Then reopen your terminal."
fi

# ---------- 8. clone + install AADOutsider-py ----------
step "Installing AADOutsider-py (M365 tenant intelligence)"
if [ -d "$AADOUTSIDER_DIR" ]; then
    ok "AADOutsider-py already at $AADOUTSIDER_DIR"
    info "  (update with: cd $AADOUTSIDER_DIR && git pull)"
else
    info "Cloning AADOutsider-py to $AADOUTSIDER_DIR"
    mkdir -p "$(dirname "$AADOUTSIDER_DIR")"
    git clone --quiet https://github.com/synacktiv/AADOutsider-py.git "$AADOUTSIDER_DIR"
    ok "AADOutsider-py cloned"
fi

if [ -f "$AADOUTSIDER_DIR/requirements.txt" ]; then
    info "Installing AADOutsider-py Python dependencies"
    pip install --quiet -r "$AADOUTSIDER_DIR/requirements.txt"
    ok "AADOutsider-py deps installed"
fi

# ---------- 9. smoke test canvass itself ----------
step "Testing canvass"
if python3 brief.py --help > /dev/null 2>&1; then
    ok "canvass imports OK, CLI responds"
else
    err "canvass failed to run. Try: python3 brief.py --help"
    exit 1
fi

# ---------- 10. final summary ----------
cat <<EOF

${GREEN}${BOLD}✓ Setup complete${RESET}

${BOLD}Installed:${RESET}
  • canvass Python deps       → ${VENV_DIR}/
  • BBOT (subdomain enum)      → $(pipx environment --value PIPX_LOCAL_VENVS 2>/dev/null || echo "~/.local/share/pipx/venvs")/bbot
  • AADOutsider-py             → $AADOUTSIDER_DIR

${BOLD}Next steps:${RESET}

  1. Activate the venv in new shells:
       ${YELLOW}source $VENV_DIR/bin/activate${RESET}

  2. Run your first scan:
       ${YELLOW}python3 brief.py <domain>${RESET}            # full scan (~2-5 min)
       ${YELLOW}python3 brief.py <domain> --skip-bbot${RESET}   # quick (~10s, skips subdomain enum)

  3. (Optional) Add BBOT API keys for 20-50% more subdomains:
       Edit ~/.config/bbot/bbot.yml  — see README for details.

${BOLD}Output files${RESET} go to: ~/engagements/<domain>/recon/

EOF
