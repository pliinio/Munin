#!/usr/bin/env bash
# Munin — setup.sh
# Installs all dependencies and prepares the environment.
# Usage: sudo bash setup.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "  ███╗   ███╗██╗   ██╗███╗   ██╗██╗███╗   ██╗"
  echo "  ████╗ ████║██║   ██║████╗  ██║██║████╗  ██║"
  echo "  ██╔████╔██║██║   ██║██╔██╗ ██║██║██╔██╗ ██║"
  echo "  ██║╚██╔╝██║██║   ██║██║╚██╗██║██║██║╚██╗██║"
  echo "  ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║██║ ╚████║"
  echo "  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝"
  echo -e "${NC}"
  echo -e "  ${CYAN}Munin v2.x — Setup Script${NC}"
  echo ""
}

log()  { echo -e "  ${GREEN}✔${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
err()  { echo -e "  ${RED}✗${NC}  $*"; exit 1; }
step() { echo -e "\n  ${CYAN}▶${NC}  ${CYAN}$*${NC}"; }

banner

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "This script must be run as root.  Run: sudo bash setup.sh"
fi

# ── Python check ──────────────────────────────────────────────────────────────
step "Checking Python 3.10+"
PYTHON=$(command -v python3 || true)
if [[ -z "$PYTHON" ]]; then
  err "Python 3 not found. Install it first: sudo apt install python3"
fi
PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
log "Python $PY_VERSION found at $PYTHON"

# ── nmap check ────────────────────────────────────────────────────────────────
step "Checking nmap"
if ! command -v nmap &>/dev/null; then
  warn "nmap not found — installing..."
  apt-get install -y nmap >/dev/null 2>&1 || err "Failed to install nmap"
fi
log "nmap $(nmap --version | head -1)"

# ── pip packages ──────────────────────────────────────────────────────────────
step "Installing Python packages"
"$PYTHON" -m pip install --upgrade pip --quiet
"$PYTHON" -m pip install -r requirements.txt --quiet
log "Python packages installed"

# ── WeasyPrint system deps (PDF) ──────────────────────────────────────────────
step "Installing WeasyPrint system dependencies (PDF support)"
apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf2.0-0 \
  libffi-dev shared-mime-info >/dev/null 2>&1 || warn "Some PDF deps may be missing"
log "PDF dependencies installed"

# ── Environment file ──────────────────────────────────────────────────────────
step "Creating .env file"
if [[ ! -f .env ]]; then
  SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  cat > .env <<EOF
# Munin Environment Configuration
MUNIN_SECRET_KEY=${SECRET}
MUNIN_DASHBOARD_USER=admin
MUNIN_DASHBOARD_PASS=changeme
MUNIN_DASHBOARD_PORT=5000
MUNIN_SESSION_TIMEOUT=3600
MUNIN_IP_ALLOWLIST=
OLLAMA_HOST=http://localhost:11434
ENABLE_NLP=true
EOF
  log ".env created (edit MUNIN_DASHBOARD_PASS before use!)"
else
  warn ".env already exists — skipping"
fi

# ── Data directories ──────────────────────────────────────────────────────────
step "Creating data directories"
mkdir -p data/history reports baselines scans
log "Directories: data/history, reports, baselines, scans"

# ── Ollama (optional) ─────────────────────────────────────────────────────────
step "Ollama (optional — for AI-powered business reports)"
if command -v ollama &>/dev/null; then
  log "Ollama already installed"
else
  echo ""
  echo -e "  ${YELLOW}Ollama is not installed. To enable AI-powered GRC reports:${NC}"
  echo -e "  ${CYAN}  curl -fsSL https://ollama.com/install.sh | sh${NC}"
  echo -e "  ${CYAN}  ollama pull mistral${NC}"
  echo -e "  ${CYAN}  ollama serve${NC}"
fi

echo ""
echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}  Munin is ready!${NC}"
echo ""
echo -e "  Start CLI:        sudo python3 main.py"
echo -e "  Start dashboard:  python3 dashboard.py"
echo -e "  Edit credentials: nano .env"
echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
