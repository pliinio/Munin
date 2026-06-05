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
  echo -e "  ${CYAN}Munin v2.1.0 — Setup Script${NC}"
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

# ── Virtual environment ───────────────────────────────────────────────────────
# Sistemas modernos (Debian 12+, Ubuntu 23+, Mint 22+) bloqueiam pip global.
# Criamos um venv isolado em .venv/ dentro do próprio projeto.

step "Setting up Python virtual environment"

# Garantir que python3-venv esteja instalado
if ! "$PYTHON" -m venv --help &>/dev/null 2>&1; then
  warn "python3-venv not found — installing..."
  apt-get install -y python3-venv python3-full >/dev/null 2>&1 \
    || err "Failed to install python3-venv"
fi

VENV_DIR="$(pwd)/.venv"

if [[ ! -d "$VENV_DIR" ]]; then
  "$PYTHON" -m venv "$VENV_DIR"
  log "Virtual environment created at .venv/"
else
  warn "Virtual environment already exists at .venv/ — reusing"
fi

# Usar o pip e python do venv a partir daqui
VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

# ── pip packages ──────────────────────────────────────────────────────────────
step "Installing Python packages into .venv"
"$VENV_PIP" install --upgrade pip --quiet
"$VENV_PIP" install -r requirements.txt --quiet
log "Python packages installed"

# ── WeasyPrint system deps (PDF) ──────────────────────────────────────────────
step "Installing WeasyPrint system dependencies (PDF support)"
apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf2.0-0 \
  libffi-dev shared-mime-info python3-venv python3-full >/dev/null 2>&1 \
  || warn "Some PDF deps may be missing"
log "PDF dependencies installed"

# ── Environment file ──────────────────────────────────────────────────────────
step "Creating .env file"
if [[ ! -f .env ]]; then
  # Usa o python do venv para gerar a chave secreta
  SECRET=$("$VENV_PYTHON" -c "import secrets; print(secrets.token_hex(32))")
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
  log ".env created  (edite MUNIN_DASHBOARD_PASS antes de usar!)"
else
  warn ".env already exists — skipping"
fi

# ── .env.example ─────────────────────────────────────────────────────────────
# Garante que .env.example existe (pode ter ficado de fora do ZIP)
if [[ ! -f .env.example ]]; then
  cp .env .env.example 2>/dev/null || true
fi

# ── Data directories ──────────────────────────────────────────────────────────
step "Creating data directories"
mkdir -p data/history reports baselines scans
log "Directories: data/history, reports, baselines, scans"

# ── Wrapper scripts ───────────────────────────────────────────────────────────
# Cria atalhos que ativam o venv automaticamente, para não precisar
# lembrar de "source .venv/bin/activate" toda vez.

step "Creating launcher scripts"

cat > run_cli.sh << 'RUNEOF'
#!/usr/bin/env bash
# Munin CLI — ativa o venv automaticamente
cd "$(dirname "$0")"
exec .venv/bin/python main.py "$@"
RUNEOF
chmod +x run_cli.sh

cat > run_dashboard.sh << 'RUNEOF'
#!/usr/bin/env bash
# Munin Dashboard — ativa o venv automaticamente
cd "$(dirname "$0")"
exec .venv/bin/python dashboard.py "$@"
RUNEOF
chmod +x run_dashboard.sh

log "run_cli.sh e run_dashboard.sh criados"

# ── Ollama (optional) ─────────────────────────────────────────────────────────
step "Ollama (opcional — para relatórios GRC com IA)"
if command -v ollama &>/dev/null; then
  log "Ollama already installed"
else
  echo ""
  echo -e "  ${YELLOW}Ollama não instalado. Para ativar relatórios com IA:${NC}"
  echo -e "  ${CYAN}  curl -fsSL https://ollama.com/install.sh | sh${NC}"
  echo -e "  ${CYAN}  ollama pull mistral${NC}"
  echo -e "  ${CYAN}  ollama serve${NC}"
fi

echo ""
echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}  Munin está pronto!${NC}"
echo ""
echo -e "  Iniciar CLI:        sudo bash run_cli.sh"
echo -e "  Iniciar dashboard:  bash run_dashboard.sh"
echo -e "  Editar credenciais: nano .env"
echo ""
echo -e "  ${YELLOW}Nota: use SEMPRE os scripts run_*.sh (eles ativam o venv)${NC}"
echo -e "  ${YELLOW}OU ative manualmente: source .venv/bin/activate${NC}"
echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
