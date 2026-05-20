# Munin — Network Reconnaissance & Threat Analysis Framework
# install.ps1 — Windows Setup Script
# Run as Administrator: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
# Then: .\install.ps1

$ErrorActionPreference = "Stop"

function Write-Step  { param($msg) Write-Host "`n  [>] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "  [!]  $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "  [X]  $msg" -ForegroundColor Red; exit 1 }

Clear-Host
Write-Host ""
Write-Host "  ███╗   ███╗██╗   ██╗███╗   ██╗██╗███╗   ██╗" -ForegroundColor Cyan
Write-Host "  ████╗ ████║██║   ██║████╗  ██║██║████╗  ██║" -ForegroundColor Cyan
Write-Host "  ██╔████╔██║██║   ██║██╔██╗ ██║██║██╔██╗ ██║" -ForegroundColor Cyan
Write-Host "  ██║╚██╔╝██║██║   ██║██║╚██╗██║██║██║╚██╗██║" -ForegroundColor Cyan
Write-Host "  ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║██║ ╚████║" -ForegroundColor Cyan
Write-Host "  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Munin v2 — Windows Installer" -ForegroundColor White
Write-Host ""

# ── Admin check ──────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warn "Not running as Administrator. Some features may fail."
    Write-Warn "Re-run: Start-Process powershell -Verb RunAs -ArgumentList '.\install.ps1'"
}

# ── Python check ─────────────────────────────────────────────────────────────
Write-Step "Checking Python 3.10+"
try {
    $pyVer = python --version 2>&1
    Write-Ok "$pyVer"
} catch {
    Write-Err "Python not found. Install from https://python.org and re-run."
}

# ── pip install ───────────────────────────────────────────────────────────────
Write-Step "Installing Python packages"
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt --quiet
Write-Ok "Python packages installed"

# ── nmap check ────────────────────────────────────────────────────────────────
Write-Step "Checking nmap"
$nmapPath = Get-Command nmap -ErrorAction SilentlyContinue
if ($null -eq $nmapPath) {
    Write-Warn "nmap not found."
    Write-Warn "Download from: https://nmap.org/download.html"
    Write-Warn "Install Npcap when prompted (required for raw socket scans)."
} else {
    $nmapVer = nmap --version 2>&1 | Select-Object -First 1
    Write-Ok $nmapVer
}

# ── .env file ─────────────────────────────────────────────────────────────────
Write-Step "Creating .env"
if (-not (Test-Path ".env")) {
    $secret = -join ((1..32) | ForEach-Object { "{0:x2}" -f (Get-Random -Max 256) })
    @"
# Munin Environment Configuration
MUNIN_SECRET_KEY=$secret
MUNIN_DASHBOARD_USER=admin
MUNIN_DASHBOARD_PASS=changeme
MUNIN_DASHBOARD_PORT=5000
MUNIN_SESSION_TIMEOUT=3600
MUNIN_IP_ALLOWLIST=
OLLAMA_HOST=http://localhost:11434
ENABLE_NLP=true
"@ | Set-Content ".env" -Encoding UTF8
    Write-Ok ".env created — edit MUNIN_DASHBOARD_PASS before use!"
} else {
    Write-Warn ".env already exists — skipping"
}

# ── Data directories ──────────────────────────────────────────────────────────
Write-Step "Creating data directories"
@("data\history", "reports", "baselines", "scans") | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}
Write-Ok "Directories created"

# ── Ollama (optional) ─────────────────────────────────────────────────────────
Write-Step "Ollama (optional — AI-powered GRC reports)"
$ollamaPath = Get-Command ollama -ErrorAction SilentlyContinue
if ($null -eq $ollamaPath) {
    Write-Host ""
    Write-Warn "Ollama not installed. For AI reports:"
    Write-Warn "  1. Download: https://ollama.com/download/windows"
    Write-Warn "  2. Run:      ollama pull mistral"
    Write-Warn "  3. Start:    ollama serve"
} else {
    Write-Ok "Ollama found at $($ollamaPath.Source)"
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  Munin is ready!" -ForegroundColor Green
Write-Host ""
Write-Host "  Start CLI:        python main.py" -ForegroundColor White
Write-Host "  Start dashboard:  python dashboard.py" -ForegroundColor White
Write-Host "  Edit credentials: notepad .env" -ForegroundColor White
Write-Host "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host ""
