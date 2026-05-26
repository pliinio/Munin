<div align="center">
  <img src="assets/Logo.png" alt="Munin Logo" width="320" />

  <h1>Munin</h1>

  <p><strong>Cyber Risk Intelligence Platform</strong></p>

  <p>
    <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+"/>
    <img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square" alt="License: AGPL-3.0"/>
    <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform"/>
    <img src="https://img.shields.io/badge/requires-root%20%2F%20sudo-critical?style=flat-square" alt="Requires root"/>
    <img src="https://img.shields.io/badge/version-2.0.1-brightgreen?style=flat-square" alt="Version"/>
  </p>


</div>

> [!WARNING]
> **Legal Warning** — Utilize o Munin **exclusivamente** em redes que você possui ou para as quais possui permissão expressa e por escrito para auditoria. O uso não autorizado é ilegal na maioria das jurisdições e pode resultar em acusações criminais. Os autores não assumem qualquer responsabilidade por uso indevido.

---
# Munin — Cyber Risk Intelligence Platform

> **"O diferencial do Munin não é detectar vulnerabilidades.**
> **É explicar, priorizar e contextualizar riscos de forma compreensível para humanos."**

Munin é um framework de reconhecimento de rede e análise de risco cibernético que traduz achados técnicos em linguagem de negócio, compliance e auditoria.

---

## O que o Munin faz

| Camada | O que entrega |
|--------|---------------|
| **Scan** | Descoberta ARP, fingerprinting de OS, port scan (4 perfis), NSE vuln scripts, lookup NVD/CVEs |
| **Correlation** | Detecção de padrões (SSH brute-force, DB exposta, Docker API exposta…) + anomalias ML |
| **Risk Engine** | Score 0–100 ajustado por criticidade do ativo (servidor AD ≠ workstation de lab) |
| **Compliance** | Mapeamento automático para NIST CSF 2.0, ISO 27001:2022, CIS Controls v8, LGPD/GDPR |
| **Remediation** | Priorização Immediate / High / Medium / Planned com ações concretas |
| **NLP Reports** | Relatórios em linguagem de negócio via Ollama (manager / auditor / board) |
| **Dashboard** | Flask com autenticação, audience switcher, trend charts, PDF download |
| **SIEM** | Push de eventos para Elastic, Splunk, Graylog, syslog, webhook |

---

## Instalação rápida

### Linux / macOS
```bash
git clone https://github.com/pliinio/munin.git
cd munin
sudo bash setup.sh
```

### Windows (PowerShell como Administrador)
```powershell
.\install.ps1
```

### Docker
```bash
cp .env.example .env
# Edite .env com suas credenciais
docker compose up -d
```

---

## Configuração

```bash
cp .env.example .env
nano .env          # Altere MUNIN_DASHBOARD_PASS antes de usar
```

Variáveis principais:

| Variável | Descrição |
|----------|-----------|
| `MUNIN_SECRET_KEY` | Chave de sessão Flask (gerada automaticamente) |
| `MUNIN_DASHBOARD_USER` | Usuário do dashboard (padrão: `admin`) |
| `MUNIN_DASHBOARD_PASS` | Senha do dashboard (**troque antes de usar**) |
| `OLLAMA_HOST` | URL do servidor Ollama para relatórios NLP |
| `MUNIN_SIEM_ELASTIC_URL` | URL do Elasticsearch para integração SIEM |

---

## Uso — CLI

```bash
sudo python3 main.py
```

### Comandos principais

```
scan net 192.168.1.0/24      # Scan completo da rede
scan host 192.168.1.10       # Scan de host único
discover 192.168.1.0/24      # Só descoberta ARP

readlog /var/log/auth.log    # Análise de log com correlação
correlate 192.168.1.10 /var/log/syslog   # Correlaciona log a host escaneado

compliance                   # Postura de compliance (ISO/NIST/CIS/LGPD)
remediation                  # Plano de remediação priorizado
assets                       # Classificação de criticidade dos ativos
history                      # Histórico de scans e tendências

export html                  # Relatório HTML interativo
export pdf                   # Relatório PDF executivo
export report                # Relatório GRC em Markdown (manager/auditor/board)
export siem [connector]      # Push para SIEM (elastic|splunk|graylog|syslog|webhook|auto)

set profile full             # Perfil: quick | normal | full | stealth
set audience board           # Audiência NLP: manager | auditor | board
set criticality on           # Ajuste de score por criticidade do ativo
set siem on                  # Auto-push para SIEM após cada scan
```

---

## Uso — Dashboard Web

```bash
python3 dashboard.py
# Acesse: http://127.0.0.1:5000
# Login com credenciais do .env
```

### Funcionalidades do dashboard
- **Autenticação** com sessão segura e timeout configurável
- **Postura de compliance** ISO 27001, NIST CSF, CIS Controls, LGPD — por host e ambiente
- **Audience switcher** — mesmo scan, relatório diferente para manager / auditor / board
- **Trend charts** — evolução do risco ao longo dos scans (Chart.js)
- **Comparação entre scans** — o que melhorou, o que piorou
- **PDF download** — relatório executivo com um clique
- **API JSON** — `/api/summary`, `/api/hosts`, `/api/host/<ip>/compliance`, `/api/trends`

---

## Estrutura do projeto

```
munin/
├── main.py                          # CLI REPL principal
├── dashboard.py                     # Flask GRC Dashboard v2
├── auth.py                          # Autenticação do dashboard
├── requirements.txt
├── setup.sh                         # Instalação Linux/macOS
├── install.ps1                      # Instalação Windows
├── Dockerfile
├── docker-compose.yml
├── .env.example
│
├── scanner/
│   ├── discovery.py                 # ARP scan (scapy) + fallback nmap
│   ├── os_detect.py                 # Fingerprinting de OS + vendor MAC
│   ├── portscan.py                  # Port scan (4 perfis)
│   ├── vulnscan.py                  # NSE scripts + NVD CVE lookup
│   ├── logreader.py                 # Parser de logs (syslog, auth, nginx…)
│   └── analysis/
│       ├── correlator.py            # Motor de correlação de ameaças
│       ├── patterns.py              # Base de padrões (SSH BF, DB exposta…)
│       ├── anomaly_detector.py      # Detecção de anomalias (Isolation Forest)
│       ├── risk_engine.py           # Score de risco 0–100 + NLP integration
│       ├── compliance_mapper.py     # Mapeamento NIST/ISO/CIS/MITRE/LGPD ← v2
│       ├── remediation_engine.py    # Priorização Immediate/High/Medium/Planned ← v2
│       ├── asset_criticality.py     # Classificação de ativos + ajuste de risco ← v2
│       ├── siem_connector.py        # Integração Elastic/Splunk/Graylog/syslog ← v2
│       └── nlp_translator.py        # Tradução técnica → linguagem de negócio (Ollama)
│
├── report/
│   ├── terminal.py                  # Output Rich para o terminal
│   ├── html_report.py               # Relatório HTML interativo
│   ├── pdf_report.py                # Relatório PDF executivo (WeasyPrint) ← v2
│   └── history.py                   # Histórico e trend analysis ← v2
│
└── data/
    └── history/                     # Snapshots de scans para trend analysis
```

---

## Perfis de scan

| Perfil | Portas | Velocidade | Ruído | Uso |
|--------|--------|------------|-------|-----|
| `quick` | Top 1.000 | ~1 min/host | Alto | Triagem rápida |
| `normal` | Top 10.000 + scripts | ~5 min/host | Médio | **Recomendado** |
| `full` | Todas 65.535 | ~15 min/host | Alto | Auditoria completa |
| `stealth` | Todas 65.535 | ~30 min/host | Baixo | Ambientes sensíveis |

---

## Compliance mapeado

Cada finding é automaticamente mapeado para:

| Framework | Versão |
|-----------|--------|
| MITRE ATT&CK | Enterprise v15 |
| NIST Cybersecurity Framework | CSF 2.0 |
| ISO/IEC 27001 Annex A | 2022 |
| CIS Controls | v8 |
| LGPD | Lei 13.709/2018 |
| GDPR | Regulation 2016/679 |

---

## Integração SIEM

Configure as variáveis de ambiente e use `export siem` ou `set siem on`:

```bash
# Elasticsearch
export MUNIN_SIEM_ELASTIC_URL=http://elastic:9200
export MUNIN_SIEM_ELASTIC_INDEX=munin-findings

# Splunk HEC
export MUNIN_SIEM_SPLUNK_URL=https://splunk:8088
export MUNIN_SIEM_SPLUNK_TOKEN=seu-token

# Webhook genérico (Slack, Teams, n8n…)
export MUNIN_SIEM_WEBHOOK_URL=https://hooks.exemplo.com/munin
```

---

## Relatórios NLP (requer Ollama)

```bash
# Instale o Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull mistral
ollama serve

# No CLI do Munin
set audience board
export report
```

Audiências disponíveis:
- **manager** — linguagem direta para coordenadores de TI e gestores
- **auditor** — orientado a controles ISO 27001 / LGPD
- **board** — executivo, sem jargão técnico, foco em impacto de negócio

---

## Requisitos

- Python 3.10+
- nmap 7.x+
- Root/sudo (para ARP scan, SYN scan, OS fingerprinting)
- Ollama (opcional, para relatórios NLP)
- WeasyPrint (opcional, para PDF — `pip install weasyprint`)

---

## Licença

GNU Affero General Public License v3.0 — veja [LICENSE](LICENSE).

Uso autorizado apenas em redes que você possui ou tem permissão explícita para auditar.
