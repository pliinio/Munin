<div align="center">
  <img src="assets/Logo.png" alt="Munin Logo" width="280" />

  <h1>Munin</h1>

  <p><strong>Cyber Risk Intelligence Platform</strong></p>

  <p>
    <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+"/>
    <img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square" alt="License: AGPL-3.0"/>
    <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform"/>
    <img src="https://img.shields.io/badge/requires-root%20%2F%20sudo-critical?style=flat-square" alt="Requires root"/>
    <img src="https://img.shields.io/badge/version-2.0.3-brightgreen?style=flat-square" alt="Version"/>
  </p>

  <p><em>"O diferencial do Munin não é detectar vulnerabilidades.<br>É explicar, priorizar e contextualizar riscos de forma compreensível para humanos."</em></p>
</div>

---

> [!WARNING]
> **Aviso Legal** — Utilize o Munin **exclusivamente** em redes que você possui ou para as quais possui **permissão expressa e por escrito** para realizar auditorias de segurança. O uso não autorizado em redes de terceiros é ilegal na maioria das jurisdições e pode resultar em acusações criminais. Os autores e colaboradores do projeto não assumem qualquer responsabilidade por uso indevido desta ferramenta.

---

## O que é o Munin

Munin é uma plataforma de reconhecimento de rede e análise de risco cibernético. Diferente de scanners tradicionais que apenas listam vulnerabilidades técnicas, o Munin vai além: ele traduz automaticamente os achados para linguagem de negócio, mapeia violações de compliance e prioriza o que deve ser corrigido primeiro.

| Camada | O que entrega |
|--------|---------------|
| **Scan** | Descoberta ARP, fingerprinting de OS, port scan com 4 perfis, NSE vuln scripts, lookup NVD/CVEs |
| **Correlação** | Detecção de padrões (SSH brute-force, DB exposta, Docker API aberta…) + anomalias ML |
| **Risk Engine** | Score 0–100 ajustado pela criticidade do ativo (servidor AD ≠ workstation de lab) |
| **Compliance** | Mapeamento automático para NIST CSF 2.0, ISO 27001:2022, CIS Controls v8, LGPD/GDPR |
| **Remediação** | Priorização Immediate / High / Medium / Planned com ações concretas |
| **Relatórios NLP** | Relatórios em linguagem de negócio via Ollama (manager / auditor / board) |
| **Dashboard** | Flask com autenticação, audience switcher, trend charts, download de PDF |
| **SIEM** | Push de eventos para Elastic, Splunk, Graylog, syslog, webhook genérico |

---

## Requisitos

### Sistema operacional

- Linux (Debian, Ubuntu, Kali, Mint, Arch)
- macOS 12+

> O Munin **não** suporta execução nativa no Windows. Use WSL2 ou Docker.

### Dependências obrigatórias

| Dependência | Versão mínima | Função |
|-------------|--------------|--------|
| Python | 3.10+ | Linguagem principal |
| nmap | 7.x+ | Port scan e NSE scripts |
| root / sudo | — | ARP scan, SYN scan (`-sS`), OS fingerprinting (`-O`) |

### Dependências opcionais

| Dependência | Função |
|-------------|--------|
| Ollama + modelo (ex: Mistral) | Relatórios GRC com IA em linguagem natural |
| WeasyPrint (instalado automaticamente) | Geração de relatórios PDF |
| Docker + Docker Compose | Deploy em container |

---

## Instalação

### Linux / macOS (recomendado)

**1. Clone o repositório**
```bash
git clone https://github.com/pliinio/munin.git
cd munin
```

**2. Execute o instalador**
```bash
sudo bash setup.sh
```

O `setup.sh` faz automaticamente:
- Verifica Python 3.10+ e nmap
- Instala `python3-venv` se necessário
- Cria um ambiente virtual isolado em `.venv/`
- Instala todas as dependências Python dentro do venv
- Instala dependências de sistema do WeasyPrint (PDF)
- Gera o arquivo `.env` com uma chave secreta aleatória
- Cria os scripts `run_cli.sh` e `run_dashboard.sh`
- Cria os diretórios `data/history/`, `reports/`, `scans/`, `baselines/`

> **Por que venv?** Sistemas modernos (Debian 12+, Ubuntu 23+, Mint 22+) bloqueiam `pip install` global via PEP 668. O setup cria um ambiente virtual isolado para evitar esse problema.

**3. Configure suas credenciais**
```bash
nano .env
```

Altere obrigatoriamente:
```env
MUNIN_DASHBOARD_PASS=suasenhaforte   # troque isso antes de usar
```

---

### Windows (PowerShell como Administrador)

```powershell
.\install.ps1
```

> Requer nmap instalado separadamente: https://nmap.org/download.html (instale o Npcap quando solicitado)

---

### Docker

```bash
# 1. Copie e edite o .env
cp .env.example .env
nano .env   # altere MUNIN_DASHBOARD_PASS

# 2. Suba os containers (Munin + Ollama)
docker compose up -d

# 3. Verifique os logs
docker compose logs -f munin
```

Acesse o dashboard em `http://localhost:5000`

---

## Configuração do .env

O arquivo `.env` controla todas as configurações do Munin. Ele é gerado automaticamente pelo `setup.sh`, mas você pode ajustá-lo a qualquer momento.

```bash
cp .env.example .env
nano .env
```

### Variáveis principais

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `MUNIN_SECRET_KEY` | gerada automaticamente | Chave de sessão Flask (não altere após instalar) |
| `MUNIN_DASHBOARD_USER` | `admin` | Usuário de acesso ao dashboard |
| `MUNIN_DASHBOARD_PASS` | `changeme` | **Troque antes de usar** |
| `MUNIN_DASHBOARD_PORT` | `5000` | Porta do dashboard web |
| `MUNIN_SESSION_TIMEOUT` | `3600` | Timeout da sessão em segundos |
| `MUNIN_IP_ALLOWLIST` | vazio (todos) | IPs autorizados separados por vírgula |
| `OLLAMA_HOST` | `http://localhost:11434` | URL do servidor Ollama |
| `ENABLE_NLP` | `true` | Ativa relatórios com IA |

### Variáveis SIEM (todas opcionais)

| Variável | Conector |
|----------|---------|
| `MUNIN_SIEM_ELASTIC_URL` | Elasticsearch |
| `MUNIN_SIEM_ELASTIC_INDEX` | Elasticsearch (índice, padrão: `munin-findings`) |
| `MUNIN_SIEM_ELASTIC_API_KEY` | Elasticsearch (autenticação por API Key) |
| `MUNIN_SIEM_SPLUNK_URL` | Splunk HEC |
| `MUNIN_SIEM_SPLUNK_TOKEN` | Splunk HEC (token) |
| `MUNIN_SIEM_GRAYLOG_URL` | Graylog GELF HTTP |
| `MUNIN_SIEM_SYSLOG_HOST` | Syslog (host de destino) |
| `MUNIN_SIEM_SYSLOG_PORT` | Syslog (porta, padrão: `514`) |
| `MUNIN_SIEM_SYSLOG_PROTO` | Syslog (`udp` ou `tcp`) |
| `MUNIN_SIEM_WEBHOOK_URL` | Webhook genérico (Slack, Teams, n8n…) |

---

## Como usar — CLI

### Iniciando

```bash
# Com os scripts gerados pelo setup (recomendado — ativa o venv automaticamente)
sudo bash run_cli.sh

# Ou ativando o venv manualmente
source .venv/bin/activate
sudo python3 main.py
```

Na primeira vez, você verá o banner do Munin e o prompt interativo:
```
munin >
```

### Comandos de scan

```bash
# Scan completo de uma rede (descoberta + OS + portas + CVEs + correlação + relatório)
munin > scan net 192.168.1.0/24

# Scan de um host específico
munin > scan host 192.168.1.10

# Apenas descoberta ARP (quais IPs estão ativos)
munin > discover 192.168.1.0/24
```

### Análise de logs

```bash
# Analisa um arquivo de log e detecta ameaças
munin > readlog /var/log/auth.log

# Correlaciona log a um host já escaneado
munin > correlate 192.168.1.10 /var/log/syslog
```

### Análise pós-scan

```bash
# Postura de compliance (ISO 27001, NIST CSF, CIS, LGPD)
munin > compliance

# Plano de remediação priorizado (Immediate / High / Medium / Planned)
munin > remediation

# Classificação de criticidade dos ativos
munin > assets

# Histórico de scans e tendências
munin > history
```

### Exportações

```bash
# Relatório HTML interativo
munin > export html

# Relatório PDF executivo
munin > export pdf

# Relatório GRC em Markdown (escolhe audience: manager / auditor / board)
munin > export report

# Push para SIEM (todos configurados, ou um específico)
munin > export siem
munin > export siem elastic
munin > export siem webhook
```

### Configurações de sessão

```bash
# Perfil de scan: quick | normal | full | stealth
munin > set profile quick

# Audiência dos relatórios NLP: manager | auditor | board
munin > set audience board

# Ativar/desativar ajuste de risco por criticidade do ativo
munin > set criticality on

# Ativar/desativar push automático para SIEM após cada scan
munin > set siem on

# Ativar/desativar lookup de CVEs no NVD
munin > set cve on

# Ativar/desativar scripts NSE (nmap vuln scripts)
munin > set nse off

# Ver configurações atuais
munin > show settings
```

### Outros comandos

```bash
# Carregar um resultado JSON salvo anteriormente
munin > load scans/munin_20260518_120000.json

# Ver versão e status do Ollama
munin > version

# Ajuda
munin > help

# Sair
munin > exit
```

---

## Perfis de scan

| Perfil | Portas | Velocidade | Ruído na rede | Quando usar |
|--------|--------|------------|---------------|-------------|
| `quick` | Top 1.000 | ~1 min/host | Alto | Triagem rápida |
| `normal` | Top 10.000 + scripts | ~5 min/host | Médio | **Uso geral (padrão)** |
| `full` | Todas 65.535 | ~15 min/host | Alto | Auditoria completa |
| `stealth` | Todas 65.535 | ~30 min/host | Baixo | Ambientes sensíveis |

---

## Como usar — Dashboard Web

### Iniciando

```bash
# Com o script gerado pelo setup (recomendado)
bash run_dashboard.sh

# Com scan específico
bash run_dashboard.sh scans/munin_20260518_120000.json

# Com porta personalizada
bash run_dashboard.sh --port 8080

# Ou ativando o venv manualmente
source .venv/bin/activate
python3 dashboard.py
```

Acesse em `http://127.0.0.1:5000` e faça login com as credenciais do `.env`.

### Funcionalidades

- **Autenticação** com sessão segura, timeout configurável e allowlist de IPs
- **Cards de compliance** ISO 27001, NIST CSF, CIS Controls e LGPD por host e por ambiente
- **Audience switcher** — alterna entre manager / auditor / board sem re-executar o scan
- **Trend charts** — gráficos de evolução do risco ao longo do tempo (Chart.js)
- **Comparação entre scans** — resumo do que melhorou e piorou
- **Download PDF** — relatório executivo com um clique
- **Tabs por host** — GRC Report / Threats / Ports / Compliance com mapeamento MITRE e ISO

### API JSON

| Endpoint | Descrição |
|----------|-----------|
| `GET /api/summary` | Resumo geral do scan |
| `GET /api/hosts` | Lista de hosts com risk score |
| `GET /api/host/<ip>/compliance` | Score de compliance de um host |
| `GET /api/trends` | Dados históricos para gráficos |
| `POST /api/audience` | Altera a audiência dos relatórios |

---

## Relatórios NLP com Ollama

O Munin gera relatórios em linguagem natural usando um modelo de IA rodando localmente (sem enviar dados para a nuvem).

### Instalando o Ollama

```bash
# Instalar
curl -fsSL https://ollama.com/install.sh | sh

# Baixar um modelo (escolha um)
ollama pull mistral        # recomendado (4 GB RAM)
ollama pull phi3:mini      # mais leve (2 GB RAM)
ollama pull llama3.1       # melhor qualidade (8 GB RAM)

# Iniciar o servidor
ollama serve
```

### Usando no Munin

```bash
# Verificar se o Ollama está disponível
munin > version

# Definir audiência e gerar relatório
munin > set audience board
munin > export report
```

### Diferença entre audiências

| Audiência | Linguagem | Foco |
|-----------|-----------|------|
| `manager` | Técnica acessível | Ações práticas e prazos |
| `auditor` | Compliance | Controles violados, evidências, referências legais |
| `board` | Executiva | Impacto no negócio, risco financeiro, sem jargão |

---

## Integração SIEM

Configure as variáveis no `.env` e use os comandos de exportação:

```bash
# No .env:
MUNIN_SIEM_ELASTIC_URL=http://elastic:9200
MUNIN_SIEM_SPLUNK_URL=https://splunk:8088
MUNIN_SIEM_SPLUNK_TOKEN=seu-token
MUNIN_SIEM_WEBHOOK_URL=https://hooks.exemplo.com/munin

# No CLI do Munin:
munin > export siem           # envia para todos configurados
munin > export siem elastic   # envia só para Elastic
munin > set siem on           # auto-push após cada scan
```

Conectores disponíveis: `elastic` · `splunk` · `graylog` · `syslog` · `webhook`

---

## Estrutura do projeto

```
munin/
├── main.py                          # CLI REPL principal
├── dashboard.py                     # Flask GRC Dashboard v2
├── auth.py                          # Autenticação do dashboard
├── run_cli.sh                       # Atalho CLI (gerado pelo setup)
├── run_dashboard.sh                 # Atalho dashboard (gerado pelo setup)
├── requirements.txt
├── setup.sh                         # Instalação Linux/macOS
├── install.ps1                      # Instalação Windows
├── Dockerfile
├── docker-compose.yml
├── .env.example                     # Template de configuração
├── assets/
│   └── Logo.png
│
├── scanner/
│   ├── discovery.py                 # ARP scan (scapy) + fallback nmap
│   ├── os_detect.py                 # Fingerprinting de OS + vendor MAC
│   ├── portscan.py                  # Port scan (4 perfis)
│   ├── vulnscan.py                  # NSE scripts + NVD CVE lookup
│   ├── logreader.py                 # Parser de logs (syslog, auth, nginx…)
│   └── analysis/
│       ├── correlator.py            # Motor de correlação de ameaças
│       ├── patterns.py              # Base de padrões de ameaças
│       ├── anomaly_detector.py      # Detecção de anomalias (Isolation Forest)
│       ├── risk_engine.py           # Score 0–100 + integração NLP
│       ├── compliance_mapper.py     # Mapeamento NIST/ISO/CIS/MITRE/LGPD
│       ├── remediation_engine.py    # Priorização de remediação
│       ├── asset_criticality.py     # Classificação de ativos
│       ├── siem_connector.py        # Integração com SIEMs
│       └── nlp_translator.py        # Tradução técnica → linguagem de negócio
│
├── report/
│   ├── terminal.py                  # Output Rich no terminal
│   ├── html_report.py               # Relatório HTML interativo
│   ├── pdf_report.py                # Relatório PDF executivo (WeasyPrint)
│   └── history.py                   # Histórico e trend analysis
│
└── data/
    └── history/                     # Snapshots de scans anteriores
```

---

## Compliance mapeado

Cada finding detectado é automaticamente vinculado aos controles de segurança correspondentes:

| Framework | Versão |
|-----------|--------|
| MITRE ATT&CK | Enterprise v15 |
| NIST Cybersecurity Framework | CSF 2.0 |
| ISO/IEC 27001 Annex A | 2022 |
| CIS Controls | v8 |
| LGPD | Lei 13.709/2018 |
| GDPR | Regulation 2016/679 |

---

## Troubleshooting

### `externally-managed-environment` ao rodar o setup

Ocorre em sistemas modernos (Debian 12+, Ubuntu 23+, Mint 22+) que bloqueiam `pip` global. O `setup.sh` já resolve isso criando um venv automaticamente. Certifique-se de usar a versão mais recente do `setup.sh`.

Após o setup, use **sempre** os scripts gerados:
```bash
sudo bash run_cli.sh       # CLI
bash run_dashboard.sh      # Dashboard
```

Ou ative o venv manualmente antes de qualquer comando Python:
```bash
source .venv/bin/activate
```

### `.env.example` não encontrado

```bash
# O arquivo existe mas começa com ponto (oculto no Linux)
ls -la | grep env

# Se não estiver lá, recrie a partir do .env gerado pelo setup
cp .env .env.example
```

### Porta 5000 já em uso

```bash
bash run_dashboard.sh --port 8080
# ou
source .venv/bin/activate && python3 dashboard.py --port 8080
```

### Nmap não encontrado

```bash
sudo apt install nmap        # Debian / Ubuntu / Mint
sudo pacman -S nmap          # Arch
sudo dnf install nmap        # Fedora
```

### Dashboard não abre — erro de SECRET_KEY

```bash
# Verifique se o .env existe e tem a chave
cat .env | grep SECRET_KEY

# Se não tiver, gere uma nova
python3 -c "import secrets; print('MUNIN_SECRET_KEY=' + secrets.token_hex(32))" >> .env
```

### Ollama não conecta

```bash
# Verifique se o servidor está rodando
curl http://localhost:11434/api/tags

# Se não estiver, inicie
ollama serve &

# Verifique qual modelo está disponível
ollama list
```

### WeasyPrint falha ao gerar PDF

```bash
# Instale as dependências de sistema
sudo apt install libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf2.0-0

# Teste direto
source .venv/bin/activate
python3 -c "from weasyprint import HTML; HTML(string='<h1>ok</h1>').write_pdf('/tmp/test.pdf'); print('OK')"
```

Se não funcionar, o Munin gera automaticamente um `.html` como fallback.

---

## Licença

GNU Affero General Public License v3.0 — veja [LICENSE](LICENSE).

Uso autorizado apenas em redes que você possui ou tem permissão explícita e por escrito para auditar.
