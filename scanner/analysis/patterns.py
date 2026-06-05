#!/usr/bin/env python3

# Munin — Cyber Risk Intelligence Platform
# Copyright (C) 2026 Plinio Lima
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3.
#
# This program is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Attack and threat patterns for Munin correlation engine.
Each pattern defines conditions (evaluated by the correlator) and
human-readable metadata used by the output layer.
"""

from typing import List, Dict

# ─────────────────────────────────────────────────────────────────────────────
# Pattern registry
# Each entry:
#   id          – unique snake_case identifier
#   name        – short display name
#   description – one sentence explanation shown in "Explain Mode"
#   severity    – CRITICAL | HIGH | MEDIUM | LOW
#   risk_bonus  – points added to base risk score when matched
#   remediation – ordered list of remediation steps
# ─────────────────────────────────────────────────────────────────────────────

PATTERNS: List[Dict] = [

    # ── 1. SSH Brute Force ───────────────────────────────────────────────────
    {
        "id":          "ssh_brute_force",
        "name":        "Força Bruta SSH",
        "description": (
            "Múltiplas tentativas de login SSH malsucedidas foram detectadas em um serviço "
            "SSH exposto, indicando provável ataque de dicionário ou força bruta em andamento."
        ),
        "severity":    "HIGH",
        "risk_bonus":  30,
        "remediation": [
            "Desabilitar autenticação por senha — utilizar exclusivamente chaves SSH (PasswordAuthentication no)",
            "Alterar a porta SSH para uma porta não padrão (ex.: 2222) para reduzir ruído",
            "Instalar fail2ban com limiar baixo (ex.: 5 tentativas → bloqueio de 1 hora)",
            "Restringir o acesso SSH a faixas de IP confiáveis por meio de regras de firewall",
            "Habilitar autenticação de dois fatores (ex.: módulo PAM Google Authenticator)",
        ],
    },

    # ── 2. Vulnerable Service Exposed ────────────────────────────────────────
    {
        "id":          "vulnerable_service_exposed",
        "name":        "Serviço Vulnerável Exposto",
        "description": (
            "Uma ou mais portas abertas executam serviços com CVEs conhecidas "
            "(CVSS ≥ 7,0), o que indica que um exploit publicamente documentado pode já existir."
        ),
        "severity":    "CRITICAL",
        "risk_bonus":  35,
        "remediation": [
            "Aplicar imediatamente patch ou atualização do serviço afetado para a versão estável mais recente",
            "Caso o patch não seja viável, restringir a porta a IPs confiáveis via firewall",
            "Consultar os advisories do fornecedor quanto a mitigações ou workarounds temporários",
            "Habilitar regras de IDS/IPS direcionadas ao vetor específico da CVE",
            "Agendar novo scan após a correção para confirmar a remediação",
        ],
    },

    # ── 3. Web Error + CVE ───────────────────────────────────────────────────
    {
        "id":          "web_error_with_cve",
        "name":        "Tentativa de Exploração Web",
        "description": (
            "Taxa elevada de erros HTTP 4xx/5xx nos logs de acesso, combinada com CVE "
            "no serviço web, sugere varredura ativa ou tentativa de exploração."
        ),
        "severity":    "HIGH",
        "risk_bonus":  25,
        "remediation": [
            "Revisar os logs de acesso em busca de padrões (caminhos repetidos, user-agents de scanners)",
            "Habilitar Web Application Firewall (WAF), como ModSecurity",
            "Atualizar o servidor web e todos os frameworks/plugins instalados",
            "Bloquear os IPs ofensores no firewall",
            "Habilitar rate-limiting e limites de tamanho de requisição no servidor web",
        ],
    },

    # ── 4. Critical Port Open ────────────────────────────────────────────────
    {
        "id":          "critical_port_open",
        "name":        "Porta Crítica Exposta",
        "description": (
            "Um serviço de alto risco (RDP, SMB, Telnet, VNC etc.) está acessível na rede, "
            "constituindo alvo conhecido de movimentação lateral ou exploração."
        ),
        "severity":    "HIGH",
        "risk_bonus":  20,
        "remediation": [
            "Posicionar o serviço atrás de VPN — nunca expor RDP/SMB diretamente à internet",
            "Aplicar os patches de segurança mais recentes do SO (ex.: correções EternalBlue/BlueKeep)",
            "Habilitar Network Level Authentication (NLA) para RDP",
            "Restringir o acesso à porta por IP de origem via firewall",
            "Desabilitar o serviço integralmente caso não seja necessário",
        ],
    },

    # ── 5. Large Attack Surface ──────────────────────────────────────────────
    {
        "id":          "large_attack_surface",
        "name":        "Superfície de Ataque Ampla",
        "description": (
            "Número incomumente elevado de portas abertas aumenta a probabilidade "
            "de que ao menos um serviço esteja mal configurado ou desatualizado."
        ),
        "severity":    "MEDIUM",
        "risk_bonus":  15,
        "remediation": [
            "Auditar cada porta aberta e desabilitar ou proteger via firewall serviços não essenciais",
            "Aplicar o princípio do menor privilégio — expor apenas o estritamente necessário",
            "Executar baseline mensal de varredura de portas para detectar novos listeners",
            "Segmentar o host em VLAN isolada caso precise executar múltiplos serviços",
        ],
    },

    # ── 6. NSE Confirmed Vulnerability ───────────────────────────────────────
    {
        "id":          "nse_confirmed_vuln",
        "name":        "Vulnerabilidade Confirmada por NSE",
        "description": (
            "Scripts NSE do Nmap retornaram resultado VULNERABLE, confirmando por verificação "
            "ativa que o host é suscetível a um exploit conhecido."
        ),
        "severity":    "CRITICAL",
        "risk_bonus":  40,
        "remediation": [
            "Tratar como emergência — aplicar patch ou isolar o host imediatamente",
            "Verificar a saída do script NSE para identificar a CVE e consultar o advisory do fornecedor",
            "Realizar snapshot forense do sistema antes de qualquer alteração",
            "Rotacionar todas as credenciais armazenadas ou acessíveis a partir deste host",
            "Conduzir revisão completa de resposta a incidentes para sinais de comprometimento",
        ],
    },

    # ── 7. Cleartext protocols ───────────────────────────────────────────────
    {
        "id":          "cleartext_protocol",
        "name":        "Protocolo em Texto Claro",
        "description": (
            "Telnet ou FTP está aberto, transmitindo credenciais e dados em texto claro, "
            "suscetíveis à interceptação por qualquer host no mesmo segmento de rede."
        ),
        "severity":    "MEDIUM",
        "risk_bonus":  15,
        "remediation": [
            "Substituir Telnet por SSH e FTP por SFTP ou FTPS imediatamente",
            "Caso o serviço não possa ser substituído, isolá-lo em VLAN dedicada",
            "Auditar usuários com credenciais nesses serviços e forçar redefinição de senha",
            "Desabilitar o serviço no SO (systemctl disable telnet/ftp)",
        ],
    },

    # ── 8. Database Port Exposed ─────────────────────────────────────────────
    {
        "id":          "database_exposed",
        "name":        "Porta de Banco de Dados Exposta",
        "description": (
            "Serviço de banco de dados (MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle) "
            "está acessível sem firewall, com risco de exfiltração direta de dados."
        ),
        "severity":    "HIGH",
        "risk_bonus":  25,
        "remediation": [
            "Vincular o banco de dados a 127.0.0.1 (somente localhost) na configuração",
            "Se o acesso remoto for necessário, restringir por IP e exigir TLS",
            "Auditar usuários do banco — remover acesso anônimo e credenciais padrão",
            "Habilitar auditoria em nível de banco de dados",
            "Posicionar o banco em VLAN privada atrás da camada de aplicação",
        ],
    },

    # ── 9. Auth Failure Spike ────────────────────────────────────────────────
    {
        "id":          "auth_failure_spike",
        "name":        "Pico de Falhas de Autenticação",
        "description": (
            "Volume elevado de falhas de autenticação nos logs do sistema, "
            "sugerindo força bruta ou credential stuffing em um ou mais serviços."
        ),
        "severity":    "MEDIUM",
        "risk_bonus":  20,
        "remediation": [
            "Habilitar políticas de bloqueio de conta após N tentativas malsucedidas",
            "Implantar fail2ban ou equivalente para bloqueio automático de IPs ofensores",
            "Habilitar autenticação multifator em todos os serviços expostos",
            "Investigar IPs de origem e bloquear ASNs conhecidos como ameaça, se aplicável",
        ],
    },

    # ── 10. Docker API Exposed ───────────────────────────────────────────────
    {
        "id":          "docker_api_exposed",
        "name":        "API Docker Exposta",
        "description": (
            "A API do daemon Docker (porta 2375/2376) está acessível, permitindo "
            "controle total sobre os containers e possível escape do host."
        ),
        "severity":    "CRITICAL",
        "risk_bonus":  40,
        "remediation": [
            "Fechar imediatamente as portas 2375/2376 no firewall",
            "Configurar o Docker para escutar somente em socket Unix (remover -H tcp://:2375)",
            "Se o acesso remoto for necessário, habilitar autenticação mútua TLS (--tlsverify)",
            "Auditar containers em execução quanto a imagens ou processos inesperados",
        ],
    },

    # ── 11. ML Anomaly Detected ──────────────────────────────────────────────
    {
        "id":          "ml_anomaly_detected",
        "name":        "Anomalia Detectada por ML",
        "description": (
            "O detector de anomalias Isolation Forest classificou este host como estatisticamente "
            "atípico em relação à baseline dos demais hosts na sessão de scan. "
            "Isso pode indicar ataque zero-day, misconfiguração inesperada ou "
            "movimentação lateral não coberta pela detecção baseada em regras."
        ),
        "severity":    "HIGH",
        "risk_bonus":  25,
        "remediation": [
            "Investigar o host manualmente — a anomalia pode indicar vetor de ataque inédito",
            "Comparar serviços e portas atuais com baseline de configuração conhecida",
            "Verificar processos, tarefas agendadas ou software instalado recentemente",
            "Revisar logs de autenticação quanto a padrões de login ou contas novas",
            "Executar scan de acompanhamento após a investigação para confirmar remediação",
        ],
    },
]

# Quick lookup by id
PATTERN_BY_ID: Dict[str, Dict] = {p["id"]: p for p in PATTERNS}
