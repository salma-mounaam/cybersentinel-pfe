# ============================================================
# LLM Attack Classifier — IDS + HIDS + DAST/SAST
# Llama 3.1 via Ollama
# Cache Redis 24h pour éviter les appels répétés CPU-only
# ============================================================

import httpx
import json
import logging
import hashlib
import redis.asyncio as aioredis

from app.core.config import settings

logger = logging.getLogger(__name__)

OLLAMA_URL = "http://172.17.0.1:11434/api/generate"
MODEL = "llama3.1:8b"


ALLOWED_ATTACK_TYPES = {
    "BruteForce",
    "AuthenticationFailure",
    "PortScan",
    "DoS",
    "DDoS",
    "SQLi",
    "XSS",
    "CommandInjection",
    "Exploit",
    "Botnet",
    "Exfiltration",
    "Reconnaissance",
    "Malware",
    "WebAttack",
    "Infiltration",
    "FileIntegrity",
    "PrivilegeEscalation",
    "Persistence",
    "CredentialAccess",
    "DefenseEvasion",
    "LateralMovement",
    "SuspiciousProcess",
    "SystemMisconfiguration",
    "DockerAbuse",
    "Unknown",
}


async def classify_attack_with_llm(
    signature_name: str,
    category: str,
    src_ip: str = "",
    dest_ip: str = "",
    dest_port: int = 0,
    protocol: str = "",
    technique_id: str = None,
    tactic: str = None,

    # Nouveaux champs pour HIDS/Wazuh/SAST/DAST
    source: str = "M1_SURICATA",
    agent_name: str = None,
    agent_ip: str = None,
    rule_id: str = None,
    rule_groups: list | str | None = None,
    full_log: str = None,
    process_name: str = None,
    username: str = None,
    file_path: str = None,
) -> dict:
    """
    Classifie le type d'attaque avec Llama 3.1 via Ollama.

    Compatible avec :
    - M1_SURICATA : IDS réseau
    - M11_WAZUH   : HIDS endpoint
    - DAST/SAST   : vulnérabilités applicatives

    Utilise Redis pour cacher le résultat.
    """

    groups_text = ""
    if isinstance(rule_groups, list):
        groups_text = ",".join(str(x) for x in rule_groups)
    elif rule_groups:
        groups_text = str(rule_groups)

    cache_source = (
        f"{source}|{signature_name}|{category}|{src_ip}|{dest_ip}|"
        f"{dest_port}|{protocol}|{technique_id}|{tactic}|"
        f"{rule_id}|{groups_text}|{process_name}|{username}|{file_path}"
    )

    cache_key = f"llm:attack_type:{hashlib.md5(cache_source.encode()).hexdigest()}"

    try:
        r = await aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        cached = await r.get(cache_key)

        if cached:
            await r.aclose()
            logger.info("LLM cache HIT | source=%s | signature=%s", source, signature_name)
            return json.loads(cached)

        await r.aclose()

    except Exception as e:
        logger.warning("Cache Redis indisponible: %s", e)

    logger.info("LLM cache MISS | source=%s | signature=%s — appel Ollama", source, signature_name)

    prompt = f"""You are a cybersecurity SOC expert.
Classify this alert as a concrete attack type.
Return ONLY a valid JSON object, no markdown, no backticks, no extra text.

Alert:
- Source: {source}
- Signature/Rule name: {signature_name}
- Category: {category}
- Source IP: {src_ip or 'Unknown'}
- Destination IP: {dest_ip or 'Unknown'}
- Destination Port: {dest_port or 'Unknown'}
- Protocol: {protocol or 'Unknown'}
- MITRE Technique: {technique_id or 'Unknown'}
- MITRE Tactic: {tactic or 'Unknown'}

HIDS/Wazuh context:
- Agent name: {agent_name or 'Unknown'}
- Agent IP: {agent_ip or 'Unknown'}
- Rule ID: {rule_id or 'Unknown'}
- Rule groups: {groups_text or 'Unknown'}
- Process: {process_name or 'Unknown'}
- User: {username or 'Unknown'}
- File path: {file_path or 'Unknown'}
- Full log excerpt: {(full_log or 'Unknown')[:800]}

Choose ONE attack type from:
BruteForce, AuthenticationFailure, PortScan, DoS, DDoS, SQLi, XSS,
CommandInjection, Exploit, Botnet, Exfiltration, Reconnaissance,
Malware, WebAttack, Infiltration, FileIntegrity, PrivilegeEscalation,
Persistence, CredentialAccess, DefenseEvasion, LateralMovement,
SuspiciousProcess, SystemMisconfiguration, DockerAbuse, Unknown

Rules:
- Wazuh "Integrity checksum changed", "File added", "File modified", "File deleted", "syscheck" => FileIntegrity.
- Failed SSH/PAM/login/authentication attempts => AuthenticationFailure or BruteForce if repeated/suspicious.
- sudo abuse, root access, privilege change, UID 0, user/group added => PrivilegeEscalation.
- Docker error, container abuse, suspicious Docker activity => DockerAbuse.
- Suspicious process execution, shell, reverse shell, unusual command => SuspiciousProcess or CommandInjection.
- Cron, systemd service creation, autorun, startup modification => Persistence.
- Credential dumping, password file access, secrets access => CredentialAccess.
- Malware, trojan, virus, rootkit indicators => Malware.
- Web exploit, CVE, RCE, path traversal, public-facing app exploit => Exploit or WebAttack.
- Recon, discovery, metadata endpoint, enumeration => Reconnaissance.
- If unsure, use Unknown with low confidence.

Respond exactly as JSON:
{{"attack_type": "TYPE", "confidence": 0.95, "reasoning": "courte explication en français"}}"""

    try:
        async with httpx.AsyncClient(timeout=90.0) as client:
            response = await client.post(
                OLLAMA_URL,
                json={
                    "model": MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "num_predict": 160,
                    },
                },
            )

        if response.status_code != 200:
            logger.warning(
                "LLM HTTP error | status=%s | body=%s",
                response.status_code,
                response.text[:300],
            )

            result = _fallback_classify(
                signature_name=signature_name,
                category=category,
                source=source,
                rule_groups=groups_text,
                full_log=full_log,
                dest_port=dest_port,
                technique_id=technique_id,
                tactic=tactic,
                process_name=process_name,
                username=username,
                file_path=file_path,
            )
            await _cache_result(cache_key, result, ttl=3600)
            return result

        data = response.json()
        raw_text = data.get("response", "").strip()

        raw_text = raw_text.replace("```json", "").replace("```", "").strip()

        start = raw_text.find("{")
        end = raw_text.rfind("}") + 1

        if start != -1 and end > start:
            result = json.loads(raw_text[start:end])
            result = _normalize_llm_result(result)

            await _cache_result(cache_key, result, ttl=86400)

            logger.info(
                "LLM | source=%s | %s → %s (conf=%.2f)",
                source,
                signature_name,
                result.get("attack_type"),
                result.get("confidence", 0),
            )

            return result

        logger.warning("LLM réponse sans JSON valide: %s", raw_text[:300])

    except httpx.TimeoutException:
        logger.warning("LLM timeout après 90s — fallback heuristique")

    except Exception as e:
        logger.warning("LLM erreur: %s — fallback heuristique", e)

    result = _fallback_classify(
        signature_name=signature_name,
        category=category,
        source=source,
        rule_groups=groups_text,
        full_log=full_log,
        dest_port=dest_port,
        technique_id=technique_id,
        tactic=tactic,
        process_name=process_name,
        username=username,
        file_path=file_path,
    )
    await _cache_result(cache_key, result, ttl=3600)
    return result


async def _cache_result(cache_key: str, result: dict, ttl: int):
    try:
        r = await aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        await r.setex(cache_key, ttl, json.dumps(result))
        await r.aclose()
    except Exception:
        pass


def _normalize_llm_result(result: dict) -> dict:
    attack_type = str(result.get("attack_type", "Unknown")).strip()

    aliases = {
        "Bruteforce": "BruteForce",
        "Brute Force": "BruteForce",
        "SSH Bruteforce": "BruteForce",
        "SSH BruteForce": "BruteForce",

        "Login Failure": "AuthenticationFailure",
        "Authentication Failure": "AuthenticationFailure",
        "AuthFailure": "AuthenticationFailure",
        "Auth Failure": "AuthenticationFailure",

        "File Integrity": "FileIntegrity",
        "FIM": "FileIntegrity",
        "Integrity": "FileIntegrity",
        "File Modification": "FileIntegrity",

        "Privilege Escalation": "PrivilegeEscalation",
        "PrivEsc": "PrivilegeEscalation",
        "Privilege Abuse": "PrivilegeEscalation",

        "Credential Access": "CredentialAccess",
        "Credential Theft": "CredentialAccess",

        "Defense Evasion": "DefenseEvasion",
        "Lateral Movement": "LateralMovement",
        "Suspicious Process": "SuspiciousProcess",
        "Suspicious Command": "SuspiciousProcess",
        "Docker Abuse": "DockerAbuse",
        "Container Abuse": "DockerAbuse",
        "Misconfiguration": "SystemMisconfiguration",

        "Port Scan": "PortScan",
        "Portscan": "PortScan",
        "DDoS Attack": "DDoS",
        "DoS Attack": "DoS",
        "SQL Injection": "SQLi",
        "Command Injection": "CommandInjection",
        "Recon": "Reconnaissance",
    }

    attack_type = aliases.get(attack_type, attack_type)

    if attack_type not in ALLOWED_ATTACK_TYPES:
        attack_type = "Unknown"

    try:
        confidence = float(result.get("confidence", 0.5))
    except Exception:
        confidence = 0.5

    confidence = max(0.0, min(1.0, confidence))

    reasoning = str(result.get("reasoning", "")).strip()
    if not reasoning:
        reasoning = "Classification LLM sans justification détaillée."

    return {
        "attack_type": attack_type,
        "confidence": confidence,
        "reasoning": reasoning,
    }


def _fallback_classify(
    signature_name: str,
    category: str,
    source: str = "",
    rule_groups: str = "",
    full_log: str = "",
    dest_port: int = 0,
    technique_id: str = None,
    tactic: str = None,
    process_name: str = None,
    username: str = None,
    file_path: str = None,
) -> dict:
    sig = (signature_name or "").upper()
    cat = (category or "").upper()
    src = (source or "").upper()
    groups = (rule_groups or "").upper()
    log = (full_log or "").upper()
    proc = (process_name or "").upper()
    user = (username or "").upper()
    path = (file_path or "").upper()
    tech = (technique_id or "").upper()
    tac = (tactic or "").upper()

    text = f"{sig} {cat} {src} {groups} {log} {proc} {user} {path} {tech} {tac}"

    confidence = 0.65

    # ========================================================
    # HIDS / Wazuh
    # ========================================================

    if any(x in text for x in [
        "INTEGRITY CHECKSUM CHANGED",
        "FILE ADDED",
        "FILE MODIFIED",
        "FILE DELETED",
        "SYSCHECK",
        "FIM",
        "INTEGRITY",
    ]):
        attack = "FileIntegrity"
        confidence = 0.75

    elif any(x in text for x in [
        "PAM",
        "LOGIN FAILED",
        "FAILED PASSWORD",
        "AUTHENTICATION FAILURE",
        "INVALID USER",
        "SSHD",
        "MULTIPLE AUTHENTICATION FAILURES",
        "MAXIMUM AUTHENTICATION ATTEMPTS",
    ]):
        if dest_port == 22 or "SSH" in text or "SSHD" in text:
            attack = "BruteForce"
            confidence = 0.75
        else:
            attack = "AuthenticationFailure"
            confidence = 0.70

    elif any(x in text for x in [
        "SUDO",
        "ROOT",
        "PRIVILEGE",
        "PRIVILEGE ESCALATION",
        "USER ADDED",
        "GROUP ADDED",
        "USER MODIFIED",
        "UID 0",
        "EUID=0",
        "BECAME ROOT",
    ]):
        attack = "PrivilegeEscalation"
        confidence = 0.72

    elif any(x in text for x in [
        "PASSWD",
        "SHADOW",
        "CREDENTIAL",
        "PASSWORD",
        "SECRET",
        "TOKEN",
        "PRIVATE KEY",
        "ID_RSA",
    ]):
        attack = "CredentialAccess"
        confidence = 0.72

    elif any(x in text for x in [
        "DOCKER",
        "CONTAINER",
        "DOCKER DAEMON",
        "DOCKER ERROR",
        "IMAGE PULL",
        "CONTAINER START",
        "CONTAINER EXEC",
    ]):
        attack = "DockerAbuse"
        confidence = 0.68

    elif any(x in text for x in [
        "PROCESS",
        "COMMAND EXECUTION",
        "SHELL",
        "BASH",
        "NC ",
        "NETCAT",
        "REVERSE SHELL",
        "POWERSHELL",
        "CMD.EXE",
        "/BIN/SH",
        "/BIN/BASH",
    ]):
        attack = "SuspiciousProcess"
        confidence = 0.70

    elif any(x in text for x in [
        "CRON",
        "CRONTAB",
        "SERVICE INSTALLED",
        "SYSTEMD",
        "AUTO START",
        "STARTUP",
        "PERSISTENCE",
        "AUTHORIZED_KEYS",
    ]):
        attack = "Persistence"
        confidence = 0.70

    elif any(x in text for x in [
        "MALWARE",
        "TROJAN",
        "VIRUS",
        "ROOTKIT",
        "RAT",
        "YARA",
        "CLAMAV",
    ]):
        attack = "Malware"
        confidence = 0.80

    elif any(x in text for x in [
        "CONFIGURATION",
        "MISCONFIGURATION",
        "INSECURE",
        "WEAK PERMISSION",
        "PERMISSION",
        "WORLD WRITABLE",
    ]):
        attack = "SystemMisconfiguration"
        confidence = 0.62

    # ========================================================
    # IDS / Réseau / Suricata
    # ========================================================

    elif any(x in text for x in ["SSH", "BRUTE", "HYDRA", "MEDUSA"]):
        attack = "BruteForce"
        confidence = 0.75

    elif any(x in text for x in ["SCAN", "NMAP", "SWEEP", "PORTSCAN", "SYN SCAN"]):
        attack = "PortScan"
        confidence = 0.75

    elif "DDOS" in text:
        attack = "DDoS"
        confidence = 0.75

    elif any(x in text for x in ["DOS", "FLOOD", "SLOWLORIS"]):
        attack = "DoS"
        confidence = 0.72

    elif any(x in text for x in ["SQL", "SQLI", "UNION SELECT", "SELECT FROM"]):
        attack = "SQLi"
        confidence = 0.78

    elif any(x in text for x in ["XSS", "CROSS SITE", "SCRIPT", "<SCRIPT"]):
        attack = "XSS"
        confidence = 0.78

    elif any(x in text for x in [
        "COMMAND",
        "CMD",
        "INJECTION",
        "RCE",
        "REMOTE CODE EXECUTION",
    ]):
        attack = "CommandInjection"
        confidence = 0.78

    elif any(x in text for x in [
        "EXPLOIT",
        "CVE",
        "SHELL",
        "PATH TRAVERSAL",
        "TRAVERSAL",
        "PUBLIC-FACING",
    ]):
        attack = "Exploit"
        confidence = 0.72

    elif any(x in text for x in ["BOTNET", "C2", "BEACON", "RAT"]):
        attack = "Botnet"
        confidence = 0.75

    elif any(x in text for x in [
        "EXFIL",
        "DATA LEAK",
        "DNS TXT",
        "DATA EXFILTRATION",
        "UPLOAD SUSPICIOUS",
    ]):
        attack = "Exfiltration"
        confidence = 0.72

    elif any(x in text for x in [
        "RECON",
        "DISCOVERY",
        "METADATA",
        "ENUMERATION",
        "PROBING",
    ]):
        attack = "Reconnaissance"
        confidence = 0.70

    elif any(x in cat for x in ["WEB", "HTTP", "POLICY"]) or dest_port in [80, 443, 8000, 8080, 3000]:
        attack = "WebAttack"
        confidence = 0.55

    else:
        attack = "Unknown"
        confidence = 0.4

    return {
        "attack_type": attack,
        "confidence": confidence,
        "reasoning": "Classification heuristique IDS/HIDS utilisée car Llama/Ollama est indisponible ou trop lent.",
    }