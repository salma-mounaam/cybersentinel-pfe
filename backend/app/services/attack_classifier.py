# ============================================================
# LLM Attack Classifier — Llama 3.1 via Ollama
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


async def classify_attack_with_llm(
    signature_name: str,
    category: str,
    src_ip: str,
    dest_ip: str,
    dest_port: int,
    protocol: str,
    technique_id: str = None,
    tactic: str = None,
) -> dict:
    """
    Classifie le type d'attaque avec Llama 3.1 via Ollama.
    Utilise Redis pour cacher le résultat 24h.
    """

    cache_source = f"{signature_name}|{category}|{dest_port}|{protocol}|{technique_id}|{tactic}"
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
            logger.info("LLM cache HIT | %s", signature_name)
            return json.loads(cached)

        await r.aclose()

    except Exception as e:
        logger.warning("Cache Redis indisponible: %s", e)

    logger.info("LLM cache MISS | %s — appel Ollama", signature_name)

    prompt = f"""You are a cybersecurity SOC expert. Analyze this network alert.
Return ONLY a valid JSON object, no markdown, no backticks, no extra text.

Alert:
- Signature: {signature_name}
- Category: {category}
- Source IP: {src_ip}
- Destination IP: {dest_ip}
- Destination Port: {dest_port}
- Protocol: {protocol}
- MITRE Technique: {technique_id or 'Unknown'}
- MITRE Tactic: {tactic or 'Unknown'}

Choose ONE attack type from:
BruteForce, PortScan, DoS, DDoS, SQLi, XSS, CommandInjection,
Exploit, Botnet, Exfiltration, Reconnaissance, Malware, WebAttack,
Infiltration, Unknown

Rules:
- SSH login attempts on port 22 can be BruteForce when repeated or suspicious.
- Nmap, SYN scan, many ports, or scan signatures should be PortScan.
- HTTP requests to metadata endpoints such as 169.254.169.254 should be Reconnaissance.
- Generic HTTP traffic without exploit evidence should be WebAttack or Reconnaissance depending on context.
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
                        "num_predict": 120,
                    },
                },
            )

        if response.status_code != 200:
            logger.warning(
                "LLM HTTP error | status=%s | body=%s",
                response.status_code,
                response.text[:300],
            )
            result = _fallback_classify(signature_name, category)
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
                "LLM | %s → %s (conf=%.2f)",
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

    result = _fallback_classify(signature_name, category)
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
    allowed_types = {
        "BruteForce",
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
        "Unknown",
    }

    attack_type = str(result.get("attack_type", "Unknown")).strip()

    aliases = {
        "Bruteforce": "BruteForce",
        "Brute Force": "BruteForce",
        "SSH Bruteforce": "BruteForce",
        "SSH BruteForce": "BruteForce",
        "Port Scan": "PortScan",
        "Portscan": "PortScan",
        "DDoS Attack": "DDoS",
        "DoS Attack": "DoS",
        "SQL Injection": "SQLi",
        "Command Injection": "CommandInjection",
        "Recon": "Reconnaissance",
    }

    attack_type = aliases.get(attack_type, attack_type)

    if attack_type not in allowed_types:
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


def _fallback_classify(signature_name: str, category: str) -> dict:
    sig = (signature_name or "").upper()
    cat = (category or "").upper()

    if any(x in sig for x in ["SSH", "BRUTE", "HYDRA", "MEDUSA"]):
        attack = "BruteForce"
    elif any(x in sig for x in ["SCAN", "NMAP", "SWEEP", "PORTSCAN"]):
        attack = "PortScan"
    elif any(x in sig for x in ["DDOS"]):
        attack = "DDoS"
    elif any(x in sig for x in ["DOS", "FLOOD", "SLOWLORIS"]):
        attack = "DoS"
    elif any(x in sig for x in ["SQL", "SQLI", "UNION SELECT"]):
        attack = "SQLi"
    elif any(x in sig for x in ["XSS", "CROSS SITE", "SCRIPT"]):
        attack = "XSS"
    elif any(x in sig for x in ["COMMAND", "CMD", "INJECTION"]):
        attack = "CommandInjection"
    elif any(x in sig for x in ["EXPLOIT", "CVE", "RCE", "SHELL"]):
        attack = "Exploit"
    elif any(x in sig for x in ["BOTNET", "C2", "BEACON", "RAT"]):
        attack = "Botnet"
    elif any(x in sig for x in ["EXFIL", "DATA", "LEAK", "DNS TXT"]):
        attack = "Exfiltration"
    elif any(x in sig for x in ["RECON", "DISCOVERY", "METADATA"]):
        attack = "Reconnaissance"
    elif any(x in cat for x in ["WEB", "HTTP", "POLICY"]):
        attack = "WebAttack"
    elif any(x in cat for x in ["TROJAN", "MALWARE", "VIRUS"]):
        attack = "Malware"
    else:
        attack = "Unknown"

    return {
        "attack_type": attack,
        "confidence": 0.5,
        "reasoning": "Classification heuristique utilisée car Llama/Ollama est indisponible ou trop lent.",
    }