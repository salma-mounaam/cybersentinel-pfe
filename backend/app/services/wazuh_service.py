# ============================================================
# M11 — Wazuh Consumer Service
# CyberSentinel — Wazuh Manager / Agents Integration
#
# Modifications :
#   [NOISE] Filtre par level + blacklist
#   [DEDUP] Clé temporelle = rule_id + agent_id + src_ip
#   [CONF]  Malus localhost seulement si aucun groupe à risque
#   [LLM]   Classification IDS/HIDS via llm_attack_classifier
#   [PURGE] purge_old_alerts()
# ============================================================

import asyncio
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
from sqlalchemy import delete

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.alert import Alert, AlertSource
from app.services.attack_classifier import classify_attack_with_llm

logger = logging.getLogger(__name__)


# ============================================================
# Constantes filtrage bruit
# ============================================================

MIN_WAZUH_LEVEL = 5

WAZUH_NOISE_DESCRIPTIONS = {
    "Systemd: Service exited due to a failure",
    "Systemd: Unit entered failed state.",
    "Systemd: Unit has begun restarting.",
    "Wazuh server started.",
    "Docker: Error message",
    "File added to the system.",
}

WAZUH_NOISE_GROUPS = {
    "systemd",
    "docker",
    "ossec",
    "syslog",
}

WAZUH_PAM_NOISE_LEVEL_THRESHOLD = 8

HIGH_RISK_GROUPS = {
    "authentication_failed",
    "authentication_failures",
    "intrusion_detection",
    "exploit_attempt",
    "rootkit",
    "web_attack",
    "sql_injection",
    "brute_force",
    "recon",
    "privilege_escalation",
    "sshd",
    "syscheck",
    "fim",
    "malware",
}

TRUSTED_INTERNAL_IPS = {
    "127.0.0.1",
    "::1",
}

WAZUH_DEDUP_WINDOW = 300
WAZUH_RETENTION_DAYS = 7


def _env_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


class WazuhConsumer:
    """
    Consumer Wazuh pour CyberSentinel.

    Fonctionnement :
    - Authentification vers l'API REST Wazuh Manager.
    - Lecture des alertes Wazuh depuis alerts.json.
    - Filtrage du bruit.
    - Déduplication temporelle.
    - Classification attack_type via LLM/fallback heuristique.
    - Insertion dans PostgreSQL.
    """

    def __init__(self) -> None:
        self.api_url = getattr(
            settings,
            "WAZUH_API_URL",
            os.getenv("WAZUH_API_URL", "https://cybersentinel_wazuh:55000"),
        ).rstrip("/")

        self.username = getattr(
            settings,
            "WAZUH_API_USER",
            os.getenv("WAZUH_API_USER", "wazuh"),
        )

        self.password = getattr(
            settings,
            "WAZUH_API_PASS",
            os.getenv("WAZUH_API_PASS", "wazuh"),
        )

        self.verify_ssl = _env_bool(
            getattr(
                settings,
                "WAZUH_VERIFY_SSL",
                os.getenv("WAZUH_VERIFY_SSL", "false"),
            ),
            False,
        )

        self.poll_interval = int(
            getattr(
                settings,
                "WAZUH_POLL_INTERVAL",
                os.getenv("WAZUH_POLL_INTERVAL", 10),
            )
        )

        self.alerts_file = Path(
            getattr(
                settings,
                "WAZUH_ALERTS_FILE",
                os.getenv("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json"),
            )
        )

        self.local_asset_ip = getattr(
            settings,
            "WAZUH_LOCAL_ASSET_IP",
            os.getenv("WAZUH_LOCAL_ASSET_IP", ""),
        )

        self._running = False
        self._token: Optional[str] = None
        self._last_offset = 0
        self._seen_keys: set[str] = set()
        self._dedup_temporal: dict[str, datetime] = {}

    # ========================================================
    # API Wazuh
    # ========================================================

    async def _get_token(self) -> Optional[str]:
        url = f"{self.api_url}/security/user/authenticate?raw=true"

        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=15.0) as client:
                response = await client.post(url, auth=(self.username, self.password))
                response.raise_for_status()
                token = response.text.strip()

                if not token:
                    logger.warning("Token Wazuh vide")
                    return None

                self._token = token
                logger.info("Token JWT Wazuh obtenu")
                return token

        except Exception as exc:
            logger.warning("Impossible d'obtenir le token Wazuh: %s", exc)
            return None

    async def _api_get(self, path: str) -> Optional[Dict[str, Any]]:
        if not self._token:
            await self._get_token()

        if not self._token:
            return None

        url = f"{self.api_url}{path}"

        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=15.0) as client:
                response = await client.get(
                    url,
                    headers={"Authorization": f"Bearer {self._token}"},
                )

                if response.status_code == 401:
                    self._token = None
                    await self._get_token()

                    if not self._token:
                        return None

                    response = await client.get(
                        url,
                        headers={"Authorization": f"Bearer {self._token}"},
                    )

                response.raise_for_status()
                return response.json()

        except Exception as exc:
            logger.warning("Erreur API Wazuh GET %s: %s", path, exc)
            return None

    async def get_manager_info(self) -> Optional[Dict[str, Any]]:
        return await self._api_get("/manager/info")

    async def get_agents(self) -> Optional[Dict[str, Any]]:
        return await self._api_get("/agents")

    async def get_active_agents(self) -> Optional[Dict[str, Any]]:
        return await self._api_get("/agents?status=active")

    # ========================================================
    # Filtrage bruit
    # ========================================================

    def _is_noise(self, event: Dict[str, Any]) -> bool:
        rule = event.get("rule", {}) or {}
        level = int(rule.get("level", 0) or 0)
        description = (rule.get("description") or "").strip()
        groups = rule.get("groups", []) or []

        if any(g in HIGH_RISK_GROUPS for g in groups):
            return False

        if level < MIN_WAZUH_LEVEL:
            return True

        if level < 8 and description in WAZUH_NOISE_DESCRIPTIONS:
            return True

        non_pam_groups = [g for g in groups if g != "pam"]
        if (
            level < 8
            and non_pam_groups
            and all(g in WAZUH_NOISE_GROUPS for g in non_pam_groups)
        ):
            return True

        if "pam" in groups and level < WAZUH_PAM_NOISE_LEVEL_THRESHOLD:
            return True

        return False

    # ========================================================
    # Déduplication
    # ========================================================

    def _is_temporal_duplicate(self, event: Dict[str, Any], src_ip: str) -> bool:
        rule = event.get("rule", {}) or {}
        agent = event.get("agent", {}) or {}

        key = f"{rule.get('id', '')}|{agent.get('id', '')}|{src_ip}"
        now = datetime.now(timezone.utc)

        last_seen = self._dedup_temporal.get(key)

        if last_seen and (now - last_seen).total_seconds() < WAZUH_DEDUP_WINDOW:
            return True

        self._dedup_temporal[key] = now

        if len(self._dedup_temporal) > 2000:
            cutoff = now - timedelta(seconds=WAZUH_DEDUP_WINDOW * 2)
            self._dedup_temporal = {
                k: v
                for k, v in self._dedup_temporal.items()
                if v > cutoff
            }

        return False

    # ========================================================
    # Score confiance
    # ========================================================

    def _compute_confidence(self, event: Dict[str, Any], src_ip: str) -> float:
        rule = event.get("rule", {}) or {}
        groups = rule.get("groups", []) or []
        level = int(rule.get("level", 0) or 0)

        confidence = level / 15.0
        has_high_risk = any(g in HIGH_RISK_GROUPS for g in groups)

        if has_high_risk:
            confidence = min(confidence + 0.20, 1.0)

        if src_ip in TRUSTED_INTERNAL_IPS and not has_high_risk:
            confidence = max(confidence - 0.15, 0.0)

        return round(confidence, 4)

    # ========================================================
    # Lecture alerts.json
    # ========================================================

    async def _fetch_alerts(self) -> list[Dict[str, Any]]:
        if not self.alerts_file.exists():
            logger.info("Fichier alertes Wazuh introuvable: %s", self.alerts_file)
            return []

        alerts: list[Dict[str, Any]] = []

        try:
            current_size = self.alerts_file.stat().st_size

            if current_size < self._last_offset:
                self._last_offset = 0

            with self.alerts_file.open("r", encoding="utf-8", errors="ignore") as file:
                file.seek(self._last_offset)

                for line in file:
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.debug("Ligne Wazuh JSON invalide ignorée")

                self._last_offset = file.tell()

        except Exception as exc:
            logger.warning("Erreur lecture alertes Wazuh: %s", exc)

        return alerts

    # ========================================================
    # Helpers parsing
    # ========================================================

    def _parse_timestamp(self, value: Optional[str]) -> datetime:
        if not value:
            return datetime.now(timezone.utc)

        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

    def _severity_from_level(self, level: int) -> str:
        if level >= 12:
            return "CRITIQUE"
        if level >= 8:
            return "ELEVE"
        if level >= 5:
            return "MOYEN"
        return "FAIBLE"

    def _dedup_key(self, event: Dict[str, Any]) -> str:
        rule = event.get("rule", {}) or {}
        agent = event.get("agent", {}) or {}
        data = event.get("data", {}) or {}

        return "|".join(
            [
                str(event.get("timestamp", "")),
                str(agent.get("id", "")),
                str(agent.get("name", "")),
                str(rule.get("id", "")),
                str(data.get("srcip", "")),
                str(data.get("srcport", "")),
                str(event.get("location", "")),
                str(event.get("full_log", ""))[:200],
            ]
        )

    def _safe_alert_kwargs(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        valid_columns = set(Alert.__table__.columns.keys())
        return {key: value for key, value in kwargs.items() if key in valid_columns}

    def _safe_int(self, value: Any) -> Optional[int]:
        try:
            if value is None or value == "":
                return None
            return int(value)
        except Exception:
            return None

    def _extract_ips(self, event: Dict[str, Any]) -> tuple[str, str]:
        agent = event.get("agent", {}) or {}
        data = event.get("data", {}) or {}

        data_src_ip = (
            data.get("srcip")
            or data.get("src_ip")
            or data.get("source_ip")
            or data.get("client_ip")
        )

        data_dst_ip = (
            data.get("dstip")
            or data.get("dst_ip")
            or data.get("dest_ip")
            or data.get("destination_ip")
        )

        agent_ip = agent.get("ip") or ""
        normalized_agent_ip = "" if agent_ip in {"127.0.0.1", "localhost"} else agent_ip

        src_ip = data_src_ip or normalized_agent_ip or agent_ip or "0.0.0.0"
        dest_ip = (
            data_dst_ip
            or self.local_asset_ip
            or normalized_agent_ip
            or agent_ip
            or "0.0.0.0"
        )

        return str(src_ip), str(dest_ip)

    def _extract_wazuh_context(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extrait un contexte utile pour le LLM/fallback :
        user, process, file_path, groups, full_log...
        """
        rule = event.get("rule", {}) or {}
        agent = event.get("agent", {}) or {}
        data = event.get("data", {}) or {}
        syscheck = event.get("syscheck", {}) or {}

        rule_groups = rule.get("groups", []) or []
        full_log = event.get("full_log") or ""

        username = (
            data.get("dstuser")
            or data.get("srcuser")
            or data.get("user")
            or data.get("username")
            or data.get("win", {}).get("eventdata", {}).get("targetUserName")
            if isinstance(data.get("win"), dict)
            else None
        )

        process_name = (
            data.get("process")
            or data.get("process_name")
            or data.get("program_name")
            or data.get("command")
            or data.get("exe")
        )

        file_path = (
            data.get("file")
            or data.get("path")
            or data.get("filename")
            or syscheck.get("path")
        )

        return {
            "agent_name": agent.get("name", ""),
            "agent_ip": agent.get("ip", ""),
            "agent_id": agent.get("id", ""),
            "rule_id": str(rule.get("id", "") or ""),
            "rule_level": int(rule.get("level", 0) or 0),
            "rule_groups": rule_groups,
            "full_log": full_log,
            "process_name": process_name,
            "username": username,
            "file_path": file_path,
        }

    # ========================================================
    # Wazuh → Alert CyberSentinel
    # ========================================================

    async def _wazuh_to_alert(self, event: Dict[str, Any], src_ip: str, dest_ip: str) -> Alert:
        rule = event.get("rule", {}) or {}
        agent = event.get("agent", {}) or {}
        data = event.get("data", {}) or {}

        level = int(rule.get("level", 0) or 0)
        rule_id_raw = str(rule.get("id", "") or "")
        rule_id = int(rule_id_raw) if rule_id_raw.isdigit() else None

        description = rule.get("description") or event.get("full_log") or "Alerte Wazuh"
        groups = rule.get("groups", []) or []
        category = groups[0] if groups else "wazuh"

        timestamp = self._parse_timestamp(event.get("timestamp"))
        confidence = self._compute_confidence(event, src_ip)

        ctx = self._extract_wazuh_context(event)

        dest_port = self._safe_int(data.get("dstport") or data.get("dest_port")) or 0

        try:
            llm_result = await classify_attack_with_llm(
                source="M11_WAZUH",
                signature_name=description,
                category=category,
                src_ip=src_ip,
                dest_ip=dest_ip,
                dest_port=dest_port,
                protocol="HOST",
                technique_id=None,
                tactic=None,
                agent_name=ctx.get("agent_name"),
                agent_ip=ctx.get("agent_ip"),
                rule_id=ctx.get("rule_id"),
                rule_groups=ctx.get("rule_groups"),
                full_log=ctx.get("full_log"),
                process_name=ctx.get("process_name"),
                username=ctx.get("username"),
                file_path=ctx.get("file_path"),
            )
        except Exception as exc:
            logger.warning("Classification LLM Wazuh échouée: %s", exc)
            llm_result = {
                "attack_type": "Unknown",
                "confidence": 0.4,
                "reasoning": "Erreur classification LLM Wazuh.",
            }

        attack_type = llm_result.get("attack_type", "Unknown")
        llm_confidence = float(llm_result.get("confidence", 0.4) or 0.4)
        llm_reasoning = llm_result.get("reasoning", "")

        final_confidence = round(max(confidence, llm_confidence), 4)

        raw_payload = {
            "source": "wazuh",
            "agent": agent,
            "rule": rule,
            "data": data,
            "location": event.get("location"),
            "full_log": event.get("full_log"),
            "llm_classification": llm_result,
            "raw": event,
        }

        asset_name = agent.get("name", "") or "unknown-host"

        title = f"{attack_type} — {src_ip} → {asset_name}"

        kwargs = {
            "source": AlertSource.M11_WAZUH,
            "severity": self._severity_from_level(level),

            "title": title,
            "description": description,
            "attack_type": attack_type,
            "category": category,

            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "src_port": self._safe_int(data.get("srcport")),
            "dest_port": dest_port if dest_port else None,
            "protocol": "HOST",

            "signature_id": rule_id,
            "signature_name": description,

            "suricata_score": final_confidence,
            "ml_score": 0.0,
            "confidence": final_confidence,
            "fusion_case": 3,

            "asset_ip": dest_ip,
            "asset_name": asset_name,
            "asset_criticality": 5.0,

            "llm_attack_type": attack_type,
            "llm_confidence": llm_confidence,
            "llm_reasoning": llm_reasoning,

            "raw_event": raw_payload,
            "raw_payload": raw_payload,

            "timestamp": timestamp,
            "detected_at": timestamp,
        }

        logger.info(
            "Wazuh classified | rule=%s | attack_type=%s | conf=%.2f | asset=%s",
            description,
            attack_type,
            final_confidence,
            asset_name,
        )

        return Alert(**self._safe_alert_kwargs(kwargs))

    # ========================================================
    # DB — Insertion
    # ========================================================

    async def _store_alerts(self, events: list[Dict[str, Any]]) -> int:
        if not events:
            return 0

        inserted = 0
        filtered_noise = 0
        filtered_dedup = 0

        async with AsyncSessionLocal() as db:
            try:
                for event in events:

                    if self._is_noise(event):
                        filtered_noise += 1
                        continue

                    src_ip, dest_ip = self._extract_ips(event)

                    key = self._dedup_key(event)
                    if key in self._seen_keys:
                        filtered_dedup += 1
                        continue

                    if self._is_temporal_duplicate(event, src_ip):
                        filtered_dedup += 1
                        continue

                    self._seen_keys.add(key)

                    if len(self._seen_keys) > 5000:
                        self._seen_keys = set(list(self._seen_keys)[-3000:])

                    alert = await self._wazuh_to_alert(event, src_ip, dest_ip)
                    db.add(alert)
                    inserted += 1

                if inserted:
                    await db.commit()

                logger.info(
                    "Wazuh : %s insérées | %s bruit filtré | %s doublons filtrés",
                    inserted,
                    filtered_noise,
                    filtered_dedup,
                )

            except Exception as exc:
                await db.rollback()
                logger.exception("Erreur insertion alertes Wazuh: %s", exc)

        return inserted

    # ========================================================
    # Purge
    # ========================================================

    async def purge_old_alerts(self) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=WAZUH_RETENTION_DAYS)

        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    delete(Alert)
                    .where(Alert.source == AlertSource.M11_WAZUH)
                    .where(Alert.detected_at < cutoff)
                )
                await db.commit()

                deleted = result.rowcount or 0

                logger.info(
                    "🧹 Purge Wazuh : %s alertes supprimées (antérieures au %s)",
                    deleted,
                    cutoff.date(),
                )

                return deleted

        except Exception as exc:
            logger.error("Erreur purge alertes Wazuh: %s", exc)
            return 0

    # ========================================================
    # Lifecycle
    # ========================================================

    async def start(self) -> None:
        self._running = True

        logger.info(
            "Wazuh consumer démarré | api=%s | file=%s | poll=%ss | "
            "local_asset_ip=%s | min_level=%s | retention=%sd",
            self.api_url,
            self.alerts_file,
            self.poll_interval,
            self.local_asset_ip or "non défini",
            MIN_WAZUH_LEVEL,
            WAZUH_RETENTION_DAYS,
        )

        await self._get_token()

        while self._running:
            try:
                events = await self._fetch_alerts()
                await self._store_alerts(events)

            except asyncio.CancelledError:
                raise

            except Exception as exc:
                logger.exception("Erreur boucle Wazuh consumer: %s", exc)

            await asyncio.sleep(self.poll_interval)

    async def stop(self) -> None:
        self._running = False
        logger.info("Arrêt Wazuh consumer demandé")