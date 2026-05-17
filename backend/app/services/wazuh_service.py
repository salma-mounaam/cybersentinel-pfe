# ============================================================
# M11 — Wazuh Consumer Service
# CyberSentinel — Wazuh Manager / Agents Integration
# ============================================================

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.alert import Alert, AlertSource

logger = logging.getLogger(__name__)


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
    - Conversion en Alert CyberSentinel.
    - Insertion dans PostgreSQL.

    Compatible avec :
    - 1 Manager Wazuh Docker
    - N agents Wazuh
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

        # IP réelle de la machine protégée par l'agent Wazuh.
        # Sur ai-learn : 10.16.2.150
        self.local_asset_ip = getattr(
            settings,
            "WAZUH_LOCAL_ASSET_IP",
            os.getenv("WAZUH_LOCAL_ASSET_IP", ""),
        )

        self._running = False
        self._token: Optional[str] = None
        self._last_offset = 0
        self._seen_keys: set[str] = set()

    # ========================================================
    # API Wazuh
    # ========================================================
    async def _get_token(self) -> Optional[str]:
        """
        Récupère le token JWT Wazuh.
        """
        url = f"{self.api_url}/security/user/authenticate?raw=true"

        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=15.0,
            ) as client:
                response = await client.post(
                    url,
                    auth=(self.username, self.password),
                )

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
        """
        GET générique vers l'API Wazuh.
        """
        if not self._token:
            await self._get_token()

        if not self._token:
            return None

        url = f"{self.api_url}{path}"

        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=15.0,
            ) as client:
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
    # Lecture alerts.json
    # ========================================================
    async def _fetch_alerts(self) -> list[Dict[str, Any]]:
        """
        Lit uniquement les nouvelles lignes de alerts.json.
        """
        if not self.alerts_file.exists():
            logger.info("Fichier alertes Wazuh introuvable: %s", self.alerts_file)
            return []

        alerts: list[Dict[str, Any]] = []

        try:
            current_size = self.alerts_file.stat().st_size

            # Si le fichier est recréé ou tronqué
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
    # Conversion Wazuh → CyberSentinel Alert
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
        if level >= 4:
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
        """
        Garde uniquement les champs qui existent réellement dans le modèle Alert.
        """
        valid_columns = set(Alert.__table__.columns.keys())
        return {key: value for key, value in kwargs.items() if key in valid_columns}

    def _extract_ips(self, event: Dict[str, Any]) -> tuple[str, str]:
        """
        Extrait les IPs de l'alerte Wazuh.

        Cas SSH brute force :
        - Wazuh agent voit agent.ip = 127.0.0.1 car l'agent parle au manager local.
        - Mais l'IP attaquante réelle est dans data.srcip.
        - La cible réelle est la VM ai-learn : WAZUH_LOCAL_ASSET_IP=10.16.2.150.

        Objectif :
        - src_ip  = IP attaquante réelle si disponible
        - dest_ip = IP de l'asset surveillé
        """
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

        # Si agent_ip vaut 127.0.0.1, ce n'est pas utile pour la corrélation réseau.
        normalized_agent_ip = "" if agent_ip in {"127.0.0.1", "localhost"} else agent_ip

        src_ip = (
            data_src_ip
            or normalized_agent_ip
            or agent_ip
            or "0.0.0.0"
        )

        dest_ip = (
            data_dst_ip
            or self.local_asset_ip
            or normalized_agent_ip
            or agent_ip
            or "0.0.0.0"
        )

        return str(src_ip), str(dest_ip)

    def _wazuh_to_alert(self, event: Dict[str, Any]) -> Alert:
        rule = event.get("rule", {}) or {}
        agent = event.get("agent", {}) or {}
        data = event.get("data", {}) or {}

        level = int(rule.get("level", 0) or 0)
        rule_id_raw = str(rule.get("id", "") or "")
        rule_id = int(rule_id_raw) if rule_id_raw.isdigit() else None

        description = (
            rule.get("description")
            or event.get("full_log")
            or "Alerte Wazuh"
        )

        groups = rule.get("groups", []) or []
        category = groups[0] if groups else "wazuh"

        src_ip, dest_ip = self._extract_ips(event)

        timestamp = self._parse_timestamp(event.get("timestamp"))
        confidence = round(min(max(level / 15.0, 0), 1), 4)

        raw_payload = {
            "source": "wazuh",
            "agent": agent,
            "rule": rule,
            "data": data,
            "location": event.get("location"),
            "full_log": event.get("full_log"),
            "raw": event,
        }

        kwargs = {
            "source": AlertSource.M11_WAZUH,
            "severity": self._severity_from_level(level),

            "title": f"Wazuh: {description}",
            "description": description,
            "attack_type": "Wazuh",
            "category": category,

            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "src_port": self._safe_int(data.get("srcport")),
            "dest_port": self._safe_int(data.get("dstport") or data.get("dest_port")),
            "protocol": "host",

            "signature_id": rule_id,
            "signature_name": description,

            "suricata_score": confidence,
            "ml_score": 0.0,
            "confidence": confidence,
            "fusion_case": 3,

            # Ces champs seront gardés seulement s'ils existent dans Alert.
            "asset_ip": dest_ip,
            "asset_name": agent.get("name", ""),
            "asset_criticality": 5.0,

            "raw_event": raw_payload,
            "raw_payload": raw_payload,

            "timestamp": timestamp,
            "detected_at": timestamp,
        }

        return Alert(**self._safe_alert_kwargs(kwargs))

    def _safe_int(self, value: Any) -> Optional[int]:
        try:
            if value is None or value == "":
                return None
            return int(value)
        except Exception:
            return None

    # ========================================================
    # DB
    # ========================================================
    async def _store_alerts(self, events: list[Dict[str, Any]]) -> int:
        if not events:
            return 0

        inserted = 0

        async with AsyncSessionLocal() as db:
            try:
                for event in events:
                    key = self._dedup_key(event)

                    if key in self._seen_keys:
                        continue

                    self._seen_keys.add(key)

                    if len(self._seen_keys) > 5000:
                        self._seen_keys = set(list(self._seen_keys)[-3000:])

                    alert = self._wazuh_to_alert(event)
                    db.add(alert)
                    inserted += 1

                if inserted:
                    await db.commit()

            except Exception as exc:
                await db.rollback()
                logger.exception("Erreur insertion alertes Wazuh: %s", exc)

        return inserted

    # ========================================================
    # Lifecycle
    # ========================================================
    async def start(self) -> None:
        self._running = True

        logger.info(
            "Wazuh consumer démarré | api=%s | file=%s | poll=%ss | local_asset_ip=%s",
            self.api_url,
            self.alerts_file,
            self.poll_interval,
            self.local_asset_ip or "non défini",
        )

        await self._get_token()

        while self._running:
            try:
                events = await self._fetch_alerts()
                inserted = await self._store_alerts(events)

                logger.info(
                    "%s alertes Wazuh récupérées, %s insérées",
                    len(events),
                    inserted,
                )

            except asyncio.CancelledError:
                raise

            except Exception as exc:
                logger.exception("Erreur boucle Wazuh consumer: %s", exc)

            await asyncio.sleep(self.poll_interval)

    async def stop(self) -> None:
        self._running = False
        logger.info("Arrêt Wazuh consumer demandé")