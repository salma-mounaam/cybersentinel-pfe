# ============================================================
# CyberSentinel — Point d'entrée FastAPI
# ============================================================

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import init_db

# ---- Routers API ----
from app.api import alerts, ml, fusion, mitre, incidents, scoring, sast, dast, cicd
from app.api import websocket as ws_router
from app.api import hids as hids_router
from app.api import wazuh
from app.api import assets as assets_router
from app.api import agents as agents_router

# ---- Routers supplémentaires ----
from app.api.reports import router as reports_router
from app.api.vulnerability_llm import router as vulnerability_llm_router

# ---- Services background ----
from app.services.suricata_service import SuricataEveWatcher
from app.services.incident_consumer import IncidentConsumer
from app.services.redis_ws_bridge import redis_ws_bridge
from app.services.wazuh_service import WazuhConsumer

# ============================================================
# Logging
# ============================================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cybersentinel")

# ============================================================
# Instances services background
# ============================================================

watcher = SuricataEveWatcher()
consumer = IncidentConsumer()
wazuh_consumer = WazuhConsumer()

# Références des tâches asyncio
watcher_task: Optional[asyncio.Task] = None
consumer_task: Optional[asyncio.Task] = None
wazuh_task: Optional[asyncio.Task] = None
redis_bridge_task: Optional[asyncio.Task] = None
purge_task: Optional[asyncio.Task] = None


# ============================================================
# M11 — Purge hebdomadaire Wazuh
# ============================================================

async def weekly_db_purge(consumer: WazuhConsumer):
    """
    Purge hebdomadaire des alertes Wazuh.
    Première purge après 1h de démarrage, puis toutes les semaines.

    Pour tester rapidement :
    remplacer 3600 par 60.
    """
    await asyncio.sleep(3600)

    while True:
        try:
            deleted = await consumer.purge_old_alerts()
            logger.info(
                "🧹 Purge hebdomadaire terminée : %s alertes Wazuh supprimées",
                deleted,
            )

        except asyncio.CancelledError:
            logger.info("🧹 Tâche purge hebdomadaire Wazuh annulée")
            raise

        except Exception as e:
            logger.error("Erreur purge hebdomadaire : %s", e)

        await asyncio.sleep(7 * 24 * 3600)


# ============================================================
# Lifecycle
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    global watcher_task
    global consumer_task
    global wazuh_task
    global redis_bridge_task
    global purge_task

    logger.info("🚀 CyberSentinel démarrage...")

    # M12 — Rend le watcher Suricata disponible pour l'ingestion distante
    # utilisée par POST /api/agents/events.
    app.state.suricata_watcher = watcher

    # Initialisation base de données
    await init_db()
    logger.info("✅ Base de données initialisée")

    try:
        # M1 — Watcher Suricata local
        watcher_task = asyncio.create_task(
            watcher.start(),
            name="suricata-watcher",
        )
        logger.info("👁️ Suricata Eve watcher démarré")

        # M7 — Consommateur incidents
        consumer_task = asyncio.create_task(
            consumer.start(),
            name="incident-consumer",
        )
        logger.info("📥 Incident consumer démarré")

        # M9 — Bridge Redis -> WebSocket
        redis_bridge_task = asyncio.create_task(
            redis_ws_bridge.start(),
            name="redis-ws-bridge",
        )
        logger.info("🌉 Redis→WebSocket bridge démarré")

        # M11 — Wazuh Consumer
        wazuh_task = asyncio.create_task(
            wazuh_consumer.start(),
            name="wazuh-consumer",
        )
        logger.info("🛡️ Wazuh consumer démarré")

        # M11 — Purge hebdomadaire Wazuh
        purge_task = asyncio.create_task(
            weekly_db_purge(wazuh_consumer),
            name="weekly-db-purge",
        )
        logger.info("🧹 Purge hebdomadaire Wazuh planifiée (rétention 7 jours)")

        yield

    finally:
        logger.info("🛑 Arrêt des services background...")

        # Arrêt propre des services
        try:
            await watcher.stop()
        except Exception as e:
            logger.warning("Erreur arrêt watcher: %s", e)

        try:
            await consumer.stop()
        except Exception as e:
            logger.warning("Erreur arrêt consumer: %s", e)

        try:
            await wazuh_consumer.stop()
        except Exception as e:
            logger.warning("Erreur arrêt wazuh_consumer: %s", e)

        try:
            await redis_ws_bridge.stop()
        except Exception as e:
            logger.warning("Erreur arrêt redis_ws_bridge: %s", e)

        # Annulation des tâches encore actives
        tasks = [
            watcher_task,
            consumer_task,
            wazuh_task,
            redis_bridge_task,
            purge_task,
        ]

        for task in tasks:
            if task and not task.done():
                task.cancel()

        # Attendre leur terminaison sans bloquer l'arrêt global
        pending = [task for task in tasks if task is not None]

        if pending:
            results = await asyncio.gather(
                *pending,
                return_exceptions=True,
            )

            for result in results:
                if isinstance(result, Exception) and not isinstance(
                    result,
                    asyncio.CancelledError,
                ):
                    logger.warning(
                        "Erreur fermeture tâche background: %s",
                        result,
                    )

        logger.info("✅ CyberSentinel arrêté proprement")


# ============================================================
# Application
# ============================================================

app = FastAPI(
    title="CyberSentinel API",
    description="Plateforme Purple Team — Détection Zero-Day & Priorisation des Menaces",
    version="2.0.0",
    lifespan=lifespan,
)

# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# Routers REST
# ============================================================

app.include_router(
    alerts.router,
    prefix="/api/alerts",
    tags=["M1 — IDS Alerts"],
)

app.include_router(
    ml.router,
    prefix="/api/ml",
    tags=["M2/M10 — ML"],
)

app.include_router(
    fusion.router,
    prefix="/api/fusion",
    tags=["M3 — Fusion Hybride"],
)

app.include_router(
    mitre.router,
    prefix="/api/mitre",
    tags=["M6 — Enrichissement MITRE"],
)

app.include_router(
    incidents.router,
    prefix="/api/incidents",
    tags=["M7 — Incidents"],
)

app.include_router(
    scoring.router,
    prefix="/api/scoring",
    tags=["M7 — Scoring"],
)

app.include_router(
    sast.router,
    prefix="/api/sast",
    tags=["M4 — SAST"],
)

app.include_router(
    dast.router,
    prefix="/api/dast",
    tags=["M5 — DAST"],
)

app.include_router(
    cicd.router,
    prefix="/api/cicd",
    tags=["M8 — CI/CD"],
)

app.include_router(
    reports_router,
    prefix="/api/reports",
    tags=["M11 — Rapports"],
)

app.include_router(
    wazuh.router,
    prefix="/api/wazuh",
    tags=["M11 — Wazuh"],
)

app.include_router(
    hids_router.router,
    prefix="/api/hids",
    tags=["M11 — HIDS"],
)

# ============================================================
# M12 — Asset Registry / Multi-Machine
# Routes créées :
# GET    /api/assets
# POST   /api/assets
# PATCH  /api/assets/{asset_id}
# GET    /api/assets/at-risk
# POST   /api/agents/heartbeat
# GET    /api/agents/status
# POST   /api/agents/events
# ============================================================

app.include_router(
    agents_router.router,
    prefix="/api",
    tags=["M12 — Agents Heartbeat"],
)

app.include_router(
    assets_router.router,
    prefix="/api",
    tags=["M12 — Assets"],
)

app.include_router(
    vulnerability_llm_router,
    prefix="/api",
    tags=["M12 — LLM Vulnerabilities"],
)

# ============================================================
# Routers WebSocket
# ============================================================

app.include_router(
    ws_router.router,
    prefix="/ws",
    tags=["M9 — WebSocket"],
)

# ============================================================
# Endpoints système
# ============================================================

@app.get("/")
async def root():
    return {
        "message": "CyberSentinel API running",
        "service": "CyberSentinel",
        "version": "2.0.0",
        "modules": {
            "M1": "Suricata IDS",
            "M2": "Machine Learning",
            "M3": "Fusion Hybride",
            "M4": "SAST",
            "M5": "DAST",
            "M6": "MITRE ATT&CK",
            "M7": "Incidents & Scoring",
            "M8": "CI/CD Security",
            "M9": "WebSocket temps réel",
            "M10": "ML avancé",
            "M11": "Wazuh HIDS",
            "M12": "Asset Registry, Agents Heartbeat & LLM Vulnerability Analysis",
        },
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "CyberSentinel",
        "version": "2.0.0",
        "background_services": {
            "suricata_watcher": watcher_task is not None and not watcher_task.done(),
            "incident_consumer": consumer_task is not None and not consumer_task.done(),
            "wazuh_consumer": wazuh_task is not None and not wazuh_task.done(),
            "redis_ws_bridge": redis_bridge_task is not None and not redis_bridge_task.done(),
            "wazuh_weekly_purge": purge_task is not None and not purge_task.done(),
        },
        "modules": {
            "asset_registry": "enabled",
            "agents_heartbeat": "enabled",
            "remote_suricata_ingest": "enabled",
            "wazuh": "enabled",
            "hids": "enabled",
            "llm_vulnerability_analysis": "enabled",
        },
    }