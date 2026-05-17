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

# ---- Services background ----
from app.services.suricata_service import SuricataEveWatcher
from app.services.incident_consumer import IncidentConsumer
from app.services.redis_ws_bridge import redis_ws_bridge
from app.api.reports import router as reports_router
from app.api.vulnerability_llm import router as vulnerability_llm_router
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cybersentinel")

watcher = SuricataEveWatcher()
consumer = IncidentConsumer()

# Références des tâches asyncio
watcher_task: Optional[asyncio.Task] = None
consumer_task: Optional[asyncio.Task] = None
redis_bridge_task: Optional[asyncio.Task] = None


# ============================================================
# Lifecycle
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global watcher_task, consumer_task, redis_bridge_task

    logger.info("🚀 CyberSentinel démarrage...")

    # Initialisation base de données
    await init_db()
    logger.info("✅ Base de données initialisée")

    try:
        # M1 — Watcher Suricata
        watcher_task = asyncio.create_task(
            watcher.start(),
            name="suricata-watcher"
        )
        logger.info("👁️ Suricata Eve watcher démarré")

        # M7 — Consommateur incidents
        consumer_task = asyncio.create_task(
            consumer.start(),
            name="incident-consumer"
        )
        logger.info("📥 Incident consumer démarré")

        # M9 — Bridge Redis -> WebSocket
        redis_bridge_task = asyncio.create_task(
            redis_ws_bridge.start(),
            name="redis-ws-bridge"
        )
        logger.info("🌉 Redis→WebSocket bridge démarré")

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
            await redis_ws_bridge.stop()
        except Exception as e:
            logger.warning("Erreur arrêt redis_ws_bridge: %s", e)

        # Annulation des tâches encore actives
        tasks = [watcher_task, consumer_task, redis_bridge_task]
        for task in tasks:
            if task and not task.done():
                task.cancel()

        # Attendre leur terminaison sans bloquer l'arrêt global
        pending = [task for task in tasks if task is not None]
        if pending:
            results = await asyncio.gather(*pending, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception) and not isinstance(result, asyncio.CancelledError):
                    logger.warning("Erreur fermeture tâche background: %s", result)

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
app.include_router(alerts.router, prefix="/api/alerts", tags=["M1 — IDS Alerts"])
app.include_router(ml.router, prefix="/api/ml", tags=["M2/M10 — ML"])
app.include_router(fusion.router, prefix="/api/fusion", tags=["M3 — Fusion Hybride"])
app.include_router(mitre.router, prefix="/api/mitre", tags=["M6 — Enrichissement MITRE"])
app.include_router(incidents.router, prefix="/api/incidents", tags=["M7 — Incidents"])
app.include_router(scoring.router, prefix="/api/scoring", tags=["M7 — Scoring"])
app.include_router(sast.router, prefix="/api/sast", tags=["M4 — SAST"])
app.include_router(dast.router, prefix="/api/dast", tags=["M5 — DAST"])
app.include_router(cicd.router, prefix="/api/cicd", tags=["M8 — CI/CD"])
app.include_router(reports_router, prefix="/api/reports", tags=["M11 — Rapports"])
app.include_router(vulnerability_llm_router, prefix="/api", tags=["M12 — LLM Vulnerabilities"])
# ============================================================
# Routers WebSocket
# ============================================================
app.include_router(ws_router.router, prefix="/ws", tags=["M9 — WebSocket"])

# ============================================================
# Endpoints système
# ============================================================
@app.get("/")
async def root():
    return {
        "message": "CyberSentinel API running",
        "service": "CyberSentinel",
        "version": "2.0.0",
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "CyberSentinel",
        "version": "2.0.0",
    }