# ============================================================
# M9 — Endpoints WebSocket
# ============================================================

import asyncio
import json
import logging

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.config import settings
from app.services.websocket_manager import ws_manager

router = APIRouter()
logger = logging.getLogger(__name__)


async def _send_recent_alerts(websocket: WebSocket):
    """
    Envoie les 20 alertes Redis les plus récentes au moment
    de la connexion sur /ws/alerts.
    """
    redis_conn = None
    try:
        redis_conn = await aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )

        recent = await redis_conn.zrevrange("alerts:recent", 0, 19)

        for raw in recent:
            try:
                alert = json.loads(raw)
                alert["_type"] = "historical"
                await ws_manager.send_personal(websocket, alert)
            except Exception as e:
                logger.warning("Impossible d'envoyer une alerte historique: %s", e)

    except Exception as e:
        logger.error("Erreur récupération alertes récentes Redis: %s", e, exc_info=True)

    finally:
        if redis_conn:
            try:
                await redis_conn.aclose()
            except Exception:
                pass


async def _keep_alive_loop(websocket: WebSocket, channel: str):
    """
    Boucle keep-alive simple.
    On attend les messages client, mais si le client n'envoie rien,
    on garde quand même la connexion vivante.
    """
    while True:
        try:
            message = await asyncio.wait_for(websocket.receive_text(), timeout=30)

            # Petit protocole minimal
            if message.lower() == "ping":
                await ws_manager.send_personal(websocket, {"_type": "pong", "channel": channel})
            elif message.lower() == "stats":
                await ws_manager.send_personal(websocket, {
                    "_type": "stats",
                    "channel": channel,
                    "stats": ws_manager.get_stats()
                })
            else:
                await ws_manager.send_personal(websocket, {
                    "_type": "ack",
                    "channel": channel,
                    "message": "message reçu"
                })

        except asyncio.TimeoutError:
            # Ping serveur -> client pour garder la socket active
            await ws_manager.send_personal(websocket, {
                "_type": "ping",
                "channel": channel
            })


@router.websocket("/alerts")
async def ws_alerts(websocket: WebSocket):
    """
    WebSocket pour les alertes IDS temps réel.
    Utilisé par les pages Overview et IDS Monitor M9.
    """
    await ws_manager.connect(websocket, "alerts")

    try:
        await ws_manager.send_personal(websocket, {
            "_type": "connected",
            "channel": "alerts",
            "message": "Canal alertes connecté"
        })

        await _send_recent_alerts(websocket)
        await _keep_alive_loop(websocket, "alerts")

    except WebSocketDisconnect:
        logger.info("WebSocket /alerts déconnecté")

    except Exception as e:
        logger.error("Erreur WebSocket /alerts: %s", e, exc_info=True)

    finally:
        ws_manager.disconnect(websocket, "alerts")


@router.websocket("/incidents")
async def ws_incidents(websocket: WebSocket):
    """
    WebSocket pour les incidents M7 temps réel.
    Utilisé par la page Incidents M9.
    """
    await ws_manager.connect(websocket, "incidents")

    try:
        await ws_manager.send_personal(websocket, {
            "_type": "connected",
            "channel": "incidents",
            "message": "Canal incidents connecté"
        })

        await _keep_alive_loop(websocket, "incidents")

    except WebSocketDisconnect:
        logger.info("WebSocket /incidents déconnecté")

    except Exception as e:
        logger.error("Erreur WebSocket /incidents: %s", e, exc_info=True)

    finally:
        ws_manager.disconnect(websocket, "incidents")


@router.websocket("/critical")
async def ws_critical(websocket: WebSocket):
    """
    WebSocket pour les alertes CRITIQUES uniquement.
    Déclenche les notifications urgentes dans M9.
    """
    await ws_manager.connect(websocket, "critical")

    try:
        await ws_manager.send_personal(websocket, {
            "_type": "connected",
            "channel": "critical",
            "message": "Canal critiques connecté"
        })

        await _keep_alive_loop(websocket, "critical")

    except WebSocketDisconnect:
        logger.info("WebSocket /critical déconnecté")

    except Exception as e:
        logger.error("Erreur WebSocket /critical: %s", e, exc_info=True)

    finally:
        ws_manager.disconnect(websocket, "critical")


@router.websocket("/all")
async def ws_all(websocket: WebSocket):
    """
    WebSocket global — reçoit tous les événements.
    Utilisé par le dashboard principal M9.
    """
    await ws_manager.connect(websocket, "all")

    try:
        await ws_manager.send_personal(websocket, {
            "_type": "connected",
            "channel": "all",
            "message": "CyberSentinel WebSocket connecté",
            "stats": ws_manager.get_stats()
        })

        await _keep_alive_loop(websocket, "all")

    except WebSocketDisconnect:
        logger.info("WebSocket /all déconnecté")

    except Exception as e:
        logger.error("Erreur WebSocket /all: %s", e, exc_info=True)

    finally:
        ws_manager.disconnect(websocket, "all")