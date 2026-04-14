# ============================================================
# M9 — WebSocket Manager
# Gère toutes les connexions clients React
# Distribue les alertes/incidents en temps réel < 2s
# ============================================================

import asyncio
import json
import logging
from typing import Dict, Set
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    Gestionnaire de connexions WebSocket.
    Maintient la liste des clients connectés et
    broadcast les messages à tous simultanément.
    """

    def __init__(self):
        # Connexions actives par channel
        self.connections: Dict[str, Set[WebSocket]] = {
            "alerts":    set(),
            "incidents": set(),
            "critical":  set(),
            "all":       set(),
        }

    async def connect(self, websocket: WebSocket, channel: str = "all"):
        """Accepte une nouvelle connexion WebSocket."""
        await websocket.accept()
        self.connections.setdefault(channel, set()).add(websocket)
        self.connections["all"].add(websocket)
        logger.info(
            f"WebSocket connecté | channel={channel} | "
            f"total={len(self.connections['all'])}"
        )

    def disconnect(self, websocket: WebSocket, channel: str = "all"):
        """Retire une connexion déconnectée."""
        self.connections.get(channel, set()).discard(websocket)
        self.connections["all"].discard(websocket)
        logger.info(
            f"WebSocket déconnecté | "
            f"total={len(self.connections['all'])}"
        )

    async def broadcast(self, message: dict, channel: str = "all"):
        """
        Envoie un message à tous les clients du channel.
        Retire automatiquement les connexions mortes.
        """
        dead = set()
        targets = self.connections.get(channel, set()).copy()

        for websocket in targets:
            try:
                await websocket.send_json(message)
            except Exception:
                dead.add(websocket)

        # Nettoyer les connexions mortes
        for ws in dead:
            self.disconnect(ws, channel)

    async def send_personal(self, websocket: WebSocket, message: dict):
        """Envoie un message à un client spécifique."""
        try:
            await websocket.send_json(message)
        except Exception:
            self.disconnect(websocket)

    def get_stats(self) -> dict:
        return {
            "total_connections": len(self.connections["all"]),
            "alerts_channel":    len(self.connections.get("alerts", set())),
            "incidents_channel": len(self.connections.get("incidents", set())),
            "critical_channel":  len(self.connections.get("critical", set())),
        }


# Singleton global
ws_manager = WebSocketManager()
