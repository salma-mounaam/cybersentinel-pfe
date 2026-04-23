# ============================================================
# M9 — Bridge Redis Pub/Sub → WebSocket
# Écoute les channels Redis et broadcast vers les clients React
# C'est le composant qui garantit la latence < 2s (CA07)
# ============================================================

import asyncio
import json
import logging
from typing import Optional

import redis.asyncio as aioredis

from app.core.config import settings
from app.services.websocket_manager import ws_manager

logger = logging.getLogger(__name__)

# Mapping channel Redis → channel WebSocket
REDIS_TO_WS_CHANNEL = {
    "channel:alerts":    "alerts",
    "channel:incidents": "incidents",
    "channel:critical":  "critical",
}


class RedisWebSocketBridge:
    """
    Écoute les channels Redis Pub/Sub et forward
    les messages vers les clients WebSocket connectés.
    """

    def __init__(self):
        self.redis: Optional[aioredis.Redis] = None
        self._running = False

    async def start(self):
        self.redis = await aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )
        self._running = True
        logger.info("🌉 Redis→WebSocket bridge démarré")
        await self._listen()

    async def stop(self):
        self._running = False
        if self.redis:
            await self.redis.aclose()

    async def _listen(self):
        """Boucle principale d'écoute Redis Pub/Sub."""
        pubsub = self.redis.pubsub()

        # S'abonner à tous les channels
        await pubsub.subscribe(*REDIS_TO_WS_CHANNEL.keys())
        logger.info(
            f"Abonné aux channels Redis : "
            f"{list(REDIS_TO_WS_CHANNEL.keys())}"
        )

        async for message in pubsub.listen():
            if not self._running:
                break

            if message["type"] != "message":
                continue

            redis_channel = message["channel"]
            ws_channel = REDIS_TO_WS_CHANNEL.get(redis_channel, "all")

            try:
                data = json.loads(message["data"])

                # Ajouter le type de message pour le frontend
                data["_channel"] = ws_channel
                data["_source"]  = "cybersentinel"

                # Broadcast vers les clients WebSocket
                await ws_manager.broadcast(data, ws_channel)
                await ws_manager.broadcast(data, "all")

                logger.debug(
                    f"Bridge: {redis_channel} → WS:{ws_channel} | "
                    f"clients={len(ws_manager.connections.get(ws_channel, set()))}"
                )

            except json.JSONDecodeError:
                logger.warning(f"Message Redis invalide: {message['data'][:100]}")
            except Exception as e:
                logger.error(f"Erreur bridge: {e}")


# Singleton global
redis_ws_bridge = RedisWebSocketBridge()
