// ============================================================
// Hook useWebSocket — connexion temps réel M9
// Reconnexion automatique si déconnecté
// Supporte enabled pour activer / désactiver la connexion
// ============================================================

import { useEffect, useRef, useState, useCallback } from "react";
import { WSMessage } from "../types";
import { createWebSocket, WS_BASE, WSChannel } from "../services/websocket";

interface UseWebSocketOptions {
  channel?: WSChannel;
  onMessage?: (msg: WSMessage) => void;
  reconnectDelay?: number;
  enabled?: boolean;
}

export function useWebSocket({
  channel = "alerts",
  onMessage,
  reconnectDelay = 3000,
  enabled = true,
}: UseWebSocketOptions = {}) {
  const ws = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(false);

  const clearReconnectTimer = useCallback(() => {
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current);
      reconnectTimer.current = null;
    }
  }, []);

  const cleanupSocket = useCallback(() => {
    if (ws.current) {
      ws.current.onopen = null;
      ws.current.onmessage = null;
      ws.current.onclose = null;
      ws.current.onerror = null;

      if (
        ws.current.readyState === WebSocket.OPEN ||
        ws.current.readyState === WebSocket.CONNECTING
      ) {
        ws.current.close();
      }

      ws.current = null;
    }

    setConnected(false);
  }, []);

  const connect = useCallback(() => {
    if (!mountedRef.current || !enabled) return;

    if (
      ws.current &&
      (ws.current.readyState === WebSocket.OPEN ||
        ws.current.readyState === WebSocket.CONNECTING)
    ) {
      return;
    }

    clearReconnectTimer();

    try {
      const url = `${WS_BASE}/${channel}`;
      const socket = createWebSocket(channel);
      ws.current = socket;

      socket.onopen = () => {
        if (!mountedRef.current || !enabled) return;
        setConnected(true);
        console.log(`[WS] connecté → ${url}`);
      };

      socket.onmessage = (event) => {
        if (!mountedRef.current || !enabled) return;

        try {
          const msg: WSMessage = JSON.parse(event.data);
          setLastMessage(msg);
          onMessage?.(msg);
        } catch (e) {
          console.error("[WS] message JSON invalide:", e, event.data);
        }
      };

      socket.onclose = (event) => {
        if (!mountedRef.current) return;

        setConnected(false);
        ws.current = null;

        if (!enabled) return;

        console.warn(
          `[WS] déconnecté → ${url} | code=${event.code} | reason=${event.reason || "n/a"} | reconnexion dans ${reconnectDelay}ms`
        );

        reconnectTimer.current = setTimeout(() => {
          connect();
        }, reconnectDelay);
      };

      socket.onerror = (error) => {
        console.error(`[WS] erreur → ${url}`, error);
      };
    } catch (e) {
      console.error(`[WS] connexion impossible → ${channel}`, e);

      if (mountedRef.current && enabled) {
        reconnectTimer.current = setTimeout(() => {
          connect();
        }, reconnectDelay);
      }
    }
  }, [channel, enabled, reconnectDelay, onMessage, clearReconnectTimer]);

  useEffect(() => {
    mountedRef.current = true;

    if (!enabled) {
      clearReconnectTimer();
      cleanupSocket();

      return () => {
        mountedRef.current = false;
        clearReconnectTimer();
        cleanupSocket();
      };
    }

    connect();

    return () => {
      mountedRef.current = false;
      clearReconnectTimer();
      cleanupSocket();
    };
  }, [enabled, connect, clearReconnectTimer, cleanupSocket]);

  return { connected, lastMessage };
}