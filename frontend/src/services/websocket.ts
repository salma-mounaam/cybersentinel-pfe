export const WS_BASE =
  process.env.REACT_APP_WS_URL?.replace(/\/$/, "") ||
  `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.hostname}:8000/ws`;

export type WSChannel = "alerts" | "incidents" | "critical" | "all";

export function createWebSocket(channel: WSChannel): WebSocket {
  return new WebSocket(`${WS_BASE}/${channel}`);
}