# ============================================================
# M2 — Extraction des features réseau
# Input  : flux réseau brut (dict depuis eve.json ou PCAP)
# Output : vecteur numpy de 29 features effectives
#
# Version corrigée v2 :
#   - REDUNDANT_FEATURES définies ici (source unique de vérité)
#   - EFFECTIVE_FEATURES / EFFECTIVE_FEATURE_DIM exportés
#     → utilisés par preprocessor.py, anomaly_models.py, ensemble.py
#   - extract_features_from_eve / extract_features_from_cicids
#     retournent directement 29 features (plus 33)
#   - packet_len_std et flow_iat_std ne sont plus forcés à 0.0
#     dans Eve : on utilise une approximation réaliste
# ============================================================

import numpy as np
import pandas as pd
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# ── Liste complète des 33 features brutes ──────────────────
_ALL_FEATURE_NAMES = [
    "flow_duration",
    "fwd_packet_count",
    "bwd_packet_count",
    "fwd_bytes_total",
    "bwd_bytes_total",
    "packet_len_mean",
    "packet_len_std",
    "packet_len_max",
    "flow_iat_mean",
    "flow_iat_std",
    "syn_flag",
    "ack_flag",
    "fin_flag",
    "rst_flag",
    "active_mean",
    "idle_mean",
    "down_up_ratio",
    "subflow_fwd_bytes",    # ← redondant avec fwd_bytes_total
    "subflow_bwd_bytes",    # ← redondant avec bwd_bytes_total
    "dst_port_category",
    "dst_port_raw",
    "flow_packets_total",
    "flow_bytes_total",     # ← = fwd + bwd (combinaison linéaire)
    "bytes_per_sec",
    "packets_per_sec",
    "fwd_pkt_ratio",
    "bwd_pkt_ratio",        # ← = 1 - fwd_pkt_ratio (toujours)
    "avg_bytes_per_packet",
    "is_ssh_port",
    "is_ftp_port",
    "syn_ack_ratio",
    "flow_duration_log",
    "packets_per_sec_log",
]

# ── Features redondantes à exclure ─────────────────────────
# Justification :
#   subflow_fwd/bwd_bytes : copiés directement de fwd/bwd_bytes_total
#   flow_bytes_total      : fwd_bytes_total + bwd_bytes_total (linéaire)
#   bwd_pkt_ratio         : 1 - fwd_pkt_ratio (toujours, apport nul)
REDUNDANT_FEATURES = {
    "subflow_fwd_bytes",
    "subflow_bwd_bytes",
    "flow_bytes_total",
    "bwd_pkt_ratio",
}

# ── Features effectives : source unique de vérité ──────────
FEATURE_NAMES = [f for f in _ALL_FEATURE_NAMES if f not in REDUNDANT_FEATURES]
FEATURE_DIM   = len(FEATURE_NAMES)   # 29

# Alias explicites pour les imports externes
EFFECTIVE_FEATURES    = FEATURE_NAMES
EFFECTIVE_FEATURE_DIM = FEATURE_DIM

# Indices des features effectives dans le vecteur brut 33D
_EFFECTIVE_IDX = [
    i for i, f in enumerate(_ALL_FEATURE_NAMES)
    if f not in REDUNDANT_FEATURES
]

assert FEATURE_DIM == 29, f"Attendu 29 features effectives, obtenu {FEATURE_DIM}"


# ── Helpers ────────────────────────────────────────────────

def encode_port_category(port: Optional[int]) -> float:
    if port is None:
        return 0.5
    if port <= 1023:
        return 0.0
    if port <= 49151:
        return 0.5
    return 1.0


def encode_port_raw(port: Optional[int]) -> float:
    if port is None:
        return 0.0
    return min(max(float(port), 0.0), 65535.0) / 65535.0


def _safe_float(val, default: float = 0.0) -> float:
    try:
        if pd.isna(val):
            return default
        return float(val)
    except Exception:
        return default


def _safe_ratio(num: float, den: float) -> float:
    den = float(den) if den is not None else 0.0
    if abs(den) < 1e-9:
        return 0.0
    return float(num) / den


def _safe_int(val, default: Optional[int] = None) -> Optional[int]:
    try:
        if pd.isna(val):
            return default
        return int(val)
    except Exception:
        return default


def _select_effective(full_vec: np.ndarray) -> np.ndarray:
    """Sélectionne les 29 features effectives depuis un vecteur 33D."""
    return full_vec[_EFFECTIVE_IDX]


# ── Extraction depuis Eve JSON (Suricata) ──────────────────

def extract_features_from_eve(event: dict) -> Optional[np.ndarray]:
    """
    Extrait 29 features effectives depuis un événement Eve JSON Suricata.

    Notes sur les approximations Eve :
    - packet_len_std  : Eve ne fournit pas la std par paquet.
      On approxime par avg_bytes_per_packet * 0.3 (heuristique
      basée sur la variabilité typique du trafic HTTP/TCP).
      C'est une approximation — ne pas interpréter sa valeur absolue.
    - flow_iat_std    : non disponible dans Eve.
      On approxime par flow_iat_mean * 0.5.
    - active_mean     : approché par flow_duration (durée totale).
    - idle_mean       : non disponible → 0.0.
    """
    try:
        flow = event.get("flow", {}) or {}
        tcp  = event.get("tcp",  {}) or {}

        duration  = _safe_float(flow.get("duration", 0), 0.0)
        fwd_pkts  = _safe_float(flow.get("pkts_toserver", 0), 0.0)
        bwd_pkts  = _safe_float(flow.get("pkts_toclient", 0), 0.0)
        fwd_bytes = _safe_float(flow.get("bytes_toserver", 0), 0.0)
        bwd_bytes = _safe_float(flow.get("bytes_toclient", 0), 0.0)

        total_pkts  = fwd_pkts + bwd_pkts
        total_bytes = fwd_bytes + bwd_bytes
        dst_port    = _safe_int(event.get("dest_port"), None)

        syn_flag = 1.0 if tcp.get("syn") else 0.0
        ack_flag = 1.0 if tcp.get("ack") else 0.0
        fin_flag = 1.0 if tcp.get("fin") else 0.0
        rst_flag = 1.0 if tcp.get("rst") else 0.0

        packets_per_sec      = _safe_ratio(total_pkts,  max(duration, 1e-6))
        bytes_per_sec        = _safe_ratio(total_bytes,  max(duration, 1e-6))
        avg_bytes_per_packet = _safe_ratio(total_bytes,  max(total_pkts, 1.0))

        # Approximations réalistes (mieux que 0.0 constant)
        packet_len_mean = avg_bytes_per_packet
        packet_len_std  = avg_bytes_per_packet * 0.3   # heuristique ~30% de la moyenne
        packet_len_max  = avg_bytes_per_packet * 1.5   # heuristique max ~ 1.5× moyenne

        flow_iat_mean = _safe_ratio(duration, max(total_pkts, 1.0))
        flow_iat_std  = flow_iat_mean * 0.5             # heuristique

        syn_ack_ratio = _safe_ratio(syn_flag, ack_flag if ack_flag > 0 else 1.0)
        fwd_pkt_ratio = _safe_ratio(fwd_pkts, max(total_pkts, 1.0))

        # Vecteur complet 33 features (ordre = _ALL_FEATURE_NAMES)
        full = {
            "flow_duration":       duration,
            "fwd_packet_count":    fwd_pkts,
            "bwd_packet_count":    bwd_pkts,
            "fwd_bytes_total":     fwd_bytes,
            "bwd_bytes_total":     bwd_bytes,
            "packet_len_mean":     packet_len_mean,
            "packet_len_std":      packet_len_std,
            "packet_len_max":      packet_len_max,
            "flow_iat_mean":       flow_iat_mean,
            "flow_iat_std":        flow_iat_std,
            "syn_flag":            syn_flag,
            "ack_flag":            ack_flag,
            "fin_flag":            fin_flag,
            "rst_flag":            rst_flag,
            "active_mean":         duration,
            "idle_mean":           0.0,
            "down_up_ratio":       _safe_ratio(bwd_bytes, max(fwd_bytes, 1.0)),
            "subflow_fwd_bytes":   fwd_bytes,   # redondant → sera retiré
            "subflow_bwd_bytes":   bwd_bytes,   # redondant → sera retiré
            "dst_port_category":   encode_port_category(dst_port),
            "dst_port_raw":        encode_port_raw(dst_port),
            "flow_packets_total":  total_pkts,
            "flow_bytes_total":    total_bytes,  # redondant → sera retiré
            "bytes_per_sec":       bytes_per_sec,
            "packets_per_sec":     packets_per_sec,
            "fwd_pkt_ratio":       fwd_pkt_ratio,
            "bwd_pkt_ratio":       1.0 - fwd_pkt_ratio,  # redondant → sera retiré
            "avg_bytes_per_packet": avg_bytes_per_packet,
            "is_ssh_port":         1.0 if dst_port == 22 else 0.0,
            "is_ftp_port":         1.0 if dst_port == 21 else 0.0,
            "syn_ack_ratio":       syn_ack_ratio,
            "flow_duration_log":   float(np.log1p(max(duration, 0.0))),
            "packets_per_sec_log": float(np.log1p(max(packets_per_sec, 0.0))),
        }

        full_vec = np.array([full[f] for f in _ALL_FEATURE_NAMES], dtype=np.float32)
        return _select_effective(full_vec)   # → 29 features

    except Exception as e:
        logger.error("Erreur extraction features Eve: %s", e, exc_info=True)
        return None


# ── Extraction depuis CIC-IDS-2017 ─────────────────────────

def extract_features_from_cicids(row: pd.Series) -> Optional[np.ndarray]:
    """
    Extrait 29 features effectives depuis une ligne CIC-IDS-2017.

    Conversions :
    - Flow Duration / IAT / Active / Idle : microsecondes → secondes
    """
    try:
        fwd_pkts  = _safe_float(row.get("Total Fwd Packets", 0), 0.0)
        bwd_pkts  = _safe_float(row.get("Total Backward Packets", 0), 0.0)
        fwd_bytes = _safe_float(row.get("Total Length of Fwd Packets", 0), 0.0)
        bwd_bytes = _safe_float(row.get("Total Length of Bwd Packets", 0), 0.0)

        duration_us = _safe_float(row.get("Flow Duration", 0), 0.0)
        duration    = duration_us / 1_000_000.0

        flow_iat_mean = _safe_float(row.get("Flow IAT Mean", 0), 0.0) / 1_000_000.0
        flow_iat_std  = _safe_float(row.get("Flow IAT Std",  0), 0.0) / 1_000_000.0
        active_mean   = _safe_float(row.get("Active Mean",   0), 0.0) / 1_000_000.0
        idle_mean     = _safe_float(row.get("Idle Mean",     0), 0.0) / 1_000_000.0

        dst_port    = _safe_int(row.get("Destination Port", None), None)
        total_pkts  = fwd_pkts + bwd_pkts
        total_bytes = fwd_bytes + bwd_bytes

        bytes_per_sec = _safe_float(row.get("Flow Bytes/s", np.nan), np.nan)
        if np.isnan(bytes_per_sec):
            bytes_per_sec = _safe_ratio(total_bytes, max(duration, 1e-6))

        packets_per_sec = _safe_float(row.get("Flow Packets/s", np.nan), np.nan)
        if np.isnan(packets_per_sec):
            packets_per_sec = _safe_ratio(total_pkts, max(duration, 1e-6))

        syn_flag = _safe_float(row.get("SYN Flag Count", 0), 0.0)
        ack_flag = _safe_float(row.get("ACK Flag Count", 0), 0.0)
        fin_flag = _safe_float(row.get("FIN Flag Count", 0), 0.0)
        rst_flag = _safe_float(row.get("RST Flag Count", 0), 0.0)

        avg_bytes_per_packet = _safe_ratio(total_bytes, max(total_pkts, 1.0))
        syn_ack_ratio        = _safe_ratio(syn_flag, ack_flag if ack_flag > 0 else 1.0)
        fwd_pkt_ratio        = _safe_ratio(fwd_pkts, max(total_pkts, 1.0))

        full = {
            "flow_duration":       duration,
            "fwd_packet_count":    fwd_pkts,
            "bwd_packet_count":    bwd_pkts,
            "fwd_bytes_total":     fwd_bytes,
            "bwd_bytes_total":     bwd_bytes,
            "packet_len_mean":     _safe_float(row.get("Packet Length Mean", 0), 0.0),
            "packet_len_std":      _safe_float(row.get("Packet Length Std",  0), 0.0),
            "packet_len_max":      _safe_float(row.get("Packet Length Max",  0), 0.0),
            "flow_iat_mean":       flow_iat_mean,
            "flow_iat_std":        flow_iat_std,
            "syn_flag":            syn_flag,
            "ack_flag":            ack_flag,
            "fin_flag":            fin_flag,
            "rst_flag":            rst_flag,
            "active_mean":         active_mean,
            "idle_mean":           idle_mean,
            "down_up_ratio":       _safe_float(row.get("Down/Up Ratio", 0), 0.0),
            "subflow_fwd_bytes":   _safe_float(row.get("Subflow Fwd Bytes", fwd_bytes), fwd_bytes),
            "subflow_bwd_bytes":   _safe_float(row.get("Subflow Bwd Bytes", bwd_bytes), bwd_bytes),
            "dst_port_category":   encode_port_category(dst_port),
            "dst_port_raw":        encode_port_raw(dst_port),
            "flow_packets_total":  total_pkts,
            "flow_bytes_total":    total_bytes,
            "bytes_per_sec":       bytes_per_sec,
            "packets_per_sec":     packets_per_sec,
            "fwd_pkt_ratio":       fwd_pkt_ratio,
            "bwd_pkt_ratio":       1.0 - fwd_pkt_ratio,
            "avg_bytes_per_packet": avg_bytes_per_packet,
            "is_ssh_port":         1.0 if dst_port == 22 else 0.0,
            "is_ftp_port":         1.0 if dst_port == 21 else 0.0,
            "syn_ack_ratio":       syn_ack_ratio,
            "flow_duration_log":   float(np.log1p(max(duration, 0.0))),
            "packets_per_sec_log": float(np.log1p(max(packets_per_sec, 0.0))),
        }

        full_vec = np.array([full[f] for f in _ALL_FEATURE_NAMES], dtype=np.float32)
        return _select_effective(full_vec)   # → 29 features

    except Exception as e:
        logger.error("Erreur extraction features CICIDS: %s", e, exc_info=True)
        return None