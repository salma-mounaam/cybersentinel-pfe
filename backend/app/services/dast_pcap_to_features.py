# ============================================================
# app/services/dast_pcap_to_features.py
#
# Convertit les captures PCAP du module DAST (ZAP)
# en features ML compatibles avec extract_features_from_cicids.
#
# Pipeline :
#   PCAP (Scapy) → flux réseau agrégés → 29 features → numpy
#
# Ces features peuvent ensuite être injectées dans
# CICIDSPreprocessor pour enrichir le dataset d'entraînement M10.
# ============================================================

import logging
from collections import defaultdict
from pathlib import Path
from typing import Optional

import numpy as np

from app.ml.features.extractor import (
    EFFECTIVE_FEATURE_DIM,
    encode_port_category,
    encode_port_raw,
    _safe_ratio,
)

logger = logging.getLogger(__name__)

# ── Labels synthétiques pour les flux issus du DAST ──────────
# ZAP génère du trafic d'attaque connu → on peut labelliser
# selon le profil du flux (port, flags, volume)
DAST_ATTACK_LABEL = "Web Attack - ZAP"
DAST_BENIGN_LABEL = "BENIGN"


def _extract_flow_key(pkt) -> Optional[tuple]:
    """Extrait la clé de flux (src_ip, dst_ip, src_port, dst_port, proto)."""
    try:
        from scapy.layers.inet import IP, TCP, UDP
        if not pkt.haslayer(IP):
            return None
        ip    = pkt[IP]
        proto = ip.proto  # 6=TCP, 17=UDP

        src_port = dst_port = 0
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        return (ip.src, ip.dst, src_port, dst_port, proto)
    except Exception:
        return None


def pcap_to_flow_features(pcap_path: str) -> Optional[np.ndarray]:
    """
    Lit un fichier PCAP et retourne un tableau numpy (N_flux × 29 features).

    Retourne None si Scapy n'est pas disponible ou si le PCAP est vide.
    """
    try:
        from scapy.all import rdpcap
        from scapy.layers.inet import IP, TCP, UDP
    except ImportError:
        logger.warning("Scapy non disponible — captures DAST ignorées pour M10")
        return None

    path = Path(pcap_path)
    if not path.exists() or path.stat().st_size == 0:
        logger.warning("PCAP vide ou absent : %s", path)
        return None

    try:
        packets = rdpcap(str(path))
    except Exception as e:
        logger.error("Erreur lecture PCAP %s : %s", path, e)
        return None

    if not packets:
        return None

    # ── Agrégation des paquets par flux ──────────────────────
    # Un flux = (src_ip, dst_ip, src_port, dst_port, proto)
    # On collecte : timestamps, tailles, flags TCP
    flows: dict = defaultdict(lambda: {
        "timestamps": [],
        "sizes":      [],
        "syn": 0, "ack": 0, "fin": 0, "rst": 0,
        "dst_port": 0, "proto": 6,
        "fwd_pkts": 0, "bwd_pkts": 0,
        "fwd_bytes": 0, "bwd_bytes": 0,
    })

    for pkt in packets:
        key = _extract_flow_key(pkt)
        if key is None:
            continue

        src_ip, dst_ip, src_port, dst_port, proto = key
        flow = flows[key]
        flow["dst_port"] = dst_port
        flow["proto"]    = proto

        ts   = float(pkt.time)
        size = len(pkt)
        flow["timestamps"].append(ts)
        flow["sizes"].append(size)

        # Direction : on considère la première IP source comme forward
        if not flow.get("src_ip_ref"):
            flow["src_ip_ref"] = src_ip

        if src_ip == flow.get("src_ip_ref"):
            flow["fwd_pkts"]  += 1
            flow["fwd_bytes"] += size
        else:
            flow["bwd_pkts"]  += 1
            flow["bwd_bytes"] += size

        # Flags TCP
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags & 0x02: flow["syn"] += 1
            if flags & 0x10: flow["ack"] += 1
            if flags & 0x01: flow["fin"] += 1
            if flags & 0x04: flow["rst"] += 1

    if not flows:
        logger.warning("Aucun flux IP extrait du PCAP %s", path)
        return None

    # ── Conversion flux → vecteur 29 features ────────────────
    feature_vectors = []

    for key, flow in flows.items():
        ts    = flow["timestamps"]
        sizes = flow["sizes"]

        if len(ts) < 2:
            continue  # flux trop court → inutilisable

        ts_arr    = np.array(ts,    dtype=np.float64)
        size_arr  = np.array(sizes, dtype=np.float64)

        duration        = float(ts_arr.max() - ts_arr.min())
        total_pkts      = flow["fwd_pkts"] + flow["bwd_pkts"]
        total_bytes     = flow["fwd_bytes"] + flow["bwd_bytes"]
        packets_per_sec = _safe_ratio(total_pkts,  max(duration, 1e-6))
        bytes_per_sec   = _safe_ratio(total_bytes,  max(duration, 1e-6))
        avg_pkt         = _safe_ratio(total_bytes,  max(total_pkts, 1))
        fwd_pkt_ratio   = _safe_ratio(flow["fwd_pkts"], max(total_pkts, 1))

        # IAT (inter-arrival times)
        if len(ts_arr) > 1:
            iats          = np.diff(np.sort(ts_arr))
            flow_iat_mean = float(iats.mean())
            flow_iat_std  = float(iats.std()) if len(iats) > 1 else flow_iat_mean * 0.5
        else:
            flow_iat_mean = duration
            flow_iat_std  = 0.0

        # packet_len stats
        pkt_mean = float(size_arr.mean())
        pkt_std  = float(size_arr.std()) if len(size_arr) > 1 else pkt_mean * 0.3
        pkt_max  = float(size_arr.max())

        syn_flag = min(float(flow["syn"]), 1.0)
        ack_flag = min(float(flow["ack"]), 1.0)
        fin_flag = min(float(flow["fin"]), 1.0)
        rst_flag = min(float(flow["rst"]), 1.0)

        syn_ack_ratio = _safe_ratio(syn_flag, max(ack_flag, 1.0))

        # Vecteur 29 features dans l'ordre FEATURE_NAMES
        # (même ordre que extractor.py FEATURE_NAMES après retrait des 4 redondantes)
        vec = np.array([
            duration,                                                    # flow_duration
            float(flow["fwd_pkts"]),                                     # fwd_packet_count
            float(flow["bwd_pkts"]),                                     # bwd_packet_count
            float(flow["fwd_bytes"]),                                    # fwd_bytes_total
            float(flow["bwd_bytes"]),                                    # bwd_bytes_total
            pkt_mean,                                                    # packet_len_mean
            pkt_std,                                                     # packet_len_std
            pkt_max,                                                     # packet_len_max
            flow_iat_mean,                                               # flow_iat_mean
            flow_iat_std,                                                # flow_iat_std
            syn_flag,                                                    # syn_flag
            ack_flag,                                                    # ack_flag
            fin_flag,                                                    # fin_flag
            rst_flag,                                                    # rst_flag
            duration,                                                    # active_mean (approx)
            0.0,                                                         # idle_mean
            _safe_ratio(flow["bwd_bytes"], max(flow["fwd_bytes"], 1)),   # down_up_ratio
            encode_port_category(flow["dst_port"]),                      # dst_port_category
            encode_port_raw(flow["dst_port"]),                           # dst_port_raw
            float(total_pkts),                                           # flow_packets_total
            bytes_per_sec,                                               # bytes_per_sec
            packets_per_sec,                                             # packets_per_sec
            fwd_pkt_ratio,                                               # fwd_pkt_ratio
            avg_pkt,                                                     # avg_bytes_per_packet
            1.0 if flow["dst_port"] == 22   else 0.0,                   # is_ssh_port
            1.0 if flow["dst_port"] == 21   else 0.0,                   # is_ftp_port
            syn_ack_ratio,                                               # syn_ack_ratio
            float(np.log1p(max(duration, 0.0))),                        # flow_duration_log
            float(np.log1p(max(packets_per_sec, 0.0))),                 # packets_per_sec_log
        ], dtype=np.float32)

        if vec.shape[0] != EFFECTIVE_FEATURE_DIM:
            logger.error(
                "Dimension incorrecte: %d attendu %d",
                vec.shape[0], EFFECTIVE_FEATURE_DIM
            )
            continue

        feature_vectors.append(vec)

    if not feature_vectors:
        logger.warning("Aucune feature extraite du PCAP %s", path)
        return None

    result = np.stack(feature_vectors)
    logger.info(
        "PCAP %s → %d flux → %d features chacun",
        path.name, len(result), EFFECTIVE_FEATURE_DIM
    )
    return result


def load_all_dast_pcaps(pcap_dir: str = "data/dast_captures") -> Optional[np.ndarray]:
    """
    Charge tous les fichiers PCAP du dossier DAST
    et retourne un tableau numpy consolidé (N_flux_total × 29).

    Utilisé par M10 AdaptiveMLLoop._load_dast_captures().
    """
    pcap_dir_path = Path(pcap_dir)
    if not pcap_dir_path.exists():
        logger.info("Dossier PCAP absent : %s", pcap_dir)
        return None

    pcap_files = list(pcap_dir_path.glob("*.pcap"))
    if not pcap_files:
        logger.info("Aucun fichier PCAP dans %s", pcap_dir)
        return None

    all_features = []
    for pcap_file in pcap_files:
        features = pcap_to_flow_features(str(pcap_file))
        if features is not None:
            all_features.append(features)

    if not all_features:
        logger.warning("Aucune feature extraite de %d fichiers PCAP", len(pcap_files))
        return None

    consolidated = np.vstack(all_features)
    logger.info(
        "DAST captures consolidées : %d fichiers → %d flux total",
        len(all_features), len(consolidated)
    )
    return consolidated