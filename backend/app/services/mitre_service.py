# ============================================================
# M6 — Enrichissement MITRE ATT&CK
# attackcti (STIX v14) + cache Redis + SQLite
# Lookup < 2ms (cache hit) | ~200ms (cache miss)
# ============================================================

import json
import sqlite3
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

import redis.asyncio as aioredis

from app.core.config import settings

logger = logging.getLogger(__name__)

# Chemin du cache SQLite local (persistance offline 7 jours)
SQLITE_CACHE_PATH = "data/mitre_cache.db"

# TTL cache Redis : 7 jours en secondes
REDIS_TTL = 604800

# ============================================================
# Tables de mapping : source → technique_id
# ============================================================

# Résolveur M1 : signature_id Suricata → technique_id
# Pour les règles ET Open sans métadonnées MITRE
SURICATA_FALLBACK_MAP = {
    2001219: "T1046",   # NMAP SYN Scan → Network Service Scanning
    2002910: "T1110",   # Brute Force SSH → Brute Force
    2012345: "T1190",   # SQLi → Exploit Public-Facing App
    2404000: "T1071",   # BotNet C2 → Application Layer Protocol
    2019284: "T1498",   # DoS → Network DoS
    2100498: "T1595",   # Active Scanning
    2010935: "T1048",   # DNS Exfiltration
}

# Catégories Suricata → technique_id (fallback sur fallback)
CATEGORY_FALLBACK_MAP = {
    "Web Application Attack":       "T1190",
    "Network Scan":                 "T1046",
    "Malware Command and Control":  "T1071",
    "Attempted Information Leak":   "T1083",
    "Denial of Service":            "T1498",
    "Attempted User Privilege Gain":"T1068",
    "Network Trojan":               "T1059",
    "Potentially Bad Traffic":      "T1595",
}

# Résolveur M4 : CWE → technique_id
CWE_TO_MITRE = {
    "CWE-89":  "T1190",      # SQL Injection
    "CWE-79":  "T1059.007",  # XSS
    "CWE-78":  "T1059",      # Command Injection
    "CWE-22":  "T1083",      # Path Traversal
    "CWE-918": "T1090",      # SSRF
    "CWE-312": "T1552.001",  # Credentials exposés
    "CWE-321": "T1552.001",  # Clé hardcodée
    "CWE-502": "T1190",      # Deserialization
    "CWE-611": "T1190",      # XXE
    "CWE-434": "T1190",      # Unrestricted Upload
    "CWE-601": "T1204",      # Open Redirect
    "CWE-352": "T1185",      # CSRF
}

# Résolveur M2/M5 : anomaly_type / zap_alert → technique_id
ATTACK_TYPE_TO_MITRE = {
    # M2 ML anomaly types
    "DoS slowloris":              "T1498",
    "DoS Slowhttptest":           "T1498",
    "DDoS":                       "T1498",
    "PortScan":                   "T1046",
    "FTP-Patator":                "T1110",
    "SSH-Patator":                "T1110",
    "Web Attack – Brute Force":   "T1110",
    "Web Attack – XSS":           "T1059.007",
    "Web Attack – Sql Injection": "T1190",
    "Infiltration":               "T1046",
    "Bot":                        "T1071",
    # M5 ZAP alert names
    "SQL Injection":              "T1190",
    "Cross Site Scripting (XSS)": "T1059.007",
    "Command Injection":          "T1059",
    "Path Traversal":             "T1083",
    "Server Side Request Forgery":"T1090",
    "IDOR":                       "T1212",
    "Remote File Inclusion":      "T1190",
}

# Base de données ATT&CK locale (pour mode offline)
# Données des 7 techniques principales du CDC
LOCAL_ATTACK_DB = {
    "T1190": {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "description":    "Exploitation de vulnérabilités dans des applications exposées",
        "apt_groups":     ["APT29", "APT41", "Lazarus Group", "Hafnium"],
        "mitigation":     "WAF, patch management, SAST/DAST continus",
        "url":            "https://attack.mitre.org/techniques/T1190/",
        "cvss_base":      9.8,
    },
    "T1046": {
        "technique_id":   "T1046",
        "technique_name": "Network Service Scanning",
        "tactic":         "Discovery",
        "description":    "Scan des services réseau pour cartographier la surface d'attaque",
        "apt_groups":     ["APT10", "FIN6", "Turla", "Kimsuky"],
        "mitigation":     "Segmentation réseau, IDS sur patterns de scan",
        "url":            "https://attack.mitre.org/techniques/T1046/",
        "cvss_base":      5.3,
    },
    "T1048": {
        "technique_id":   "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic":         "Exfiltration",
        "description":    "Exfiltration via canaux alternatifs DNS/ICMP",
        "apt_groups":     ["APT32", "Ke3chang", "MuddyWater"],
        "mitigation":     "DPI sur DNS/ICMP, surveillance flux sortants",
        "url":            "https://attack.mitre.org/techniques/T1048/",
        "cvss_base":      7.5,
    },
    "T1552.001": {
        "technique_id":   "T1552.001",
        "technique_name": "Credentials In Files",
        "tactic":         "Credential Access",
        "description":    "Découverte de credentials en clair dans des fichiers",
        "apt_groups":     ["APT28", "FIN7", "TA505"],
        "mitigation":     "Secrets managers, rotation credentials, Gitleaks hooks",
        "url":            "https://attack.mitre.org/techniques/T1552/001/",
        "cvss_base":      8.1,
    },
    "T1059": {
        "technique_id":   "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic":         "Execution",
        "description":    "Exécution de commandes via interpréteurs shell/scripts",
        "apt_groups":     ["APT29", "Lazarus", "MuddyWater", "Kimsuky"],
        "mitigation":     "Validation inputs, sandboxing, principe moindre privilège",
        "url":            "https://attack.mitre.org/techniques/T1059/",
        "cvss_base":      9.0,
    },
    "T1059.007": {
        "technique_id":   "T1059.007",
        "technique_name": "JavaScript",
        "tactic":         "Execution",
        "description":    "Exécution de code JavaScript malveillant via XSS",
        "apt_groups":     ["APT32", "FIN7", "Lazarus"],
        "mitigation":     "CSP headers, validation/encodage outputs, HttpOnly cookies",
        "url":            "https://attack.mitre.org/techniques/T1059/007/",
        "cvss_base":      7.4,
    },
    "T1498": {
        "technique_id":   "T1498",
        "technique_name": "Network Denial of Service",
        "tactic":         "Impact",
        "description":    "Saturation ressources réseau par flood massif",
        "apt_groups":     ["Sandworm", "Fancy Bear", "Anonymous"],
        "mitigation":     "Rate limiting, scrubbing centers, BGP blackholing",
        "url":            "https://attack.mitre.org/techniques/T1498/",
        "cvss_base":      7.5,
    },
    "T1595": {
        "technique_id":   "T1595",
        "technique_name": "Active Scanning",
        "tactic":         "Reconnaissance",
        "description":    "Reconnaissance active — scan IP, fingerprinting OS/services",
        "apt_groups":     ["APT10", "FIN7", "APT41"],
        "mitigation":     "Honeypots, détection scan IDS, obscurcissement bannières",
        "url":            "https://attack.mitre.org/techniques/T1595/",
        "cvss_base":      5.3,
    },
    "T1071": {
        "technique_id":   "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic":         "Command and Control",
        "description":    "Communication C2 via protocoles applicatifs légitimes",
        "apt_groups":     ["APT29", "APT41", "Lazarus", "MuddyWater"],
        "mitigation":     "DPI, surveillance DNS/HTTP anormaux, proxy filtrant",
        "url":            "https://attack.mitre.org/techniques/T1071/",
        "cvss_base":      6.5,
    },
    "T1083": {
        "technique_id":   "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic":         "Discovery",
        "description":    "Lecture de fichiers arbitraires via path traversal",
        "apt_groups":     ["APT10", "FIN6", "Turla"],
        "mitigation":     "Validation chemins, chroot, permissions fichiers",
        "url":            "https://attack.mitre.org/techniques/T1083/",
        "cvss_base":      7.5,
    },
    "T1110": {
        "technique_id":   "T1110",
        "technique_name": "Brute Force",
        "tactic":         "Credential Access",
        "description":    "Tentatives répétées de connexion par dictionnaire",
        "apt_groups":     ["APT28", "APT33", "Lazarus"],
        "mitigation":     "MFA, lockout policies, fail2ban, alertes anomalie",
        "url":            "https://attack.mitre.org/techniques/T1110/",
        "cvss_base":      8.1,
    },
    "T1090": {
        "technique_id":   "T1090",
        "technique_name": "Proxy",
        "tactic":         "Command and Control",
        "description":    "Forge de requêtes côté serveur via SSRF",
        "apt_groups":     ["APT41", "APT29"],
        "mitigation":     "Validation URLs, blocage métadonnées cloud, egress filtering",
        "url":            "https://attack.mitre.org/techniques/T1090/",
        "cvss_base":      8.6,
    },
}

# Technique par défaut si rien trouvé
DEFAULT_TECHNIQUE_ID = "T1190"


class MitreEnrichmentEngine:
    """
    Enrichit chaque alerte avec les métadonnées MITRE ATT&CK.
    Cache à deux niveaux : Redis (mémoire) + SQLite (disque).
    """

    def __init__(self):
        self.redis: Optional[aioredis.Redis] = None
        self._init_sqlite_cache()
        self._attackcti_available = self._check_attackcti()

    def _check_attackcti(self) -> bool:
        """Vérifie si attackcti est disponible."""
        try:
            import attackcti
            logger.info("attackcti disponible — STIX v14 activé")
            return True
        except ImportError:
            logger.warning(
                "attackcti non installé — mode local uniquement. "
                "pip install attackcti pour activer STIX v14"
            )
            return False

    def _init_sqlite_cache(self):
        """Initialise le cache SQLite local."""
        Path(SQLITE_CACHE_PATH).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(SQLITE_CACHE_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mitre_cache (
                technique_id TEXT PRIMARY KEY,
                data          TEXT NOT NULL,
                cached_at     TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

        # Pré-remplir avec les données locales
        self._populate_sqlite_from_local()

    def _populate_sqlite_from_local(self):
        """Insère les données locales dans SQLite au démarrage."""
        conn = sqlite3.connect(SQLITE_CACHE_PATH)
        now = datetime.now(timezone.utc).isoformat()
        for tid, data in LOCAL_ATTACK_DB.items():
            conn.execute(
                "INSERT OR REPLACE INTO mitre_cache VALUES (?, ?, ?)",
                (tid, json.dumps(data), now)
            )
        conn.commit()
        conn.close()

    async def _get_redis(self) -> aioredis.Redis:
        if not self.redis:
            self.redis = await aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
        return self.redis

    # ============================================================
    # Résolveurs : source → technique_id
    # ============================================================

    def resolve_suricata(self, alert_data: dict) -> str:
        """Résolveur M1 : extrait technique_id depuis une alerte Suricata."""
        # 1. Métadonnées déjà dans la règle
        metadata = alert_data.get("metadata", {})
        if isinstance(metadata, dict):
            tid = metadata.get("mitre_technique")
            if tid:
                return tid
        elif isinstance(metadata, list):
            for item in metadata:
                if isinstance(item, str) and "mitre_technique" in item:
                    return item.split("=")[-1].strip()

        # 2. Fallback par signature_id
        sig_id = alert_data.get("signature_id", 0)
        if sig_id in SURICATA_FALLBACK_MAP:
            return SURICATA_FALLBACK_MAP[sig_id]

        # 3. Fallback par catégorie
        category = alert_data.get("category", "")
        return CATEGORY_FALLBACK_MAP.get(category, DEFAULT_TECHNIQUE_ID)

    def resolve_suricata_fallback(
        self, signature_id: int, category: str
    ) -> str:
        """Version simplifiée pour appel depuis suricata_service."""
        if signature_id in SURICATA_FALLBACK_MAP:
            return SURICATA_FALLBACK_MAP[signature_id]
        return CATEGORY_FALLBACK_MAP.get(category, DEFAULT_TECHNIQUE_ID)

    def resolve_sast(self, finding: dict) -> str:
        """Résolveur M4 : CWE → technique_id."""
        tool = finding.get("tool", "")

        # Gitleaks → toujours T1552.001
        if tool == "gitleaks":
            return "T1552.001"

        cwe = finding.get("cwe", "")
        return CWE_TO_MITRE.get(cwe, DEFAULT_TECHNIQUE_ID)

    def resolve_ml_dast(self, attack_type: str) -> str:
        """Résolveur M2/M5 : anomaly_type ou zap_alert → technique_id."""
        # Cherche correspondance exacte puis partielle
        if attack_type in ATTACK_TYPE_TO_MITRE:
            return ATTACK_TYPE_TO_MITRE[attack_type]

        # Correspondance partielle (insensible à la casse)
        attack_lower = attack_type.lower()
        for key, tid in ATTACK_TYPE_TO_MITRE.items():
            if key.lower() in attack_lower or attack_lower in key.lower():
                return tid

        return DEFAULT_TECHNIQUE_ID

    # ============================================================
    # Lookup MITRE : technique_id → données complètes
    # ============================================================

    async def enrich_by_technique_id(
        self, technique_id: str
    ) -> dict:
        """
        Lookup complet pour un technique_id.
        1. Cache Redis (< 2ms)
        2. Cache SQLite (< 10ms)
        3. attackcti STIX local (~200ms)
        4. Base locale hardcodée (fallback)
        """
        if not technique_id:
            technique_id = DEFAULT_TECHNIQUE_ID

        cache_key = f"mitre:{technique_id}"

        # 1. Redis
        try:
            r = await self._get_redis()
            cached = await r.get(cache_key)
            if cached:
                return json.loads(cached)
        except Exception:
            pass

        # 2. SQLite
        sqlite_data = self._lookup_sqlite(technique_id)
        if sqlite_data:
            # Repopuler Redis depuis SQLite
            try:
                r = await self._get_redis()
                await r.setex(cache_key, REDIS_TTL, json.dumps(sqlite_data))
            except Exception:
                pass
            return sqlite_data

        # 3. attackcti STIX
        if self._attackcti_available:
            stix_data = self._lookup_attackcti(technique_id)
            if stix_data:
                await self._store_in_cache(cache_key, technique_id, stix_data)
                return stix_data

        # 4. Base locale (fallback ultime)
        local_data = LOCAL_ATTACK_DB.get(
            technique_id,
            LOCAL_ATTACK_DB[DEFAULT_TECHNIQUE_ID]
        )
        return local_data

    def _lookup_sqlite(self, technique_id: str) -> Optional[dict]:
        """Cherche dans le cache SQLite local."""
        try:
            conn = sqlite3.connect(SQLITE_CACHE_PATH)
            row = conn.execute(
                "SELECT data FROM mitre_cache WHERE technique_id = ?",
                (technique_id,)
            ).fetchone()
            conn.close()
            if row:
                return json.loads(row[0])
        except Exception as e:
            logger.error(f"SQLite lookup error: {e}")
        return None

    def _lookup_attackcti(self, technique_id: str) -> Optional[dict]:
        """Interroge la base STIX via attackcti."""
        try:
            from attackcti import attack_client
            client = attack_client()

            technique = client.get_technique_by_id(technique_id)
            if not technique:
                return None

            t = technique[0] if isinstance(technique, list) else technique

            # Extraire les groupes APT
            groups = []
            try:
                relationships = client.get_groups_using_technique(
                    technique_id
                )
                groups = [
                    g.get("name", "") for g in relationships
                    if g.get("name")
                ][:5]  # Max 5 groupes
            except Exception:
                pass

            return {
                "technique_id":   technique_id,
                "technique_name": getattr(t, "name", technique_id),
                "tactic":         self._extract_tactic(t),
                "description":    getattr(t, "description", "")[:200],
                "apt_groups":     groups,
                "mitigation":     "",
                "url": f"https://attack.mitre.org/techniques/"
                       f"{technique_id.replace('.', '/')}/",
                "cvss_base":      LOCAL_ATTACK_DB.get(
                                      technique_id, {}
                                  ).get("cvss_base", 5.0),
            }
        except Exception as e:
            logger.error(f"attackcti error pour {technique_id}: {e}")
            return None

    def _extract_tactic(self, technique) -> str:
        """Extrait la tactique depuis un objet STIX."""
        try:
            kill_chain = getattr(technique, "kill_chain_phases", [])
            if kill_chain:
                return kill_chain[0].get("phase_name", "").replace("-", " ").title()
        except Exception:
            pass
        return "Unknown"

    async def _store_in_cache(
        self, cache_key: str, technique_id: str, data: dict
    ):
        """Stocke dans Redis et SQLite."""
        data_json = json.dumps(data)
        # Redis
        try:
            r = await self._get_redis()
            await r.setex(cache_key, REDIS_TTL, data_json)
        except Exception:
            pass
        # SQLite
        try:
            conn = sqlite3.connect(SQLITE_CACHE_PATH)
            conn.execute(
                "INSERT OR REPLACE INTO mitre_cache VALUES (?, ?, ?)",
                (technique_id, data_json,
                 datetime.now(timezone.utc).isoformat())
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"SQLite store error: {e}")

    # ============================================================
    # Point d'entrée unifié pour tous les modules
    # ============================================================

    async def enrich_alert(self, alert_data: dict) -> dict:
        """
        Enrichit une alerte depuis n'importe quelle source.
        Détecte automatiquement la source et applique le bon résolveur.
        """
        source = alert_data.get("source_module", "")

        if "suricata" in source.lower() or "M1" in source:
            technique_id = self.resolve_suricata(alert_data)
        elif "sast" in source.lower() or "M4" in source:
            technique_id = self.resolve_sast(alert_data)
        elif source in ("M2_ml", "M5_dast"):
            technique_id = self.resolve_ml_dast(
                alert_data.get("anomaly_type")
                or alert_data.get("zap_alert", "")
            )
        else:
            technique_id = DEFAULT_TECHNIQUE_ID

        mitre_data = await self.enrich_by_technique_id(technique_id)

        # Fusionner avec l'alerte originale
        alert_data.update({
            "technique_id":   mitre_data["technique_id"],
            "technique_name": mitre_data["technique_name"],
            "tactic":         mitre_data["tactic"],
            "apt_groups":     mitre_data["apt_groups"],
            "mitigation":     mitre_data.get("mitigation", ""),
            "mitre_url":      mitre_data.get("url", ""),
        })

        return alert_data
