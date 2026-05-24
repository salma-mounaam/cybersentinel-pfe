from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Enum
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class SeverityLevel(str, enum.Enum):
    CRITIQUE = "CRITIQUE"
    ELEVE    = "ELEVE"
    MOYEN    = "MOYEN"
    FAIBLE   = "FAIBLE"


class AlertSource(str, enum.Enum):
    M1_SURICATA = "M1_suricata"
    M2_ML       = "M2_ml"
    M3_FUSION   = "M3_fusion"
    M11_WAZUH   = "M11_wazuh"


class Alert(Base):
    __tablename__ = "alerts"

    id             = Column(Integer, primary_key=True, index=True)
    source         = Column(Enum(AlertSource), nullable=False)
    severity       = Column(Enum(SeverityLevel), nullable=False)

    # Réseau
    src_ip         = Column(String(45))
    dest_ip        = Column(String(45))
    src_port       = Column(Integer)
    dest_port      = Column(Integer)
    protocol       = Column(String(10))

    # Asset ciblé / machine surveillée
    asset_ip          = Column(String(45), nullable=True)
    asset_name        = Column(String(255), nullable=True)
    asset_criticality = Column(Float, default=5.0)

    # Suricata (M1)
    signature_id   = Column(Integer, nullable=True)
    signature_name = Column(String(255), nullable=True)
    category       = Column(String(100), nullable=True)
    suricata_score = Column(Float, default=0.0)

    # [LLM] Type d'attaque classifié par Llama 3.1 via Ollama
    # Exemples : BruteForce, PortScan, DoS, SQLi, Reconnaissance...
    attack_type    = Column(String(100), nullable=True)

    # ML (M2)
    ml_score       = Column(Float, default=0.0)
    anomaly_type   = Column(String(100), nullable=True)
    if_score       = Column(Float, nullable=True)
    ocsvm_score    = Column(Float, nullable=True)
    ae_score       = Column(Float, nullable=True)

    # Fusion (M3)
    confidence     = Column(Float, default=0.0)
    fusion_case    = Column(Integer, nullable=True)

    # MITRE ATT&CK (M6)
    technique_id   = Column(String(20), nullable=True)
    technique_name = Column(String(255), nullable=True)
    tactic         = Column(String(100), nullable=True)
    apt_groups     = Column(JSON, default=list)

    # Payload brut
    raw_payload    = Column(JSON, nullable=True)

    # Timestamps
    detected_at    = Column(DateTime(timezone=True), server_default=func.now())
    created_at     = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return (
            f"<Alert {self.id} | {self.source} | "
            f"{self.severity} | {self.attack_type or 'Unknown'} | "
            f"asset={self.asset_name or self.asset_ip or 'Unknown'}>"
        )