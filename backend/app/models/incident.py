from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Enum, Text
from sqlalchemy.sql import func
from app.core.database import Base
from app.models.alert import SeverityLevel
import enum


class IncidentStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN, nullable=False)
    severity = Column(Enum(SeverityLevel), nullable=False)

    # Score R = 0.35A + 0.30V + 0.25E + 0.10C
    score_r = Column(Float, nullable=False)
    score_a = Column(Float, default=0.0)  # Anomalie IDS
    score_v = Column(Float, default=0.0)  # CVSS / 10
    score_e = Column(Float, default=0.0)  # Exploitabilité DAST
    score_c = Column(Float, default=0.0)  # Criticité Asset

    # Sources corrélées
    alert_ids = Column(JSON, default=list)
    sast_finding_ids = Column(JSON, default=list)
    dast_finding_ids = Column(JSON, default=list)

    # MITRE ATT&CK
    technique_id = Column(String(20), nullable=True)
    technique_name = Column(String(255), nullable=True)
    tactic = Column(String(100), nullable=True)
    apt_groups = Column(JSON, default=list)
    mitre_url = Column(String(255), nullable=True)

    # Asset cible
    asset_ip = Column(String(45), nullable=True)
    asset_name = Column(String(255), nullable=True)
    asset_criticality = Column(Float, default=5.0)

    # SLA
    sla_deadline = Column(DateTime(timezone=True), nullable=True)
    description = Column(Text, nullable=True)

    # Timestamps
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<Incident {self.id} | R={self.score_r} | {self.severity}>"