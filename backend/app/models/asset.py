# ============================================================
# M12 — Asset Registry
# Modèle SQLAlchemy pour les machines surveillées
# ============================================================

from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Boolean
from sqlalchemy.sql import func

from app.core.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)

    # Identité machine
    hostname = Column(String, unique=True, nullable=False, index=True)
    ip_address = Column(String, nullable=False, index=True)

    # Environnement : production, test, dev, lab...
    environment = Column(String, default="unknown", index=True)

    # Criticité métier de l'asset [0-10]
    criticality = Column(Float, default=5.0, nullable=False)

    # Responsable / propriétaire
    owner = Column(String, nullable=True)

    # Agent CyberSentinel
    agent_status = Column(String, default="unknown", index=True)
    last_heartbeat = Column(DateTime(timezone=True), nullable=True)
    is_monitored = Column(Boolean, default=True, index=True)

    # État des services de sécurité sur la machine
    suricata_status = Column(String, nullable=True)
    wazuh_status = Column(String, nullable=True)

    # Wazuh
    wazuh_agent_id = Column(String, nullable=True, index=True)

    # Tags libres : ["linux", "prod", "db", "critical"]
    tags = Column(JSON, default=list)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    def __repr__(self):
        return (
            f"<Asset {self.hostname} | {self.ip_address} | "
            f"C={self.criticality} | status={self.agent_status}>"
        )