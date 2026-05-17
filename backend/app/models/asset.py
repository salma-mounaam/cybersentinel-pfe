# ============================================================
# M12 — Asset Registry
# Modèle SQLAlchemy pour les machines surveillées
# ============================================================

from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from sqlalchemy.sql import func

from app.core.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)

    hostname = Column(String, unique=True, nullable=False, index=True)
    ip_address = Column(String, nullable=False, index=True)

    environment = Column(String, default="unknown", index=True)

    criticality = Column(Float, default=5.0, nullable=False)

    owner = Column(String, nullable=True)

    agent_status = Column(String, default="unknown", index=True)

    last_heartbeat = Column(DateTime(timezone=True), nullable=True)

    wazuh_agent_id = Column(String, nullable=True, index=True)

    tags = Column(JSON, default=list)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )
