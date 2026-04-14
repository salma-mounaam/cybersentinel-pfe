from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Boolean
from sqlalchemy.sql import func
from app.core.database import Base

class MLModelVersion(Base):
    __tablename__ = "ml_model_registry"

    id              = Column(Integer, primary_key=True, index=True)
    version         = Column(String(20), nullable=False)   # ex: v1, v2
    is_active       = Column(Boolean, default=False)

    # Métriques LOAO
    recall_mean     = Column(Float, nullable=True)
    precision_mean  = Column(Float, nullable=True)
    f1_mean         = Column(Float, nullable=True)
    fpr_mean        = Column(Float, nullable=True)
    auc_roc_mean    = Column(Float, nullable=True)

    # Métriques par type d'attaque
    metrics_by_type = Column(JSON, default=dict)
    # {
    #   "DoS": {"recall": 0.82, "f1": 0.79},
    #   "DDoS": {"recall": 0.76, "f1": 0.74},
    #   ...
    # }

    # Dataset utilisé
    dataset_size    = Column(Integer, nullable=True)
    dast_samples    = Column(Integer, default=0)  # captures DAST incluses

    # Artefacts
    model_path_if     = Column(String(500), nullable=True)
    model_path_ocsvm  = Column(String(500), nullable=True)
    model_path_ae     = Column(String(500), nullable=True)
    scaler_path       = Column(String(500), nullable=True)

    # Déploiement
    deployed_at     = Column(DateTime(timezone=True), nullable=True)
    rollback_reason = Column(String(500), nullable=True)

    created_at      = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<MLModel {self.version} | F1={self.f1_mean} | active={self.is_active}>"
