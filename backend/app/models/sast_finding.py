from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Enum, Text
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class SASTTool(str, enum.Enum):
    SEMGREP = "semgrep"
    TRIVY = "trivy"
    GITLEAKS = "gitleaks"


class SASTSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class SASTFinding(Base):
    __tablename__ = "sast_findings"

    id = Column(Integer, primary_key=True, index=True)

    tool = Column(Enum(SASTTool), nullable=False)
    severity = Column(Enum(SASTSeverity), nullable=False)

    # ============================================================
    # Localisation exacte
    # ============================================================
    file_path = Column(String(1000), nullable=True)

    # Ancien champ gardé pour compatibilité
    line_number = Column(Integer, nullable=True)

    # Nouveaux champs précis
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    col_start = Column(Integer, nullable=True)
    col_end = Column(Integer, nullable=True)

    code_snippet = Column(Text, nullable=True)
    vulnerable_line = Column(Text, nullable=True)

    rule_id = Column(String(255), nullable=True)

    # ============================================================
    # Vulnérabilité
    # ============================================================
    cwe = Column(String(255), nullable=True)
    cve = Column(String(100), nullable=True)
    cvss_score = Column(Float, default=0.0)

    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    message = Column(Text, nullable=True)

    fix_suggestion = Column(Text, nullable=True)
    fix_code = Column(Text, nullable=True)
    references = Column(JSON, nullable=True)

    category = Column(String(255), nullable=True)

    # ============================================================
    # Trivy / SCA
    # ============================================================
    package_name = Column(String(255), nullable=True)
    package_version = Column(String(100), nullable=True)
    fix_version = Column(String(100), nullable=True)

    # ============================================================
    # Gitleaks / Secrets
    # ============================================================
    secret_type = Column(String(255), nullable=True)
    secret_preview = Column(String(255), nullable=True)

    # ============================================================
    # MITRE ATT&CK (M6)
    # ============================================================
    technique_id = Column(String(50), nullable=True)
    technique_name = Column(String(255), nullable=True)
    tactic = Column(String(100), nullable=True)

    # ============================================================
    # DAST confirmation
    # ============================================================
    dast_confirmed = Column(Integer, default=0)

    # ============================================================
    # Scan context
    # ============================================================
    repo_name = Column(String(255), nullable=True)
    commit_sha = Column(String(100), nullable=True)
    pr_number = Column(Integer, nullable=True)
    sarif_raw = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())