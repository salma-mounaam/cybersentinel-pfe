// ============================================================
// types/index.ts — Types TypeScript alignés sur le vrai backend
// ============================================================

export type Severity = "CRITIQUE" | "ELEVE" | "MOYEN" | "FAIBLE";
export type IncidentStatus = "OPEN" | "IN_REVIEW" | "RESOLVED" | "FALSE_POSITIVE";
export type SASTTool = "semgrep" | "trivy" | "gitleaks";
export type SASTSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

// ── M1 Alertes ───────────────────────────────────────────────
export interface Alert {
  id: number;
  source: string;
  severity: Severity;
  src_ip: string;
  dest_ip: string;
  src_port: number | null;
  dest_port: number | null;
  protocol: string;
  signature_id: number | null;
  signature_name: string;
  category: string;
  suricata_score: number;
  ml_score: number;
  confidence: number;
  fusion_case: number | null;
  technique_id: string | null;
  technique_name: string | null;
  tactic: string | null;
  apt_groups: string[];
  detected_at: string;
}

export interface AlertStats {
  total: number;
  by_severity: Record<Severity, number>;
  detection_rate: number;
}

// ── M2/M10 ML ────────────────────────────────────────────────
export interface MLStatus {
  models_loaded: boolean;
  if_model: boolean;
  ocsvm_model: boolean;
  ae_model: boolean;
  scaler: boolean;
  active_version: ModelVersion | null;
  recent_versions: ModelVersion[];
  h3_status: H3Status;
}

export interface ModelVersion {
  version: string;
  metrics: {
    f1_mean: number;
    recall_mean: number;
    precision_mean: number;
    fpr_mean: number;
    h1_validated: boolean;
    by_attack?: Record<string, any>;
  };
  model_path: string;
  created_at: string;
  is_active: boolean;
}

export interface H3Status {
  h3_validated: boolean;
  delta_f1: number;
  f1_v0: number;
  f1_vN: number;
  version_v0: string | null;
  version_vN: string | null;
  target: string;
  message?: string;
}

// ── M3 Fusion ────────────────────────────────────────────────
export interface FusionStats {
  total_fused: number;
  total_suricata: number;
  cases: Record<string, number>;
  noise_eliminated: number;
  estimated_fpr_reduction_pct: number;
  h2_on_track: boolean;
}

// ── M4 SAST ──────────────────────────────────────────────────
export interface SASTFinding {
  id: number;
  tool: SASTTool;
  severity: SASTSeverity;
  file_path: string | null;
  line_number: number | null;
  rule_id: string | null;
  cwe: string | null;
  cve: string | null;
  cvss_score: number;
  title: string;
  description: string | null;
  fix_suggestion: string | null;
  fix_code: string | null;
  technique_id: string | null;
  technique_name: string | null;
  tactic: string | null;
  dast_confirmed: boolean;
  repo_name: string | null;
  commit_sha: string | null;
  pr_number: number | null;
  created_at: string;
}

export interface SASTStats {
  total: number;
  by_tool: Record<SASTTool, number>;
  by_severity: Record<SASTSeverity, number>;
  confirmed_by_dast: number;
  critical_count: number;
  secrets_found: number;
}

// ── M5 DAST ──────────────────────────────────────────────────
export interface DASTStatus {
  active: boolean;
  session_id: string | null;
}

export interface DASTFinding {
  session_id: string;
  alert_name: string;
  risk: string;
  confidence: string;
  url: string;
  method: string;
  attack: string;
  evidence: string;
  cwe_id: string;
  timestamp: string;
}

// ── M6 MITRE ─────────────────────────────────────────────────
export interface MITRETechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  description: string;
  apt_groups: string[];
  mitigation: string;
  url: string;
  cvss_base: number;
}

export interface MITREMatrixEntry {
  technique_id: string;
  tactic: string;
  total_count: number;
  severities: Record<string, number>;
}

// ── M7 Incidents ─────────────────────────────────────────────
export interface Incident {
  id: number;
  title: string;
  status: IncidentStatus;
  severity: Severity;
  score_r: number;
  score_a: number;
  score_v: number;
  score_e: number;
  score_c: number;
  alert_ids: number[];
  sast_finding_ids: number[];
  dast_finding_ids: number[];
  technique_id: string | null;
  technique_name: string | null;
  tactic: string | null;
  apt_groups: string[];
  mitre_url: string | null;
  asset_ip: string | null;
  asset_name: string | null;
  asset_criticality: number;
  sla_deadline: string | null;
  description: string | null;
  detected_at: string;
}

export interface IncidentStats {
  total: number;
  by_severity: Record<Severity, number>;
  avg_score_r: number;
  overdue_sla: number;
}

// ── M8 CI/CD ─────────────────────────────────────────────────
export interface CICDRun {
  run_id: string;
  decision: "BLOCK" | "PASS" | "UNKNOWN";
  pr_number: string | null;
  commit_sha: string;
  repo: string | null;
  timestamp: string;
  source: string;
}

export interface CICDStats {
  total: number;
  blocked: number;
  passed: number;
  block_rate: number;
  h5_status: boolean | null;
  runs: CICDRun[];
}

// ── WebSocket ─────────────────────────────────────────────────
export interface WSMessage {
  _type?: string;
  _channel?: string;
  _source?: string;
  type?: string;
  id?: number;
  severity?: Severity;
  [key: string]: any;
}