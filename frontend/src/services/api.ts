// ============================================================
// services/api.ts — Tous les appels HTTP vers le backend réel
// Base URL configurable via variable d'env
//
// Version modifiée :
//   - Ajout API LLM pour expliquer les vulnérabilités SAST / DAST
//   - Ajout API Asset Registry / Agents Heartbeat
//   - Endpoints :
//       POST /api/vulnerabilities/llm/explain
//       POST /api/vulnerabilities/llm/explain-many
//       GET  /api/assets
//       GET  /api/assets/at-risk
//       GET  /api/agents/status
//       POST /api/assets
//       PATCH /api/assets/{id}
// ============================================================

const API_BASE =
  process.env.REACT_APP_API_URL?.replace(/\/$/, "") || "http://localhost:8000/api";

async function parseJsonSafe<T>(
  res: Response,
  method: string,
  url: string
): Promise<T> {
  const text = await res.text();

  if (!res.ok) {
    throw new Error(`${method} ${url} → ${res.status} | ${text.slice(0, 200)}`);
  }

  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(
      `${method} ${url} → réponse non JSON : ${text.slice(0, 200)}`
    );
  }
}

async function get<T>(url: string): Promise<T> {
  const res = await fetch(`${API_BASE}${url}`);
  return parseJsonSafe<T>(res, "GET", url);
}

async function post<T>(url: string, body?: any): Promise<T> {
  const res = await fetch(`${API_BASE}${url}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });

  return parseJsonSafe<T>(res, "POST", url);
}

async function patch<T>(url: string, body: any): Promise<T> {
  const res = await fetch(`${API_BASE}${url}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  return parseJsonSafe<T>(res, "PATCH", url);
}

async function postForm<T>(url: string, formData: FormData): Promise<T> {
  const res = await fetch(`${API_BASE}${url}`, {
    method: "POST",
    body: formData,
  });

  return parseJsonSafe<T>(res, "POST", url);
}

// ── M1 Alertes ───────────────────────────────────────────────
export const alertsAPI = {
  getRecent: (limit = 20) =>
    get<{ total: number; alerts: any[] }>(`/alerts/recent?limit=${limit}`),

  getAll: (params?: { severity?: string; limit?: number; offset?: number }) => {
    const q = new URLSearchParams();

    if (params?.severity) q.set("severity", params.severity);
    if (params?.limit !== undefined) q.set("limit", String(params.limit));
    if (params?.offset !== undefined) q.set("offset", String(params.offset));

    const qs = q.toString();

    return get<{ total: number; alerts: any[] }>(
      `/alerts/${qs ? `?${qs}` : ""}`
    );
  },

  getStats: () => get<any>("/alerts/stats"),

  getById: (id: number) => get<any>(`/alerts/${id}`),
};

// ── M2/M10 ML ────────────────────────────────────────────────
export const mlAPI = {
  getStatus: () => get<any>("/ml/status"),

  triggerTraining: () => post<any>("/ml/train"),

  trainSync: () => post<any>("/ml/train/sync"),

  getLoaoResults: () => get<any>("/ml/loao-results"),

  getRegistry: () => get<any>("/ml/registry"),

  getH3: () => get<any>("/ml/h3-validation"),

  getReports: () => get<any>("/ml/training-reports"),

  rollback: () => post<any>("/ml/rollback"),

  deployVersion: (v: string) => post<any>(`/ml/deploy/${v}`),
};

// ── M3 Fusion ────────────────────────────────────────────────
export const fusionAPI = {
  getStats: () => get<any>("/fusion/stats"),

  validateH2: (fpr_before: number, fpr_after: number) =>
    post<any>("/fusion/validate-h2", {
      fpr_signature: fpr_before,
      fpr_fusion: fpr_after,
    }),
};

// ── M4 SAST ──────────────────────────────────────────────────
export const sastAPI = {
  scan: (repo_path: string, repo_name = "", commit_sha = "") =>
    post<any>("/sast/scan", {
      repo_path,
      repo_name,
      commit_sha,
    }),

  scanSync: (
    repo_path: string,
    repo_name = "",
    commit_sha = "",
    pr_number?: number
  ) =>
    post<any>("/sast/scan/sync", {
      repo_path,
      repo_name,
      commit_sha,
      pr_number,
    }),

  uploadScan: (file: File, project_name = "", commit_sha = "") => {
    const formData = new FormData();

    formData.append("file", file);

    if (project_name) {
      formData.append("project_name", project_name);
    }

    if (commit_sha) {
      formData.append("commit_sha", commit_sha);
    }

    return postForm<any>("/sast/scan/upload", formData);
  },

  getLatestScan: (params?: { repo_name?: string; commit_sha?: string }) => {
    const q = new URLSearchParams();

    if (params?.repo_name) q.set("repo_name", params.repo_name);
    if (params?.commit_sha) q.set("commit_sha", params.commit_sha);

    const qs = q.toString();

    return get<{
      scan_id: string | null;
      repo_name?: string;
      commit_sha?: string;
    }>(`/sast/latest-scan${qs ? `?${qs}` : ""}`);
  },

  getFindings: (params?: {
    tool?: string;
    severity?: string;
    cwe?: string;
    scan_id?: string;
    limit?: number;
    offset?: number;
  }) => {
    const q = new URLSearchParams();

    if (params?.tool) q.set("tool", params.tool);
    if (params?.severity) q.set("severity", params.severity);
    if (params?.cwe) q.set("cwe", params.cwe);
    if (params?.scan_id) q.set("scan_id", params.scan_id);
    if (params?.limit !== undefined) q.set("limit", String(params.limit));
    if (params?.offset !== undefined) q.set("offset", String(params.offset));

    const qs = q.toString();

    return get<{ total: number; findings: any[] }>(
      `/sast/findings${qs ? `?${qs}` : ""}`
    );
  },

  getStats: (params?: { scan_id?: string }) => {
    const q = new URLSearchParams();

    if (params?.scan_id) q.set("scan_id", params.scan_id);

    const qs = q.toString();

    return get<any>(`/sast/stats${qs ? `?${qs}` : ""}`);
  },

  getById: (id: number) => get<any>(`/sast/findings/${id}`),

  qualityGate: (data: {
    critical_count: number;
    high_count: number;
    secrets_found: boolean;
    ml_smoke_pass?: boolean;
  }) => post<any>("/sast/quality-gate", data),
};

// ── M5 DAST ──────────────────────────────────────────────────
export const dastAPI = {
  getStatus: () => get<any>("/dast/status"),

  verifyIsolation: () => get<any>("/dast/isolation/verify"),

  startSync: (payload: {
    target?: "webgoat" | "dvwa";
    target_url?: string;
    deploy_target?: boolean;
  }) => post<any>("/dast/start/sync", payload),

  start: (payload: {
    target?: "webgoat" | "dvwa";
    target_url?: string;
    deploy_target?: boolean;
  }) => post<any>("/dast/start", payload),

  startFromUpload: (file: File) => {
    const formData = new FormData();

    formData.append("file", file);

    return postForm<any>("/dast/start/from-upload", formData);
  },

  startFromImage: (payload: {
    image: string;
    port?: number;
    healthcheck_path?: string;
    scan_profile?: string;
  }) => post<any>("/dast/start/from-image", payload),

  startFromGit: (payload: {
    repo_url: string;
    branch?: string;
    project_name?: string;
  }) => post<any>("/dast/start/from-git", payload),

  getFindings: (limit = 50, session_id?: string) => {
    const q = new URLSearchParams();

    q.set("limit", String(limit));

    if (session_id) {
      q.set("session_id", session_id);
    }

    return get<any>(`/dast/findings?${q.toString()}`);
  },

  getFindingsHistory: (limit = 100) =>
    get<any>(`/dast/findings/history?limit=${limit}`),
};

// ── M12 Asset Registry / Agents ──────────────────────────────
export const assetsAPI = {
  getAll: () => get<any>("/assets"),

  getAtRisk: () => get<any>("/assets/at-risk"),

  getStatus: () => get<any>("/agents/status"),

  create: (data: any) => post<any>("/assets", data),

  update: (id: number, data: any) => patch<any>(`/assets/${id}`, data),
};

// ── LLM — Explication des vulnérabilités SAST / DAST ─────────
export type VulnerabilitySource = "sast" | "dast";

export type VulnerabilityLLMExplanation = {
  resume_simple: string;
  description_technique: string;
  impact: string;
  cause_probable: string;
  preuve_observee: string;
  niveau_risque: "CRITIQUE" | "ELEVE" | "MOYEN" | "FAIBLE" | "INFO" | string;
  priorite_correction: "P1" | "P2" | "P3" | "P4" | string;
  correction_recommandee: string;
  exemple_correction: string;
  faux_positif_possible: boolean;
  raison_faux_positif: string;
  mapping?: {
    cwe?: string | null;
    owasp?: string | null;
    mitre?: string | null;
  };
};

export type VulnerabilityLLMResponse = {
  success: boolean;
  source: VulnerabilitySource;
  model?: string;
  error?: string;
  explanation: VulnerabilityLLMExplanation;
};

export type VulnerabilityLLMManyResponse = {
  success: boolean;
  source: VulnerabilitySource;
  count: number;
  limit: number;
  items: Array<{
    finding: any;
    llm: VulnerabilityLLMResponse;
  }>;
};

export const vulnerabilityLLMAPI = {
  explain: (source: VulnerabilitySource, finding: any) =>
    post<VulnerabilityLLMResponse>("/vulnerabilities/llm/explain", {
      source,
      finding,
    }),

  explainSAST: (finding: any) =>
    post<VulnerabilityLLMResponse>("/vulnerabilities/llm/explain", {
      source: "sast",
      finding,
    }),

  explainDAST: (finding: any) =>
    post<VulnerabilityLLMResponse>("/vulnerabilities/llm/explain", {
      source: "dast",
      finding,
    }),

  explainMany: (
    source: VulnerabilitySource,
    findings: any[],
    limit: number = 20
  ) =>
    post<VulnerabilityLLMManyResponse>("/vulnerabilities/llm/explain-many", {
      source,
      findings,
      limit,
    }),

  explainManySAST: (findings: any[], limit: number = 20) =>
    post<VulnerabilityLLMManyResponse>("/vulnerabilities/llm/explain-many", {
      source: "sast",
      findings,
      limit,
    }),

  explainManyDAST: (findings: any[], limit: number = 20) =>
    post<VulnerabilityLLMManyResponse>("/vulnerabilities/llm/explain-many", {
      source: "dast",
      findings,
      limit,
    }),
};

// ── M6 MITRE ─────────────────────────────────────────────────
export const mitreAPI = {
  getTechnique: (id: string) => get<any>(`/mitre/technique/${id}`),

  listTechniques: () => get<any>("/mitre/techniques"),

  getMatrix: () => get<any>("/mitre/matrix"),

  getCweMapping: () => get<any>("/mitre/cwe-mapping"),

  enrich: (alert: any) => post<any>("/mitre/enrich", alert),
};

// ── M7 Incidents ─────────────────────────────────────────────
export const incidentsAPI = {
  getAll: (params?: {
    severity?: string;
    status?: string;
    technique_id?: string;
    limit?: number;
    offset?: number;
  }) => {
    const q = new URLSearchParams();

    if (params?.severity) q.set("severity", params.severity);
    if (params?.status) q.set("status", params.status);
    if (params?.technique_id) q.set("technique_id", params.technique_id);

    const safeLimit =
      params?.limit !== undefined ? Math.min(params.limit, 100) : undefined;

    if (safeLimit !== undefined) q.set("limit", String(safeLimit));
    if (params?.offset !== undefined) q.set("offset", String(params.offset));

    const qs = q.toString();

    return get<any>(`/incidents/${qs ? `?${qs}` : ""}`);
  },

  getStats: () => get<any>("/incidents/stats"),

  getCritical: () => get<any>("/incidents/critical"),

  getById: (id: number) => get<any>(`/incidents/${id}`),

  updateStatus: (id: number, status: string) =>
    patch<any>(`/incidents/${id}/status`, {
      status,
    }),

  computeR: (data: {
    anomaly_score: number;
    cvss_score: number;
    dast_confirmed: boolean;
    asset_criticality: number;
  }) => post<any>("/incidents/compute-r", data),

  validateH4: (computed: number[], expert: number[]) =>
    post<any>("/incidents/validate-h4", {
      computed_scores: computed,
      expert_scores: expert,
    }),
};

// ── Scoring ──────────────────────────────────────────────────
export const scoringAPI = {
  getWeights: () => get<any>("/scoring/weights"),

  getSLA: () => get<any>("/scoring/sla"),

  getAssetCriticality: () => get<any>("/scoring/asset-criticality"),
};

// ── M8 CI/CD ─────────────────────────────────────────────────
export const cicdAPI = {
  getRuns: () => get<any>("/cicd/runs"),

  getGateConfig: () => get<any>("/cicd/quality-gate/config"),

  getIntegGuide: () => get<any>("/cicd/integration-guide"),

  sendWebhook: (data: any) => post<any>("/cicd/webhook", data),

  scanRepo: (repo_url: string, branch = "main") =>
    post<any>("/cicd/scan/repo", {
      repo_url,
      branch,
    }),

  submitResults: (data: any) => post<any>("/cicd/submit-results", data),
};

// ── Reports LLM — Rapports narratifs CyberSentinel ───────────
export type LLMReportType =
  | "security_summary"
  | "incident_analysis"
  | "sast_dast_summary"
  | "executive_briefing";

export type LLMReportLanguage = "fr" | "en";

export type LLMReportRequest = {
  report_type: LLMReportType;
  language?: LLMReportLanguage;
  period_days?: number;
  incident_id?: number | null;
};

export type LLMReportResponse = {
  success: boolean;
  report_type: LLMReportType;
  generated_at: string;
  period_days: number;
  incident_id?: number | null;
  markdown: string;
  stats: {
    counts?: {
      alerts?: number;
      incidents?: number;
      open_incidents?: number;
      sla_overdue?: number;
      sast_findings?: number;
      dast_findings?: number;
      dast_confirmed_sast?: number;
      [key: string]: any;
    };
    aggregates?: any;
    selected_incident?: any;
    [key: string]: any;
  };
  model: string;
};

export type LLMReportTypesResponse = {
  types: Array<{
    id: LLMReportType;
    label: string;
    description: string;
    incident_id_required: boolean;
  }>;
};

export const reportsAPI = {
  analyze: (payload: LLMReportRequest) =>
    post<LLMReportResponse>("/reports/analyze", payload),

  getTypes: () => get<LLMReportTypesResponse>("/reports/types"),
};

// ── Health ───────────────────────────────────────────────────
export const healthAPI = {
  check: async () => {
    const res = await fetch(
      process.env.REACT_APP_API_ROOT?.replace(/\/$/, "") ||
        "http://localhost:8000/health"
    );

    return res.json();
  },
};

// ============================================================
// M11 — HIDS / Wazuh API
// ============================================================

export const hidsAPI = {
  getStats: () => get<any>("/hids/stats"),

  getAlerts: (limit = 50) => get<any>(`/hids/alerts?limit=${limit}`),

  getAgentStatus: (name = "ai-learn") =>
    get<any>(`/hids/agent/status?name=${encodeURIComponent(name)}`),
};