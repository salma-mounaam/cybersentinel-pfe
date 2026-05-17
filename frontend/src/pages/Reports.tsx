// ============================================================
// pages/Reports.tsx — CyberSentinel Reports
//
// Contient deux parties :
//   1. Exports classiques CSV / JSON
//   2. Rapports narratifs intelligents via LLM / Ollama
//
// Backend LLM attendu :
//   POST /api/reports/analyze
//
// api.ts attendu :
//   reportsAPI.analyze()
// ============================================================

import React, { useState, useCallback, useMemo } from "react";
import {
  FileText,
  Download,
  FileSpreadsheet,
  FileJson,
  Calendar,
  CheckCircle2,
  Loader2,
  AlertTriangle,
  X,
  RefreshCw,
  Brain,
  Sparkles,
  ShieldAlert,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { cn } from "../lib/utils";

import {
  incidentsAPI,
  sastAPI,
  alertsAPI,
  mlAPI,
  cicdAPI,
  reportsAPI,
  LLMReportType,
  LLMReportLanguage,
  LLMReportResponse,
} from "../services/api";

// ─────────────────────────────────────────────────────────────
// Pagination automatique
// ─────────────────────────────────────────────────────────────

async function fetchAllPages<T>(
  fetcher: (
    offset: number,
    limit: number
  ) => Promise<{ total: number; [key: string]: any }>,
  itemsKey: string,
  batchSize = 100,
  maxItems = 500
): Promise<T[]> {
  const results: T[] = [];
  let offset = 0;

  while (results.length < maxItems) {
    const limit = Math.min(batchSize, maxItems - results.length);
    const page = await fetcher(offset, limit);
    const items: T[] = page[itemsKey] ?? [];

    results.push(...items);

    if (results.length >= page.total || items.length < limit) {
      break;
    }

    offset += limit;
  }

  return results;
}

// ─────────────────────────────────────────────────────────────
// Helpers export CSV / JSON / Markdown / HTML
// ─────────────────────────────────────────────────────────────

function toCSV(rows: any[], headers: string[]): string {
  const esc = (v: any) => {
    const s = String(v ?? "");

    return s.includes(",") || s.includes('"') || s.includes("\n")
      ? `"${s.replace(/"/g, '""')}"`
      : s;
  };

  return [
    headers.join(","),
    ...rows.map((r) => headers.map((h) => esc(r[h])).join(",")),
  ].join("\n");
}

function downloadBlob(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();

  URL.revokeObjectURL(url);
}

function escapeHtml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function markdownToHtml(markdown: string): string {
  let html = escapeHtml(markdown || "");

  html = html.replace(/^### (.*)$/gm, "<h3>$1</h3>");
  html = html.replace(/^## (.*)$/gm, "<h2>$1</h2>");
  html = html.replace(/^# (.*)$/gm, "<h1>$1</h1>");

  html = html.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*(.*?)\*/g, "<em>$1</em>");

  html = html.replace(/^- (.*)$/gm, "<li>$1</li>");
  html = html.replace(/(<li>.*<\/li>)/gs, "<ul>$1</ul>");

  html = html.replace(/\n{2,}/g, "</p><p>");
  html = `<p>${html}</p>`;

  html = html
    .replaceAll("<p><h1>", "<h1>")
    .replaceAll("</h1></p>", "</h1>")
    .replaceAll("<p><h2>", "<h2>")
    .replaceAll("</h2></p>", "</h2>")
    .replaceAll("<p><h3>", "<h3>")
    .replaceAll("</h3></p>", "</h3>")
    .replaceAll("<p><ul>", "<ul>")
    .replaceAll("</ul></p>", "</ul>");

  return html;
}

function buildHtmlDocument(markdown: string, title: string) {
  const body = markdownToHtml(markdown);

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8" />
  <title>${escapeHtml(title)}</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #f8fafc;
      color: #111827;
      margin: 0;
      padding: 40px;
      line-height: 1.65;
    }
    .report {
      max-width: 920px;
      margin: auto;
      background: white;
      border-radius: 18px;
      padding: 42px;
      box-shadow: 0 20px 50px rgba(15, 23, 42, 0.10);
    }
    h1 {
      color: #064e3b;
      border-bottom: 3px solid #10b981;
      padding-bottom: 12px;
    }
    h2 {
      color: #065f46;
      margin-top: 32px;
    }
    h3 {
      color: #047857;
    }
    p {
      margin: 12px 0;
    }
    ul {
      margin: 12px 0 12px 24px;
    }
    li {
      margin: 6px 0;
    }
    strong {
      color: #111827;
    }
    .footer {
      margin-top: 40px;
      font-size: 12px;
      color: #6b7280;
      border-top: 1px solid #e5e7eb;
      padding-top: 16px;
    }
    @media print {
      body {
        background: white;
        padding: 0;
      }
      .report {
        box-shadow: none;
        border-radius: 0;
      }
    }
  </style>
</head>
<body>
  <main class="report">
    ${body}
    <div class="footer">
      Rapport généré par CyberSentinel — LLM / Ollama
    </div>
  </main>
</body>
</html>`;
}

// ─────────────────────────────────────────────────────────────
// Types exports classiques
// ─────────────────────────────────────────────────────────────

type ReportFormat = "csv" | "json";

interface Section {
  key: string;
  label: string;
}

interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  format: ReportFormat;
  sections: Section[];
  color: string;
  fetcher: (
    active: string[],
    dateRange: { start: string; end: string }
  ) => Promise<string>;
}

// ─────────────────────────────────────────────────────────────
// Templates CSV / JSON
// ─────────────────────────────────────────────────────────────

const TEMPLATES: ReportTemplate[] = [
  {
    id: "incidents-csv",
    name: "Incidents — CSV",
    description: "Score R décomposé A/V/E/C, MITRE, SLA, statut",
    format: "csv",
    color: "bg-green-500/10 border-green-500/30",
    sections: [
      { key: "score_r", label: "Décomposition score R (A / V / E / C)" },
      { key: "mitre", label: "Technique & tactique MITRE ATT&CK" },
      { key: "sla", label: "SLA deadline" },
      { key: "statut", label: "Statut de l'incident" },
      { key: "asset", label: "Asset IP & criticité" },
      { key: "sources", label: "IDs alertes / SAST / DAST liés" },
    ],
    fetcher: async (active) => {
      const incs = await fetchAllPages<any>(
        (offset, limit) => incidentsAPI.getAll({ limit, offset }),
        "incidents",
        100,
        500
      );

      const h = ["id", "titre", "severite", "score_r", "detected_at"];

      if (active.includes("score_r")) {
        h.push("score_a", "score_v", "score_e", "score_c");
      }
      if (active.includes("mitre")) {
        h.push("technique_id", "technique_name", "tactic", "apt_groups");
      }
      if (active.includes("sla")) h.push("sla_deadline");
      if (active.includes("statut")) h.push("status");
      if (active.includes("asset")) {
        h.push("asset_ip", "asset_name", "asset_criticality");
      }
      if (active.includes("sources")) {
        h.push("alert_ids", "sast_finding_ids", "dast_finding_ids");
      }

      const rows = incs.map((i: any) => ({
        id: i.id,
        titre: i.title,
        severite: i.severity,
        score_r: i.score_r,
        detected_at: i.detected_at,
        score_a: i.score_a,
        score_v: i.score_v,
        score_e: i.score_e,
        score_c: i.score_c,
        technique_id: i.technique_id,
        technique_name: i.technique_name,
        tactic: i.tactic,
        apt_groups: (i.apt_groups ?? []).join("|"),
        sla_deadline: i.sla_deadline,
        status: i.status,
        asset_ip: i.asset_ip,
        asset_name: i.asset_name,
        asset_criticality: i.asset_criticality,
        alert_ids: (i.alert_ids ?? []).join("|"),
        sast_finding_ids: (i.sast_finding_ids ?? []).join("|"),
        dast_finding_ids: (i.dast_finding_ids ?? []).join("|"),
      }));

      return toCSV(rows, h);
    },
  },

  {
    id: "alerts-csv",
    name: "Alertes IDS — CSV",
    description: "Flux M1/M3 avec scores ML et cas de fusion",
    format: "csv",
    color: "bg-blue-500/10 border-blue-500/30",
    sections: [
      { key: "ips", label: "IP source / destination / protocole" },
      { key: "ports", label: "Ports src / dest" },
      { key: "attack", label: "Type d'attaque (classification LLM)" },
      { key: "ml_scores", label: "Score Suricata / ML / confiance" },
      { key: "fusion", label: "Cas de fusion M3 (1-5)" },
      { key: "mitre", label: "Technique & tactique MITRE" },
    ],
    fetcher: async (active) => {
      const alerts = await fetchAllPages<any>(
        (offset, limit) => alertsAPI.getAll({ limit, offset }),
        "alerts",
        100,
        1000
      );

      const h = ["id", "severite", "signature", "detected_at"];

      if (active.includes("ips")) h.push("src_ip", "dest_ip", "protocol");
      if (active.includes("ports")) h.push("src_port", "dest_port");
      if (active.includes("attack")) h.push("attack_type");
      if (active.includes("ml_scores")) {
        h.push("suricata_score", "ml_score", "confidence");
      }
      if (active.includes("fusion")) h.push("fusion_case");
      if (active.includes("mitre")) h.push("technique_id", "tactic");

      const rows = alerts.map((a: any) => ({
        id: a.id,
        severite: a.severity,
        signature: a.signature_name,
        detected_at: a.detected_at,
        src_ip: a.src_ip,
        dest_ip: a.dest_ip,
        protocol: a.protocol,
        src_port: a.src_port,
        dest_port: a.dest_port,
        attack_type: a.attack_type,
        suricata_score: a.suricata_score,
        ml_score: a.ml_score,
        confidence: a.confidence,
        fusion_case: a.fusion_case,
        technique_id: a.technique_id,
        tactic: a.tactic,
      }));

      return toCSV(rows, h);
    },
  },

  {
    id: "sast-csv",
    name: "SAST Findings — CSV",
    description: "Semgrep + Trivy + Gitleaks avec CVSS, CWE, fix",
    format: "csv",
    color: "bg-amber-500/10 border-amber-500/30",
    sections: [
      { key: "location", label: "Fichier & ligne" },
      { key: "cwe", label: "CWE & CVE" },
      { key: "cvss", label: "Score CVSS" },
      { key: "mitre", label: "Technique MITRE ATT&CK" },
      { key: "fix", label: "Suggestion de correction (200 chars)" },
      { key: "dast", label: "Confirmation DAST" },
      { key: "repo", label: "Repo & commit SHA" },
    ],
    fetcher: async (active) => {
      const findings = await fetchAllPages<any>(
        (offset, limit) => sastAPI.getFindings({ limit, offset }),
        "findings",
        100,
        1000
      );

      const h = ["id", "outil", "severite", "titre"];

      if (active.includes("location")) h.push("fichier", "ligne");
      if (active.includes("cwe")) h.push("cwe", "cve");
      if (active.includes("cvss")) h.push("cvss_score");
      if (active.includes("mitre")) h.push("technique_id", "tactic");
      if (active.includes("fix")) h.push("fix_suggestion");
      if (active.includes("dast")) h.push("dast_confirmed");
      if (active.includes("repo")) h.push("repo_name", "commit_sha");

      const rows = findings.map((f: any) => ({
        id: f.id,
        outil: f.tool,
        severite: f.severity,
        titre: f.title,
        fichier: f.file_path,
        ligne: f.line_number,
        cwe: f.cwe,
        cve: f.cve,
        cvss_score: f.cvss_score,
        technique_id: f.technique_id,
        tactic: f.tactic,
        fix_suggestion: (f.fix_suggestion ?? "").slice(0, 200),
        dast_confirmed: f.dast_confirmed ? "oui" : "non",
        repo_name: f.repo_name,
        commit_sha: f.commit_sha,
      }));

      return toCSV(rows, h);
    },
  },

  {
    id: "incidents-json",
    name: "Incidents — JSON",
    description: "Export complet structuré avec toutes les métadonnées",
    format: "json",
    color: "bg-purple-500/10 border-purple-500/30",
    sections: [
      { key: "score_r", label: "Décomposition score R" },
      { key: "mitre", label: "MITRE ATT&CK + groupes APT" },
      { key: "sla", label: "SLA & asset" },
      { key: "sources", label: "Sources liées (alertes, SAST, DAST)" },
      { key: "stats", label: "Statistiques globales (getStats)" },
    ],
    fetcher: async (active) => {
      const [incs, stats] = await Promise.all([
        fetchAllPages<any>(
          (o, l) => incidentsAPI.getAll({ limit: l, offset: o }),
          "incidents",
          100,
          500
        ),
        active.includes("stats")
          ? incidentsAPI.getStats()
          : Promise.resolve(null),
      ]);

      const incidents = incs.map((i: any) => {
        const out: any = {
          id: i.id,
          title: i.title,
          severity: i.severity,
          status: i.status,
          detected_at: i.detected_at,
          updated_at: i.updated_at,
        };

        if (active.includes("score_r")) {
          out.score_r = {
            total: i.score_r,
            A: i.score_a,
            V: i.score_v,
            E: i.score_e,
            C: i.score_c,
          };
        }

        if (active.includes("mitre")) {
          out.mitre = {
            technique_id: i.technique_id,
            technique_name: i.technique_name,
            tactic: i.tactic,
            apt_groups: i.apt_groups ?? [],
            mitre_url: i.mitre_url,
          };
        }

        if (active.includes("sla")) {
          out.sla = {
            deadline: i.sla_deadline,
            asset_ip: i.asset_ip,
            asset_name: i.asset_name,
            asset_criticality: i.asset_criticality,
          };
        }

        if (active.includes("sources")) {
          out.sources = {
            alert_ids: i.alert_ids ?? [],
            sast_finding_ids: i.sast_finding_ids ?? [],
            dast_finding_ids: i.dast_finding_ids ?? [],
          };
        }

        return out;
      });

      const output: any = {
        exported_at: new Date().toISOString(),
        total: incidents.length,
        incidents,
      };

      if (stats) output.stats = stats;

      return JSON.stringify(output, null, 2);
    },
  },

  {
    id: "ml-json",
    name: "Modèles ML — JSON",
    description: "Registre versions, F1, Recall, FPR, H1/H3",
    format: "json",
    color: "bg-violet-500/10 border-violet-500/30",
    sections: [
      { key: "status", label: "Statut modèles en mémoire" },
      { key: "versions", label: "Historique des versions (registry)" },
      { key: "loao", label: "Résultats LOAO par type d'attaque (H1)" },
      { key: "h3", label: "Validation H3 (ΔF1 ≥ 0.10)" },
      { key: "reports", label: "Rapports d'entraînement M10" },
    ],
    fetcher: async (active) => {
      const [status, registry, loao, h3, reports] = await Promise.all([
        active.includes("status") ? mlAPI.getStatus() : Promise.resolve(null),
        active.includes("versions")
          ? mlAPI.getRegistry()
          : Promise.resolve(null),
        active.includes("loao")
          ? mlAPI.getLoaoResults()
          : Promise.resolve(null),
        active.includes("h3") ? mlAPI.getH3() : Promise.resolve(null),
        active.includes("reports")
          ? mlAPI.getReports()
          : Promise.resolve(null),
      ]);

      const out: any = {
        exported_at: new Date().toISOString(),
      };

      if (status) out.status = status;

      if (registry) {
        out.registry = {
          active_version: registry.active_version,
          total_versions: registry.total_versions,
          versions: registry.versions,
          h3_validation: registry.h3_validation,
        };
      }

      if (loao) out.loao = loao;
      if (h3) out.h3 = h3;
      if (reports) out.reports = reports;

      return JSON.stringify(out, null, 2);
    },
  },

  {
    id: "cicd-json",
    name: "CI/CD — JSON",
    description: "Historique runs, taux blocage H5, quality gate config",
    format: "json",
    color: "bg-teal-500/10 border-teal-500/30",
    sections: [
      { key: "summary", label: "Résumé (total / bloqué / passé)" },
      { key: "block_rate", label: "Taux de blocage & validation H5" },
      { key: "runs", label: "Détail des 50 derniers runs" },
      { key: "gate_cfg", label: "Configuration quality gate" },
    ],
    fetcher: async (active) => {
      const [data, gateConfig] = await Promise.all([
        cicdAPI.getRuns(),
        active.includes("gate_cfg")
          ? cicdAPI.getGateConfig()
          : Promise.resolve(null),
      ]);

      const out: any = {
        exported_at: new Date().toISOString(),
      };

      if (active.includes("summary")) {
        out.summary = {
          total: data.total,
          blocked: data.blocked,
          passed: data.passed,
          running: data.running,
        };
      }

      if (active.includes("block_rate")) {
        out.block_rate = {
          rate: data.block_rate,
          h5_validated: data.h5_status,
        };
      }

      if (active.includes("runs")) {
        out.runs = data.runs ?? [];
      }

      if (gateConfig) {
        out.gate_config = gateConfig;
      }

      return JSON.stringify(out, null, 2);
    },
  },
];

// ─────────────────────────────────────────────────────────────
// Constantes UI exports classiques
// ─────────────────────────────────────────────────────────────

const FORMAT_ICON: Record<ReportFormat, React.ReactNode> = {
  csv: <FileSpreadsheet size={20} className="text-green-400" />,
  json: <FileJson size={20} className="text-blue-400" />,
};

const FORMAT_MIME: Record<ReportFormat, string> = {
  csv: "text/csv",
  json: "application/json",
};

// ─────────────────────────────────────────────────────────────
// Rapports LLM
// ─────────────────────────────────────────────────────────────

type LLMReportOption = {
  id: LLMReportType;
  label: string;
  description: string;
  incidentRequired: boolean;
};

const LLM_REPORT_TYPES: LLMReportOption[] = [
  {
    id: "security_summary",
    label: "Synthèse sécurité",
    description:
      "Vue globale : alertes IDS, incidents, MITRE, SAST/DAST et recommandations.",
    incidentRequired: false,
  },
  {
    id: "incident_analysis",
    label: "Analyse d'incident",
    description:
      "Analyse détaillée d'un incident précis avec corrélation IDS / SAST / DAST.",
    incidentRequired: true,
  },
  {
    id: "sast_dast_summary",
    label: "Rapport SAST / DAST",
    description:
      "Synthèse AppSec des vulnérabilités code et web avec priorisation.",
    incidentRequired: false,
  },
  {
    id: "executive_briefing",
    label: "Briefing exécutif",
    description:
      "Résumé court, non technique, destiné au RSSI ou à la direction.",
    incidentRequired: false,
  },
];

// ─────────────────────────────────────────────────────────────
// ReportCard classique
// ─────────────────────────────────────────────────────────────

function ReportCard({
  template,
  onGenerate,
}: {
  template: ReportTemplate;
  onGenerate: (t: ReportTemplate) => void;
}) {
  return (
    <Card
      className={cn(
        "border transition-all duration-200 hover:scale-[1.02] cursor-pointer",
        template.color
      )}
    >
      <CardContent className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-background/50">
              {FORMAT_ICON[template.format]}
            </div>

            <div>
              <h4 className="font-medium text-sm">{template.name}</h4>
              <p className="text-xs text-muted-foreground mt-0.5">
                {template.description}
              </p>
            </div>
          </div>

          <Badge variant="secondary" className="uppercase text-[10px]">
            {template.format}
          </Badge>
        </div>

        <div className="mt-3 flex flex-wrap gap-1">
          {template.sections.slice(0, 3).map((s) => (
            <span
              key={s.key}
              className="text-[10px] px-1.5 py-0.5 rounded bg-background/50 text-muted-foreground"
            >
              {s.label}
            </span>
          ))}

          {template.sections.length > 3 && (
            <span className="text-[10px] text-muted-foreground">
              +{template.sections.length - 3}
            </span>
          )}
        </div>

        <Button
          size="sm"
          className="w-full mt-4 bg-violet-600 hover:bg-violet-700"
          onClick={() => onGenerate(template)}
        >
          <Download size={14} className="mr-2" />
          Configurer &amp; télécharger
        </Button>
      </CardContent>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────
// MetricBox
// ─────────────────────────────────────────────────────────────

function MetricBox({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl bg-background/40 border border-border/50 p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-lg font-bold">{value}</div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Composant principal
// ─────────────────────────────────────────────────────────────

export function Reports() {
  // Exports classiques
  const [selected, setSelected] = useState<ReportTemplate | null>(null);
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated] = useState(false);
  const [error, setError] = useState("");
  const [dateRange, setDateRange] = useState({ start: "", end: "" });
  const [activeSections, setActiveSections] = useState<string[]>([]);

  const [recentReports, setRecentReports] = useState<
    {
      name: string;
      date: string;
      size: string;
      format: ReportFormat;
      rows: number;
    }[]
  >([]);

  // LLM reports
  const [llmReportType, setLlmReportType] =
    useState<LLMReportType>("security_summary");
  const [llmLanguage, setLlmLanguage] = useState<LLMReportLanguage>("fr");
  const [llmPeriodDays, setLlmPeriodDays] = useState<number>(7);
  const [llmIncidentId, setLlmIncidentId] = useState<string>("");

  const [llmLoading, setLlmLoading] = useState(false);
  const [llmMarkdown, setLlmMarkdown] = useState<string>("");
  const [llmError, setLlmError] = useState<string | null>(null);
  const [llmMeta, setLlmMeta] = useState<LLMReportResponse | null>(null);

  const selectedLLMReport = useMemo(
    () => LLM_REPORT_TYPES.find((r) => r.id === llmReportType),
    [llmReportType]
  );

  const canGenerateLLM =
    llmReportType !== "incident_analysis" ||
    (llmIncidentId.trim() !== "" && Number(llmIncidentId) > 0);

  const llmRenderedHtml = useMemo(() => {
    if (!llmMarkdown) return "";
    return markdownToHtml(llmMarkdown);
  }, [llmMarkdown]);

  const openDialog = (t: ReportTemplate) => {
    setSelected(t);
    setActiveSections(t.sections.map((s) => s.key));
    setGenerated(false);
    setError("");
  };

  const closeDialog = () => {
    setSelected(null);
    setGenerated(false);
    setGenerating(false);
    setError("");
  };

  const toggleSection = (key: string) => {
    setActiveSections((prev) =>
      prev.includes(key) ? prev.filter((x) => x !== key) : [...prev, key]
    );
  };

  const confirmGenerate = useCallback(async () => {
    if (!selected) return;

    setGenerating(true);
    setError("");

    try {
      const content = await selected.fetcher(activeSections, dateRange);
      const filename = `cybersentinel_${selected.id}_${new Date()
        .toISOString()
        .slice(0, 10)}.${selected.format}`;

      downloadBlob(content, filename, FORMAT_MIME[selected.format]);

      const sizeKB = (new Blob([content]).size / 1024).toFixed(1);

      let rows = 0;

      if (selected.format === "csv") {
        rows = content.split("\n").length - 1;
      } else {
        try {
          const p = JSON.parse(content);
          rows =
            p.total ??
            p.incidents?.length ??
            p.runs?.length ??
            Object.keys(p).length;
        } catch {
          rows = 0;
        }
      }

      setRecentReports((prev) => [
        {
          name: filename,
          date: new Date().toLocaleDateString("fr-FR"),
          size: `${sizeKB} KB`,
          format: selected.format,
          rows,
        },
        ...prev.slice(0, 9),
      ]);

      setGenerated(true);
    } catch (e: any) {
      const msg = String(e?.message ?? "Erreur inconnue");
      setError(msg.length > 300 ? msg.slice(0, 300) + "…" : msg);
    } finally {
      setGenerating(false);
    }
  }, [selected, activeSections, dateRange]);

  const generateLLMReport = async () => {
    try {
      setLlmLoading(true);
      setLlmError(null);
      setLlmMarkdown("");
      setLlmMeta(null);

      const result = await reportsAPI.analyze({
        report_type: llmReportType,
        language: llmLanguage,
        period_days: llmPeriodDays,
        incident_id:
          llmReportType === "incident_analysis"
            ? Number(llmIncidentId)
            : null,
      });

      setLlmMarkdown(result.markdown || "");
      setLlmMeta(result);
    } catch (e: any) {
      const msg = String(
        e?.message || "Erreur pendant la génération du rapport LLM."
      );
      setLlmError(msg.length > 400 ? msg.slice(0, 400) + "…" : msg);
    } finally {
      setLlmLoading(false);
    }
  };

  const exportLLMMarkdown = () => {
    if (!llmMarkdown) return;

    const filename = `cybersentinel_llm_${llmReportType}_${Date.now()}.md`;
    downloadBlob(llmMarkdown, filename, "text/markdown;charset=utf-8");
  };

  const exportLLMHtml = () => {
    if (!llmMarkdown) return;

    const title = selectedLLMReport?.label || "Rapport CyberSentinel";
    const html = buildHtmlDocument(llmMarkdown, title);
    const filename = `cybersentinel_llm_${llmReportType}_${Date.now()}.html`;

    downloadBlob(html, filename, "text/html;charset=utf-8");
  };

  return (
    <div className="p-6 space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Reports</h1>
        <p className="text-sm text-muted-foreground">
          Exports CSV / JSON et rapports narratifs LLM depuis le backend
          CyberSentinel
        </p>
      </div>

      {/* ====================================================== */}
      {/* Rapports LLM */}
      {/* ====================================================== */}

      <Card className="bg-card/50 border-cyber-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain size={20} className="text-emerald-400" />
            Rapports intelligents avec LLM
          </CardTitle>

          <p className="text-sm text-muted-foreground">
            Génère une synthèse narrative à partir des alertes IDS, incidents,
            findings SAST et résultats DAST.
          </p>
        </CardHeader>

        <CardContent className="space-y-6">
          <div className="grid grid-cols-1 xl:grid-cols-[390px_1fr] gap-6">
            {/* Configuration */}
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-3">
                {LLM_REPORT_TYPES.map((option) => (
                  <button
                    key={option.id}
                    onClick={() => setLlmReportType(option.id)}
                    className={cn(
                      "w-full rounded-xl border p-4 text-left transition",
                      llmReportType === option.id
                        ? "border-emerald-500 bg-emerald-500/10 ring-2 ring-emerald-500/20"
                        : "border-border bg-background/40 hover:border-emerald-400/40"
                    )}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="font-semibold text-sm">
                        {option.label}
                      </div>

                      {llmReportType === option.id && (
                        <CheckCircle2 className="h-5 w-5 text-emerald-500" />
                      )}
                    </div>

                    <p className="mt-1 text-xs leading-5 text-muted-foreground">
                      {option.description}
                    </p>
                  </button>
                ))}
              </div>

              <div>
                <label className="mb-2 block text-sm font-medium">Langue</label>

                <select
                  value={llmLanguage}
                  onChange={(e) =>
                    setLlmLanguage(e.target.value as LLMReportLanguage)
                  }
                  className="w-full rounded-xl border border-border bg-background px-3 py-2 text-sm outline-none"
                >
                  <option value="fr">Français</option>
                  <option value="en">English</option>
                </select>
              </div>

              <div>
                <label className="mb-2 block text-sm font-medium">
                  Période d’analyse
                </label>

                <select
                  value={llmPeriodDays}
                  onChange={(e) => setLlmPeriodDays(Number(e.target.value))}
                  className="w-full rounded-xl border border-border bg-background px-3 py-2 text-sm outline-none"
                >
                  <option value={1}>Dernières 24h</option>
                  <option value={7}>7 derniers jours</option>
                  <option value={14}>14 derniers jours</option>
                  <option value={30}>30 derniers jours</option>
                  <option value={90}>90 derniers jours</option>
                </select>
              </div>

              {llmReportType === "incident_analysis" && (
                <div>
                  <label className="mb-2 block text-sm font-medium">
                    ID de l’incident
                  </label>

                  <input
                    type="number"
                    min={1}
                    value={llmIncidentId}
                    onChange={(e) => setLlmIncidentId(e.target.value)}
                    placeholder="Exemple : 12"
                    className="w-full rounded-xl border border-border bg-background px-3 py-2 text-sm outline-none"
                  />

                  <p className="mt-2 text-xs text-muted-foreground">
                    Obligatoire pour reconstruire la chaîne d’attaque d’un
                    incident.
                  </p>
                </div>
              )}

              {!canGenerateLLM && (
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-500">
                  <div className="flex gap-2">
                    <AlertTriangle className="mt-0.5 h-4 w-4" />
                    <span>
                      Entre un ID incident valide pour ce type de rapport.
                    </span>
                  </div>
                </div>
              )}

              <Button
                onClick={generateLLMReport}
                disabled={llmLoading || !canGenerateLLM}
                className={cn(
                  "w-full",
                  llmLoading || !canGenerateLLM
                    ? "cursor-not-allowed"
                    : "bg-emerald-600 hover:bg-emerald-700"
                )}
              >
                {llmLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Génération en cours...
                  </>
                ) : (
                  <>
                    <Sparkles className="h-4 w-4 mr-2" />
                    Générer le rapport LLM
                  </>
                )}
              </Button>

              {llmMeta && (
                <div className="rounded-xl border border-border bg-background/40 p-4">
                  <h3 className="mb-3 text-sm font-semibold">
                    Données analysées
                  </h3>

                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <MetricBox
                      label="Alertes"
                      value={llmMeta.stats?.counts?.alerts ?? 0}
                    />
                    <MetricBox
                      label="Incidents"
                      value={llmMeta.stats?.counts?.incidents ?? 0}
                    />
                    <MetricBox
                      label="SAST"
                      value={llmMeta.stats?.counts?.sast_findings ?? 0}
                    />
                    <MetricBox
                      label="DAST"
                      value={llmMeta.stats?.counts?.dast_findings ?? 0}
                    />
                  </div>

                  <div className="mt-3 text-xs text-muted-foreground">
                    Modèle :{" "}
                    <span className="font-medium">{llmMeta.model}</span>
                  </div>
                </div>
              )}
            </div>

            {/* Preview */}
            <div className="rounded-2xl border border-border bg-background/30">
              <div className="flex flex-col gap-3 border-b border-border p-5 md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="flex items-center gap-2 text-lg font-semibold">
                    <ShieldAlert className="h-5 w-5 text-emerald-500" />
                    Rapport généré
                  </h2>

                  <p className="mt-1 text-sm text-muted-foreground">
                    Le résultat est généré en Markdown et peut être exporté.
                  </p>
                </div>

                {llmMarkdown && (
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={exportLLMMarkdown}>
                      <Download className="h-4 w-4 mr-2" />
                      .md
                    </Button>

                    <Button size="sm" onClick={exportLLMHtml}>
                      <Download className="h-4 w-4 mr-2" />
                      .html
                    </Button>
                  </div>
                )}
              </div>

              <div className="min-h-[420px] p-6">
                {llmError && (
                  <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">
                    <div className="mb-1 font-semibold">Erreur</div>
                    {llmError}
                  </div>
                )}

                {llmLoading && (
                  <div className="flex min-h-[360px] flex-col items-center justify-center text-center">
                    <Loader2 className="mb-4 h-10 w-10 animate-spin text-emerald-500" />

                    <h3 className="text-lg font-semibold">
                      Analyse LLM en cours
                    </h3>

                    <p className="mt-2 max-w-md text-sm text-muted-foreground">
                      CyberSentinel collecte les données, construit le contexte,
                      puis génère un rapport narratif via Ollama.
                    </p>
                  </div>
                )}

                {!llmLoading && !llmMarkdown && !llmError && (
                  <div className="flex min-h-[360px] flex-col items-center justify-center text-center">
                    <div className="mb-4 rounded-2xl bg-emerald-500/10 p-4">
                      <FileText className="h-10 w-10 text-emerald-500" />
                    </div>

                    <h3 className="text-lg font-semibold">
                      Aucun rapport généré
                    </h3>

                    <p className="mt-2 max-w-md text-sm text-muted-foreground">
                      Choisis un type de rapport, une période, puis lance la
                      génération.
                    </p>
                  </div>
                )}

                {!llmLoading && llmMarkdown && (
                  <article
                    className="prose prose-slate dark:prose-invert max-w-none text-sm"
                    dangerouslySetInnerHTML={{ __html: llmRenderedHtml }}
                  />
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* ====================================================== */}
      {/* Exports classiques CSV / JSON */}
      {/* ====================================================== */}

      <div>
        <h2 className="text-lg font-semibold">Exports classiques CSV / JSON</h2>
        <p className="text-sm text-muted-foreground">
          Téléchargement brut des données depuis les modules CyberSentinel.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {TEMPLATES.map((t) => (
          <ReportCard key={t.id} template={t} onGenerate={openDialog} />
        ))}
      </div>

      {recentReports.length > 0 && (
        <Card className="bg-card/50 border-cyber-border">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <FileText size={16} className="text-violet-400" />
              Générés cette session
            </CardTitle>
          </CardHeader>

          <CardContent>
            <div className="space-y-2">
              {recentReports.map((r, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between p-3 rounded-lg bg-card/30 hover:bg-card/60 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    {FORMAT_ICON[r.format]}

                    <div>
                      <p className="text-sm font-medium font-mono">{r.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {r.date} · {r.size} · {r.rows.toLocaleString()} entrées
                      </p>
                    </div>
                  </div>

                  <Badge variant="secondary" className="uppercase text-[10px]">
                    {r.format}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Modal exports classiques */}
      {selected && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,.6)",
            zIndex: 60,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "24px",
          }}
          onClick={closeDialog}
        >
          <div
            style={{
              width: "100%",
              maxWidth: "540px",
              background: "hsl(var(--card))",
              border: "1px solid hsl(var(--border))",
              borderRadius: 16,
              padding: 24,
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                marginBottom: 20,
              }}
            >
              <div className="flex items-center gap-3">
                {FORMAT_ICON[selected.format]}

                <div>
                  <h2 style={{ fontSize: 16, fontWeight: 600, margin: 0 }}>
                    {selected.name}
                  </h2>

                  <p style={{ fontSize: 12, opacity: 0.6, margin: 0 }}>
                    {selected.description}
                  </p>
                </div>
              </div>

              <button
                onClick={closeDialog}
                style={{
                  border: "none",
                  background: "transparent",
                  cursor: "pointer",
                  opacity: 0.5,
                }}
              >
                <X size={18} />
              </button>
            </div>

            {generated ? (
              <div style={{ textAlign: "center", padding: "12px 0" }}>
                <div
                  style={{
                    width: 52,
                    height: 52,
                    borderRadius: "50%",
                    background: "rgba(34,197,94,.12)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    margin: "0 auto 12px",
                  }}
                >
                  <CheckCircle2 size={26} className="text-green-400" />
                </div>

                <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 4 }}>
                  Rapport téléchargé
                </h3>

                <p style={{ fontSize: 12, opacity: 0.6, marginBottom: 16 }}>
                  {recentReports[0]?.rows?.toLocaleString()} entrées ·{" "}
                  {recentReports[0]?.size}
                </p>

                <div className="flex gap-2">
                  <Button variant="outline" className="flex-1" onClick={closeDialog}>
                    Fermer
                  </Button>

                  <Button
                    className="flex-1 bg-violet-600 hover:bg-violet-700"
                    onClick={confirmGenerate}
                  >
                    <RefreshCw size={14} className="mr-2" />
                    Re-télécharger
                  </Button>
                </div>
              </div>
            ) : (
              <div className="space-y-5">
                <div>
                  <p style={{ fontSize: 12, fontWeight: 500, marginBottom: 8 }}>
                    Plage de dates{" "}
                    <span style={{ fontWeight: 400, opacity: 0.5 }}>
                      (optionnel)
                    </span>
                  </p>

                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "1fr 1fr",
                      gap: 10,
                    }}
                  >
                    {(["start", "end"] as const).map((k) => (
                      <div key={k} style={{ position: "relative" }}>
                        <Calendar
                          size={13}
                          style={{
                            position: "absolute",
                            left: 10,
                            top: "50%",
                            transform: "translateY(-50%)",
                            opacity: 0.4,
                            pointerEvents: "none",
                          }}
                        />

                        <input
                          type="date"
                          style={{
                            width: "100%",
                            paddingLeft: 30,
                            paddingRight: 8,
                            paddingTop: 8,
                            paddingBottom: 8,
                            borderRadius: 8,
                            border: "0.5px solid hsl(var(--border))",
                            background: "transparent",
                            fontSize: 12,
                            boxSizing: "border-box",
                            color: "inherit",
                          }}
                          value={dateRange[k]}
                          onChange={(e) =>
                            setDateRange((p) => ({
                              ...p,
                              [k]: e.target.value,
                            }))
                          }
                        />
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginBottom: 8,
                    }}
                  >
                    <p style={{ fontSize: 12, fontWeight: 500, margin: 0 }}>
                      Sections{" "}
                      <span style={{ fontWeight: 400, opacity: 0.5 }}>
                        ({activeSections.length}/{selected.sections.length})
                      </span>
                    </p>

                    <div style={{ display: "flex", gap: 10 }}>
                      {["Tout", "Aucun"].map((lbl) => (
                        <button
                          key={lbl}
                          onClick={() =>
                            setActiveSections(
                              lbl === "Tout"
                                ? selected.sections.map((s) => s.key)
                                : []
                            )
                          }
                          style={{
                            fontSize: 11,
                            background: "transparent",
                            border: "none",
                            cursor: "pointer",
                            opacity: 0.55,
                            textDecoration: "underline",
                          }}
                        >
                          {lbl}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 6,
                      maxHeight: 180,
                      overflowY: "auto",
                    }}
                  >
                    {selected.sections.map((s) => (
                      <label
                        key={s.key}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 8,
                          fontSize: 13,
                          cursor: "pointer",
                          userSelect: "none",
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={activeSections.includes(s.key)}
                          onChange={() => toggleSection(s.key)}
                          style={{ accentColor: "#7c3aed" }}
                        />

                        {s.label}
                      </label>
                    ))}
                  </div>
                </div>

                {error && (
                  <div
                    style={{
                      display: "flex",
                      alignItems: "flex-start",
                      gap: 8,
                      padding: "10px 12px",
                      borderRadius: 8,
                      background: "rgba(239,68,68,.08)",
                      border: "0.5px solid rgba(239,68,68,.3)",
                      fontSize: 12,
                      color: "#f87171",
                    }}
                  >
                    <AlertTriangle
                      size={14}
                      style={{
                        flexShrink: 0,
                        marginTop: 1,
                      }}
                    />

                    <span style={{ wordBreak: "break-word" }}>{error}</span>
                  </div>
                )}

                <div className="flex gap-2 pt-1">
                  <Button
                    variant="outline"
                    className="flex-1"
                    onClick={closeDialog}
                  >
                    Annuler
                  </Button>

                  <Button
                    className="flex-1 bg-violet-600 hover:bg-violet-700"
                    onClick={confirmGenerate}
                    disabled={generating || activeSections.length === 0}
                  >
                    {generating ? (
                      <>
                        <Loader2 size={14} className="mr-2 animate-spin" />
                        Génération…
                      </>
                    ) : (
                      <>
                        <Download size={14} className="mr-2" />
                        Télécharger
                      </>
                    )}
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default Reports;