// ============================================================
// pages/Reports.tsx — Rapports connectés au vrai backend
// Version compatible sans input/label/checkbox/dialog shadcn
// ============================================================
import React, { useState, useCallback } from "react";
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
} from "../services/api";

// ── Types ─────────────────────────────────────────────────────
type ReportFormat = "csv" | "json";

interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  format: ReportFormat;
  sections: string[];
  color: string;
  fetcher: (
    sections: string[],
    dateRange: { start: string; end: string }
  ) => Promise<string>;
}

// ── Helpers export ────────────────────────────────────────────
function toCSV(rows: any[], headers: string[]): string {
  const escape = (v: any) => {
    const s = String(v ?? "");
    return s.includes(",") || s.includes('"') || s.includes("\n")
      ? `"${s.replace(/"/g, '""')}"`
      : s;
  };

  return [
    headers.join(","),
    ...rows.map((r) => headers.map((h) => escape(r[h])).join(",")),
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

// ── Templates connectés au backend ───────────────────────────
const TEMPLATES: ReportTemplate[] = [
  {
    id: "incidents-csv",
    name: "Incidents — CSV",
    description: "Score R décomposé A/V/E/C, MITRE, SLA, statut",
    format: "csv",
    sections: ["score_r", "mitre", "sla", "statut", "actif"],
    color: "bg-green-500/10 border-green-500/30",
    fetcher: async (sections) => {
      const data = await incidentsAPI.getAll({ limit: 500 });
      const incs = data.incidents || [];
      const headers = ["id", "titre", "severite", "score_r"];

      if (sections.includes("score_r")) headers.push("score_a", "score_v", "score_e", "score_c");
      if (sections.includes("mitre")) headers.push("technique_id", "tactic");
      if (sections.includes("sla")) headers.push("sla_deadline");
      if (sections.includes("statut")) headers.push("status");
      if (sections.includes("actif")) headers.push("asset_ip", "asset_criticality");

      const rows = incs.map((i: any) => ({
        id: i.id,
        titre: i.title,
        severite: i.severity,
        score_r: i.score_r,
        score_a: i.score_a,
        score_v: i.score_v,
        score_e: i.score_e,
        score_c: i.score_c,
        technique_id: i.technique_id,
        tactic: i.tactic,
        sla_deadline: i.sla_deadline,
        status: i.status,
        asset_ip: i.asset_ip,
        asset_criticality: i.asset_criticality,
      }));

      return toCSV(rows, headers);
    },
  },
  {
    id: "alerts-csv",
    name: "Alertes IDS — CSV",
    description: "Flux alertes M1/M3 avec scores ML et cas de fusion",
    format: "csv",
    sections: ["ml_scores", "fusion", "mitre", "ips"],
    color: "bg-blue-500/10 border-blue-500/30",
    fetcher: async (sections) => {
      const data = await alertsAPI.getAll({ limit: 1000 });
      const alerts = data.alerts || [];
      const headers = ["id", "severite", "signature", "heure"];

      if (sections.includes("ips")) headers.push("src_ip", "dest_ip", "protocol");
      if (sections.includes("ml_scores")) headers.push("ml_score", "confidence");
      if (sections.includes("fusion")) headers.push("fusion_case");
      if (sections.includes("mitre")) headers.push("technique_id", "tactic");

      const rows = alerts.map((a: any) => ({
        id: a.id,
        severite: a.severity,
        signature: a.signature_name,
        heure: a.detected_at,
        src_ip: a.src_ip,
        dest_ip: a.dest_ip,
        protocol: a.protocol,
        ml_score: a.ml_score,
        confidence: a.confidence,
        fusion_case: a.fusion_case,
        technique_id: a.technique_id,
        tactic: a.tactic,
      }));

      return toCSV(rows, headers);
    },
  },
  {
    id: "sast-csv",
    name: "SAST Findings — CSV",
    description: "Semgrep + Trivy + Gitleaks avec CVSS et fix code",
    format: "csv",
    sections: ["cvss", "cwe", "mitre", "fix", "dast"],
    color: "bg-amber-500/10 border-amber-500/30",
    fetcher: async (sections) => {
      const data = await sastAPI.getFindings({ limit: 1000 });
      const findings = data.findings || [];
      const headers = ["id", "outil", "severite", "titre", "fichier", "ligne"];

      if (sections.includes("cwe")) headers.push("cwe", "cve");
      if (sections.includes("cvss")) headers.push("cvss_score");
      if (sections.includes("mitre")) headers.push("technique_id", "tactic");
      if (sections.includes("fix")) headers.push("fix_suggestion");
      if (sections.includes("dast")) headers.push("dast_confirmed");

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
        fix_suggestion: f.fix_suggestion,
        dast_confirmed: f.dast_confirmed ? "oui" : "non",
      }));

      return toCSV(rows, headers);
    },
  },
  {
    id: "incidents-json",
    name: "Incidents — JSON",
    description: "Export complet avec toutes les métadonnées",
    format: "json",
    sections: ["score_r", "mitre", "sla", "sources"],
    color: "bg-purple-500/10 border-purple-500/30",
    fetcher: async (sections) => {
      const data = await incidentsAPI.getAll({ limit: 500 });
      const incs = (data.incidents || []).map((i: any) => {
        const out: any = {
          id: i.id,
          title: i.title,
          severity: i.severity,
          status: i.status,
          detected_at: i.detected_at,
        };

        if (sections.includes("score_r")) {
          out.score_r = i.score_r;
          out.decomposition = {
            A: i.score_a,
            V: i.score_v,
            E: i.score_e,
            C: i.score_c,
          };
        }

        if (sections.includes("mitre")) {
          out.mitre = {
            technique_id: i.technique_id,
            tactic: i.tactic,
            apt_groups: i.apt_groups,
          };
        }

        if (sections.includes("sla")) {
          out.sla = {
            deadline: i.sla_deadline,
            asset_ip: i.asset_ip,
            asset_criticality: i.asset_criticality,
          };
        }

        if (sections.includes("sources")) {
          out.sources = {
            alert_ids: i.alert_ids,
            sast_finding_ids: i.sast_finding_ids,
            dast_finding_ids: i.dast_finding_ids,
          };
        }

        return out;
      });

      return JSON.stringify(
        {
          exported_at: new Date().toISOString(),
          total: incs.length,
          incidents: incs,
        },
        null,
        2
      );
    },
  },
  {
    id: "ml-json",
    name: "Modèles ML — JSON",
    description: "Registre versions, F1, Recall, FPR, H1/H3",
    format: "json",
    sections: ["versions", "metriques", "h1", "h3"],
    color: "bg-violet-500/10 border-violet-500/30",
    fetcher: async (sections) => {
      const [status, registry, h3, loao] = await Promise.all([
        mlAPI.getStatus(),
        mlAPI.getRegistry(),
        mlAPI.getH3(),
        mlAPI.getLoaoResults(),
      ]);

      const out: any = { exported_at: new Date().toISOString() };

      if (sections.includes("versions")) {
        out.active_version = registry.active_version;
        out.total_versions = registry.total_versions;
      }
      if (sections.includes("metriques")) out.versions = registry.versions;
      if (sections.includes("h1")) out.h1_loao = loao;
      if (sections.includes("h3")) out.h3_delta_f1 = h3;

      return JSON.stringify(out, null, 2);
    },
  },
  {
    id: "cicd-json",
    name: "CI/CD — JSON",
    description: "Historique runs, taux blocage, validation H5",
    format: "json",
    sections: ["runs", "block_rate", "h5"],
    color: "bg-teal-500/10 border-teal-500/30",
    fetcher: async (sections) => {
      const data = await cicdAPI.getRuns();
      const out: any = { exported_at: new Date().toISOString() };

      if (sections.includes("block_rate")) {
        out.total = data.total;
        out.blocked = data.blocked;
        out.passed = data.passed;
        out.block_rate = data.block_rate;
      }
      if (sections.includes("h5")) out.h5_validated = data.h5_status;
      if (sections.includes("runs")) out.runs = data.runs;

      return JSON.stringify(out, null, 2);
    },
  },
];

// ── Icônes par format ─────────────────────────────────────────
const FORMAT_ICON: Record<ReportFormat, React.ReactNode> = {
  csv: <FileSpreadsheet size={20} className="text-green-400" />,
  json: <FileJson size={20} className="text-blue-400" />,
};

const FORMAT_MIME: Record<ReportFormat, string> = {
  csv: "text/csv",
  json: "application/json",
};

// ── Card template ─────────────────────────────────────────────
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

        <div className="mt-4 flex flex-wrap gap-1">
          {template.sections.slice(0, 3).map((s) => (
            <span
              key={s}
              className="text-[10px] px-1.5 py-0.5 rounded bg-background/50 text-muted-foreground"
            >
              {s.replace(/_/g, " ")}
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
          Générer
        </Button>
      </CardContent>
    </Card>
  );
}

// ── Composant principal ───────────────────────────────────────
export function Reports() {
  const [selected, setSelected] = useState<ReportTemplate | null>(null);
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated] = useState(false);
  const [error, setError] = useState("");
  const [dateRange, setDateRange] = useState({ start: "", end: "" });
  const [sections, setSections] = useState<string[]>([]);
  const [recentReports, setRecentReports] = useState<
    { name: string; date: string; size: string; format: ReportFormat }[]
  >([]);

  const openDialog = (t: ReportTemplate) => {
    setSelected(t);
    setSections(t.sections);
    setGenerated(false);
    setError("");
  };

  const closeDialog = () => {
    setSelected(null);
    setGenerated(false);
    setGenerating(false);
    setError("");
  };

  const toggleSection = (s: string) => {
    setSections((prev) =>
      prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]
    );
  };

  const confirmGenerate = useCallback(async () => {
    if (!selected) return;

    setGenerating(true);
    setError("");

    try {
      const content = await selected.fetcher(sections, dateRange);
      const filename = `${selected.id}_${new Date().toISOString().slice(0, 10)}.${selected.format}`;

      downloadBlob(content, filename, FORMAT_MIME[selected.format]);

      const sizeKB = (new Blob([content]).size / 1024).toFixed(0);
      setRecentReports((prev) => [
        {
          name: filename,
          date: new Date().toLocaleDateString("fr-FR"),
          size: `${sizeKB} KB`,
          format: selected.format,
        },
        ...prev.slice(0, 9),
      ]);

      setGenerated(true);
    } catch (e: any) {
      setError(e?.message || "Erreur lors de la génération");
    } finally {
      setGenerating(false);
    }
  }, [selected, sections, dateRange]);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Reports</h1>
          <p className="text-sm text-muted-foreground">
            Export CSV / JSON connecté au backend réel
          </p>
        </div>
      </div>

      {/* Templates */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {TEMPLATES.map((t) => (
          <ReportCard key={t.id} template={t} onGenerate={openDialog} />
        ))}
      </div>

      {/* Rapports récents */}
      {recentReports.length > 0 && (
        <Card className="bg-card/50 border-cyber-border">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <FileText size={16} className="text-violet-400" />
              Rapports générés cette session
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
                      <p className="text-sm font-medium">{r.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {r.date} · {r.size}
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

      {/* Modal simple */}
      {selected && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,.55)",
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
              maxWidth: "640px",
              background: "var(--cs-surface)",
              border: "1px solid var(--cs-border)",
              borderRadius: "16px",
              padding: "20px",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                marginBottom: "16px",
              }}
            >
              <div>
                <h2 style={{ fontSize: "20px", fontWeight: 700 }}>
                  Générer un rapport
                </h2>
                <p style={{ fontSize: "13px", color: "var(--cs-text2)" }}>
                  Paramétrage du template sélectionné
                </p>
              </div>

              <button
                onClick={closeDialog}
                style={{
                  border: "none",
                  background: "transparent",
                  color: "var(--cs-text2)",
                  cursor: "pointer",
                }}
              >
                <X size={20} />
              </button>
            </div>

            {generated ? (
              <div className="text-center py-8">
                <div className="w-16 h-16 rounded-full bg-green-500/10 flex items-center justify-center mx-auto mb-4">
                  <CheckCircle2 size={32} className="text-green-400" />
                </div>

                <h3 className="text-lg font-medium mb-2">Rapport généré !</h3>
                <p className="text-sm text-muted-foreground mb-4">
                  {selected.name} téléchargé avec succès.
                </p>

                <div className="flex gap-2">
                  <Button variant="outline" className="flex-1" onClick={closeDialog}>
                    Fermer
                  </Button>
                  <Button
                    className="flex-1 bg-green-600 hover:bg-green-700"
                    onClick={confirmGenerate}
                  >
                    <Download size={16} className="mr-2" />
                    Re-télécharger
                  </Button>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                {/* Template sélectionné */}
                <div>
                  <div className="text-sm text-muted-foreground mb-2 block">
                    Template sélectionné
                  </div>
                  <div className="p-3 rounded-lg bg-card/30 flex items-center gap-3">
                    {FORMAT_ICON[selected.format]}
                    <span className="font-medium text-sm">{selected.name}</span>
                  </div>
                </div>

                {/* Plage de dates */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="text-sm text-muted-foreground mb-2 block">
                      Date début
                    </div>
                    <div className="relative">
                      <Calendar
                        size={14}
                        className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
                      />
                      <input
                        type="date"
                        className="w-full pl-9 pr-3 py-2 rounded-md bg-card/30 border border-cyber-border text-sm outline-none"
                        value={dateRange.start}
                        onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                          setDateRange((p) => ({ ...p, start: e.target.value }))
                        }
                      />
                    </div>
                  </div>

                  <div>
                    <div className="text-sm text-muted-foreground mb-2 block">
                      Date fin
                    </div>
                    <div className="relative">
                      <Calendar
                        size={14}
                        className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
                      />
                      <input
                        type="date"
                        className="w-full pl-9 pr-3 py-2 rounded-md bg-card/30 border border-cyber-border text-sm outline-none"
                        value={dateRange.end}
                        onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                          setDateRange((p) => ({ ...p, end: e.target.value }))
                        }
                      />
                    </div>
                  </div>
                </div>

                {/* Sections */}
                <div>
                  <div className="text-sm text-muted-foreground mb-2 block">
                    Sections à inclure
                  </div>
                  <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                    {selected.sections.map((s) => (
                      <label
                        key={s}
                        htmlFor={s}
                        className="flex items-center gap-2 text-sm capitalize cursor-pointer"
                      >
                        <input
                          id={s}
                          type="checkbox"
                          checked={sections.includes(s)}
                          onChange={() => toggleSection(s)}
                        />
                        {s.replace(/_/g, " ")}
                      </label>
                    ))}
                  </div>
                </div>

                {/* Erreur */}
                {error && (
                  <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
                    <AlertTriangle size={14} className="shrink-0" />
                    {error}
                  </div>
                )}

                {/* Boutons */}
                <div className="flex gap-2 pt-2">
                  <Button variant="outline" className="flex-1" onClick={closeDialog}>
                    Annuler
                  </Button>
                  <Button
                    className="flex-1 bg-violet-600 hover:bg-violet-700"
                    onClick={confirmGenerate}
                    disabled={generating || sections.length === 0}
                  >
                    {generating ? (
                      <>
                        <Loader2 size={16} className="mr-2 animate-spin" />
                        Génération...
                      </>
                    ) : (
                      <>
                        <Download size={16} className="mr-2" />
                        Générer
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