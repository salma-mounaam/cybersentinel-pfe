// ============================================================
// pages/Incidents.tsx
// FIXES :
//   [#15] Uniformisation des valeurs de filtre sévérité
//   [#11] Appel API avec offset pour pagination correcte
//   [#16] Description détaillée dans le modal incident
//   [#17] Affichage attack_type LLM dans minicard + modal
//   [#18] Tri incidents par date décroissante
// ============================================================

import React, { useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { incidentsAPI } from "../services/api";
import {
  AlertTriangle,
  Search,
  Calendar,
  User,
  Send,
  X,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { Card, CardContent } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";

type IncidentStatus =
  | "OPEN"
  | "IN_REVIEW"
  | "RESOLVED"
  | "FALSE_POSITIVE"
  | string;

const statusOptions: { value: IncidentStatus; label: string; color: string }[] =
  [
    { value: "OPEN", label: "Ouvert", color: "var(--cs-red)" },
    { value: "IN_REVIEW", label: "En revue", color: "var(--cs-amber)" },
    { value: "RESOLVED", label: "Résolu", color: "var(--cs-green)" },
    {
      value: "FALSE_POSITIVE",
      label: "Faux positif",
      color: "var(--cs-text3)",
    },
  ];

const severityOptions: { value: string; label: string }[] = [
  { value: "all", label: "Toutes sévérités" },
  { value: "CRITIQUE", label: "Critique" },
  { value: "ELEVE", label: "Élevé" },
  { value: "MOYEN", label: "Moyen" },
  { value: "FAIBLE", label: "Faible" },
];

const PAGE_SIZE = 12;

function formatDate(value?: string) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString("fr-FR");
  } catch {
    return value;
  }
}

function normalizeSeverity(sev?: string): string {
  const map: Record<string, string> = {
    CRITICAL: "CRITIQUE",
    HIGH: "ELEVE",
    MEDIUM: "MOYEN",
    LOW: "FAIBLE",
    CRITIQUE: "CRITIQUE",
    ELEVE: "ELEVE",
    ÉLEVÉ: "ELEVE",
    ELEVÉ: "ELEVE",
    MOYEN: "MOYEN",
    FAIBLE: "FAIBLE",
  };
  return map[(sev || "").toUpperCase()] ?? (sev || "FAIBLE").toUpperCase();
}

function severityColor(sev?: string) {
  const s = normalizeSeverity(sev);
  if (s === "CRITIQUE") return "var(--cs-red)";
  if (s === "ELEVE") return "var(--cs-amber)";
  if (s === "MOYEN") return "var(--cs-blue)";
  return "var(--cs-green)";
}

function scoreBg(score?: number) {
  const v = Number(score || 0);
  if (v >= 8) return "rgba(239,68,68,.12)";
  if (v >= 6) return "rgba(245,158,11,.12)";
  if (v >= 4) return "rgba(59,130,246,.12)";
  return "rgba(34,197,94,.12)";
}

function scoreColor(score?: number) {
  const v = Number(score || 0);
  if (v >= 8) return "var(--cs-red)";
  if (v >= 6) return "var(--cs-amber)";
  if (v >= 4) return "var(--cs-blue)";
  return "var(--cs-green)";
}

function SeverityPill({ severity }: { severity?: string }) {
  const normalized = normalizeSeverity(severity);
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "2px 8px",
        borderRadius: "999px",
        fontSize: "10px",
        fontWeight: 600,
        background: `${severityColor(normalized)}22`,
        color: severityColor(normalized),
        border: `0.5px solid ${severityColor(normalized)}55`,
      }}
    >
      {normalized}
    </span>
  );
}

// [#17] Badge violet pour le type d'attaque classifié par LLM
function AttackTypeBadge({ attackType }: { attackType?: string }) {
  if (!attackType) return null;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "2px 8px",
        borderRadius: "999px",
        fontSize: "10px",
        fontWeight: 600,
        background: "rgba(168,85,247,.12)",
        color: "#a855f7",
        border: "0.5px solid rgba(168,85,247,.35)",
        marginBottom: "6px",
      }}
    >
      🤖 {attackType}
    </span>
  );
}

function ScoreRBar({ score }: { score?: number }) {
  const value = Math.max(0, Math.min(10, Number(score || 0)));
  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginBottom: "6px",
          fontSize: "12px",
        }}
      >
        <span style={{ color: "var(--cs-text2)" }}>Score R</span>
        <span
          style={{
            fontFamily: "monospace",
            fontWeight: 700,
            color: scoreColor(value),
          }}
        >
          {value.toFixed(2)} / 10
        </span>
      </div>
      <div
        style={{
          width: "100%",
          height: "8px",
          borderRadius: "999px",
          background: "var(--cs-surface2)",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            width: `${value * 10}%`,
            height: "100%",
            borderRadius: "999px",
            background: scoreColor(value),
          }}
        />
      </div>
    </div>
  );
}

function IncidentMiniCard({
  incident,
  onClick,
}: {
  incident: any;
  onClick: (incident: any) => void;
}) {
  return (
    <button
      onClick={() => onClick(incident)}
      style={{
        textAlign: "left",
        width: "100%",
        background: "transparent",
        border: "none",
        padding: 0,
        cursor: "pointer",
      }}
    >
      <div
        style={{
          background: "var(--cs-surface)",
          border: "1px solid var(--cs-border)",
          borderRadius: "14px",
          padding: "16px",
          transition: "all .18s ease",
          boxShadow: "0 2px 10px rgba(0,0,0,.12)",
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.borderColor = "rgba(59,130,246,.35)";
          e.currentTarget.style.transform = "translateY(-1px)";
          e.currentTarget.style.background = "rgba(255,255,255,.025)";
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.borderColor = "var(--cs-border)";
          e.currentTarget.style.transform = "translateY(0)";
          e.currentTarget.style.background = "var(--cs-surface)";
        }}
      >
        <div className="flex items-start justify-between gap-3 mb-3">
          <div style={{ minWidth: 0 }}>
            <div
              style={{
                fontSize: "10px",
                color: "var(--cs-text3)",
                fontFamily: "monospace",
                marginBottom: "6px",
              }}
            >
              {incident.id || "—"}
            </div>
            <div
              style={{
                fontWeight: 600,
                marginBottom: "6px",
                color: "var(--cs-text)",
                fontSize: "14px",
                lineHeight: 1.4,
                wordBreak: "break-word",
              }}
            >
              {incident.title || "Incident"}
            </div>
          </div>
          <SeverityPill severity={incident.severity} />
        </div>

        {/* [#17] Badge attack_type LLM */}
        <AttackTypeBadge attackType={incident.attack_type} />

        <div
          style={{
            fontSize: "12px",
            color: "var(--cs-text2)",
            marginBottom: "10px",
            minHeight: "34px",
          }}
        >
          {incident.summary || incident.description || "—"}
        </div>

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "10px",
            gap: "12px",
          }}
        >
          <span
            style={{
              fontSize: "10px",
              padding: "2px 8px",
              borderRadius: "999px",
              background: "var(--cs-surface2)",
              color: "var(--cs-text2)",
              border: "0.5px solid var(--cs-border)",
            }}
          >
            {incident.status || "OPEN"}
          </span>
          <span
            style={{
              fontSize: "12px",
              fontFamily: "monospace",
              fontWeight: 700,
              color: scoreColor(incident.score_r ?? incident.scoreR),
            }}
          >
            R {Number(incident.score_r ?? incident.scoreR ?? 0).toFixed(2)}
          </span>
        </div>

        <div style={{ fontSize: "11px", color: "var(--cs-text3)" }}>
          {formatDate(
            incident.created_at ||
              incident.timestamp ||
              incident.detected_at ||
              incident.updated_at
          )}
        </div>
      </div>
    </button>
  );
}

function Pagination({
  currentPage,
  totalPages,
  onPageChange,
}: {
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
}) {
  if (totalPages <= 1) return null;
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: "8px",
        marginTop: "16px",
      }}
    >
      <Button
        variant="outline"
        size="sm"
        onClick={() => onPageChange(currentPage - 1)}
        disabled={currentPage === 1}
      >
        <ChevronLeft size={14} />
      </Button>
      <span style={{ fontSize: "13px", color: "var(--cs-text2)" }}>
        Page {currentPage} / {totalPages}
      </span>
      <Button
        variant="outline"
        size="sm"
        onClick={() => onPageChange(currentPage + 1)}
        disabled={currentPage === totalPages}
      >
        <ChevronRight size={14} />
      </Button>
    </div>
  );
}

export default function Incidents() {
  const location = useLocation();
  const incidentIdFromState = (location.state as any)?.incidentId;

  const [incidents, setIncidents] = useState<any[]>([]);
  const [totalIncidents, setTotalIncidents] = useState(0);
  const [selectedIncident, setSelectedIncident] = useState<any | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] =
    useState<IncidentStatus | "all">("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [currentPage, setCurrentPage] = useState(1);
  const [newComment, setNewComment] = useState("");
  const [loading, setLoading] = useState(true);

  const loadIncidents = async (page = 1) => {
    setLoading(true);
    try {
      const offset = (page - 1) * PAGE_SIZE;
      const params: Record<string, any> = { limit: PAGE_SIZE, offset };
      if (severityFilter !== "all") params.severity = severityFilter;
      if (statusFilter !== "all") params.status = statusFilter;

      const res = await incidentsAPI.getAll(params);

      const list = Array.isArray(res)
        ? res
        : Array.isArray((res as any)?.incidents)
        ? (res as any).incidents
        : Array.isArray((res as any)?.items)
        ? (res as any).items
        : [];

      const total = (res as any)?.total ?? list.length;

      // [#18] Tri par date décroissante
      const sorted = [...list].sort((a, b) => {
        const da = new Date(a.created_at || a.detected_at || 0).getTime();
        const db = new Date(b.created_at || b.detected_at || 0).getTime();
        return db - da;
      });

      setIncidents(sorted);
      setTotalIncidents(total);
    } catch (e) {
      console.error("Incidents load error:", e);
      setIncidents([]);
      setTotalIncidents(0);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { setCurrentPage(1); }, [severityFilter, statusFilter]);

  useEffect(() => {
    loadIncidents(currentPage);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentPage, severityFilter, statusFilter]);

  useEffect(() => {
    if (!incidentIdFromState || incidents.length === 0) return;
    const found = incidents.find(
      (inc) => String(inc.id) === String(incidentIdFromState)
    );
    if (found) setSelectedIncident(found);
  }, [incidentIdFromState, incidents]);

  const filteredIncidents = useMemo(() => {
    if (!searchQuery.trim()) return incidents;
    const q = searchQuery.toLowerCase();
    return incidents.filter(
      (incident) =>
        (incident.title || "").toLowerCase().includes(q) ||
        (incident.description || "").toLowerCase().includes(q) ||
        (incident.summary || "").toLowerCase().includes(q) ||
        (incident.attack_type || "").toLowerCase().includes(q) ||
        String(incident.id || "").toLowerCase().includes(q)
    );
  }, [incidents, searchQuery]);

  const totalPages = Math.ceil(totalIncidents / PAGE_SIZE);

  const handleStatusChange = async (status: IncidentStatus) => {
    if (!selectedIncident?.id) return;
    try {
      await incidentsAPI.updateStatus(selectedIncident.id, status);
      const updated = { ...selectedIncident, status };
      setSelectedIncident(updated);
      setIncidents((prev) =>
        prev.map((inc) =>
          inc.id === selectedIncident.id ? { ...inc, status } : inc
        )
      );
    } catch (e) {
      console.error("Status update error:", e);
    }
  };

  const handleAddComment = () => {
    if (!selectedIncident || !newComment.trim()) return;
    const comment = {
      id: `COM-${Date.now()}`,
      author: "current.user@cybersentinel.local",
      timestamp: new Date().toISOString(),
      content: newComment,
    };
    const nextComments = [...(selectedIncident.comments || []), comment];
    const updated = { ...selectedIncident, comments: nextComments };
    setSelectedIncident(updated);
    setIncidents((prev) =>
      prev.map((inc) =>
        inc.id === selectedIncident.id ? { ...inc, comments: nextComments } : inc
      )
    );
    setNewComment("");
  };

  const openCount = incidents.filter(
    (i) => (i.status || "").toUpperCase() === "OPEN"
  ).length;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 style={{ fontSize: "28px", fontWeight: 700, color: "var(--cs-text)" }}>
            Incidents
          </h1>
          <p style={{ fontSize: "14px", color: "var(--cs-text2)" }}>
            Gestion des incidents avec score R et SLA
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge
            variant="secondary"
            style={{
              border: "1px solid rgba(239,68,68,.25)",
              background: "rgba(239,68,68,.08)",
              color: "var(--cs-red)",
            }}
          >
            <AlertTriangle size={12} className="mr-1" />
            {openCount} ouverts
          </Badge>
        </div>
      </div>

      <Card
        style={{
          background: "var(--cs-surface)",
          border: "1px solid var(--cs-border)",
          borderRadius: "16px",
        }}
      >
        <CardContent className="p-4">
          <div className="flex flex-wrap items-center gap-4">
            <div style={{ position: "relative", flex: 1, minWidth: 220 }}>
              <Search
                size={16}
                style={{
                  position: "absolute",
                  left: "12px",
                  top: "50%",
                  transform: "translateY(-50%)",
                  color: "var(--cs-text3)",
                }}
              />
              <input
                placeholder="Rechercher un incident ou type d'attaque..."
                value={searchQuery}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setSearchQuery(e.target.value)
                }
                style={{
                  width: "100%",
                  padding: "12px 12px 12px 38px",
                  borderRadius: "10px",
                  background: "var(--cs-surface2)",
                  border: "1px solid var(--cs-border)",
                  color: "var(--cs-text)",
                  fontSize: "14px",
                  outline: "none",
                }}
              />
            </div>

            <select
              value={statusFilter}
              onChange={(e) =>
                setStatusFilter(e.target.value as IncidentStatus | "all")
              }
              style={{
                padding: "12px",
                borderRadius: "10px",
                background: "var(--cs-surface2)",
                border: "1px solid var(--cs-border)",
                color: "var(--cs-text)",
                fontSize: "14px",
                outline: "none",
                minWidth: "170px",
              }}
            >
              <option value="all">Tous les statuts</option>
              {statusOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              style={{
                padding: "12px",
                borderRadius: "10px",
                background: "var(--cs-surface2)",
                border: "1px solid var(--cs-border)",
                color: "var(--cs-text)",
                fontSize: "14px",
                outline: "none",
                minWidth: "170px",
              }}
            >
              {severityOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>
        </CardContent>
      </Card>

      <div style={{ fontSize: "13px", color: "var(--cs-text2)", padding: "0 2px" }}>
        {searchQuery ? (
          <>Résultats filtrés : <strong>{filteredIncidents.length}</strong> sur <strong>{totalIncidents}</strong></>
        ) : (
          <>Total incidents : <strong>{totalIncidents}</strong></>
        )}
      </div>

      {loading ? (
        <div style={{ color: "var(--cs-text2)", fontSize: "14px" }}>Chargement...</div>
      ) : filteredIncidents.length === 0 ? (
        <Card style={{ background: "var(--cs-surface)", border: "1px solid var(--cs-border)", borderRadius: "16px" }}>
          <CardContent className="p-8">
            <div style={{ textAlign: "center", color: "var(--cs-text3)", fontSize: "14px" }}>
              Aucun incident trouvé
            </div>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredIncidents.map((incident) => (
              <IncidentMiniCard
                key={incident.id}
                incident={incident}
                onClick={setSelectedIncident}
              />
            ))}
          </div>
          {!searchQuery && (
            <Pagination
              currentPage={currentPage}
              totalPages={totalPages}
              onPageChange={setCurrentPage}
            />
          )}
        </>
      )}

      {selectedIncident && (
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
          onClick={() => setSelectedIncident(null)}
        >
          <div
            style={{
              width: "100%",
              maxWidth: "980px",
              maxHeight: "90vh",
              overflow: "auto",
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
                gap: "16px",
                marginBottom: "18px",
              }}
            >
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
                  <span style={{ fontSize: "11px", fontFamily: "monospace", color: "var(--cs-text3)" }}>
                    {selectedIncident.id}
                  </span>
                  <SeverityPill severity={selectedIncident.severity} />
                  {/* [#17] Badge attack_type dans le modal */}
                  <AttackTypeBadge attackType={selectedIncident.attack_type} />
                </div>
                <h2 style={{ fontSize: "22px", fontWeight: 700, color: "var(--cs-text)" }}>
                  {selectedIncident.title || "Incident"}
                </h2>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                style={{ border: "none", background: "transparent", color: "var(--cs-text2)", cursor: "pointer" }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ marginBottom: "18px" }}>
              <ScoreRBar score={selectedIncident.score_r ?? selectedIncident.scoreR} />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "18px" }}>
              <div style={{ padding: "12px", borderRadius: "10px", background: "var(--cs-surface2)", border: "0.5px solid var(--cs-border)" }}>
                <div style={{ fontSize: "11px", color: "var(--cs-text3)", marginBottom: "6px" }}>Créé le</div>
                <div style={{ display: "flex", gap: "8px", alignItems: "center", fontSize: "14px", color: "var(--cs-text)" }}>
                  <Calendar size={14} />
                  {formatDate(selectedIncident.created_at || selectedIncident.timestamp || selectedIncident.detected_at)}
                </div>
              </div>
              <div style={{ padding: "12px", borderRadius: "10px", background: "var(--cs-surface2)", border: "0.5px solid var(--cs-border)" }}>
                <div style={{ fontSize: "11px", color: "var(--cs-text3)", marginBottom: "6px" }}>Assigné à</div>
                <div style={{ display: "flex", gap: "8px", alignItems: "center", fontSize: "14px", color: "var(--cs-text)" }}>
                  <User size={14} />
                  {selectedIncident.assigned_to || selectedIncident.assignedTo || "Non assigné"}
                </div>
              </div>
            </div>

            {/* Description détaillée */}
            <div
              style={{
                padding: "14px",
                borderRadius: "10px",
                background: scoreBg(selectedIncident.score_r ?? selectedIncident.scoreR),
                border: "0.5px solid var(--cs-border)",
                marginBottom: "18px",
              }}
            >
              <div style={{ fontSize: "11px", color: "var(--cs-text3)", marginBottom: "8px" }}>
                Description détaillée
              </div>
              <div style={{ fontSize: "14px", color: "var(--cs-text)", lineHeight: 1.7 }}>
                <p style={{ marginBottom: "10px" }}>
                  Cet incident a été généré automatiquement à partir d'une alerte IDS
                  détectée par Suricata, puis analysée par le moteur de fusion hybride M3.
                  Le système corrèle le score signature, le score ML et le contexte temporel
                  afin d'évaluer le niveau de risque.
                </p>

                {/* [#17] Type d'attaque LLM dans la description */}
                {selectedIncident.attack_type && (
                  <p style={{ marginBottom: "10px" }}>
                    <strong>Type d'attaque (LLM) :</strong>{" "}
                    <span style={{ color: "#a855f7", fontWeight: 600 }}>
                      🤖 {selectedIncident.attack_type}
                    </span>
                    {" "}— classifié par Llama 3.1 8B via Ollama.
                  </p>
                )}

                <p style={{ marginBottom: "10px" }}>
                  <strong>Résumé :</strong>{" "}
                  {selectedIncident.description || selectedIncident.summary || "Aucune description fournie."}
                </p>

                <p style={{ marginBottom: "10px" }}>
                  <strong>Sévérité :</strong>{" "}
                  {normalizeSeverity(selectedIncident.severity)} — cette valeur représente
                  la priorité de traitement par l'analyste SOC.
                </p>

                <p style={{ marginBottom: "10px" }}>
                  <strong>Score R :</strong>{" "}
                  {Number(selectedIncident.score_r ?? selectedIncident.scoreR ?? 0).toFixed(2)} / 10.
                  Plus ce score est élevé, plus l'incident doit être traité rapidement.
                </p>

                {(selectedIncident.src_ip || selectedIncident.asset_ip || selectedIncident.dest_ip) && (
                  <p style={{ marginBottom: "10px" }}>
                    <strong>Flux concerné :</strong> source{" "}
                    {selectedIncident.src_ip || "—"} vers cible{" "}
                    {selectedIncident.asset_ip || selectedIncident.dest_ip || "—"}.
                  </p>
                )}

                {selectedIncident.confidence !== undefined && (
                  <p style={{ marginBottom: "10px" }}>
                    <strong>Confiance fusion :</strong>{" "}
                    {Number(selectedIncident.confidence).toFixed(3)}. Cette valeur indique
                    le niveau de certitude calculé par le moteur de fusion.
                  </p>
                )}

                {selectedIncident.fusion_case && (
                  <p style={{ marginBottom: "10px" }}>
                    <strong>Cas de fusion :</strong> Cas {selectedIncident.fusion_case}.
                    Il indique le type de corrélation utilisé entre Suricata, ML et contexte temporel.
                  </p>
                )}

                {selectedIncident.technique_id && (
                  <p style={{ marginBottom: 0 }}>
                    <strong>MITRE ATT&CK :</strong> technique associée{" "}
                    {selectedIncident.technique_id}
                    {selectedIncident.technique_name ? ` — ${selectedIncident.technique_name}` : ""}.
                  </p>
                )}
              </div>
            </div>

            <div style={{ marginBottom: "18px" }}>
              <div style={{ fontSize: "12px", color: "var(--cs-text2)", marginBottom: "10px" }}>
                Changer le statut
              </div>
              <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                {statusOptions.map((opt) => (
                  <Button
                    key={opt.value}
                    variant={
                      (selectedIncident.status || "").toUpperCase() === opt.value
                        ? "default"
                        : "outline"
                    }
                    size="sm"
                    onClick={() => handleStatusChange(opt.value)}
                  >
                    {opt.label}
                  </Button>
                ))}
              </div>
            </div>

            {!!selectedIncident.technique_id && (
              <div
                style={{
                  padding: "14px",
                  borderRadius: "10px",
                  background: "var(--cs-surface2)",
                  border: "0.5px solid var(--cs-border)",
                  marginBottom: "18px",
                }}
              >
                <div style={{ fontSize: "11px", color: "var(--cs-text3)", marginBottom: "8px" }}>
                  MITRE ATT&CK
                </div>
                <span
                  style={{
                    display: "inline-flex",
                    padding: "4px 10px",
                    borderRadius: "999px",
                    fontSize: "11px",
                    fontFamily: "monospace",
                    background: "rgba(59,130,246,.12)",
                    color: "var(--cs-blue)",
                    border: "0.5px solid rgba(59,130,246,.35)",
                  }}
                >
                  {selectedIncident.technique_id}
                </span>
              </div>
            )}

            <div style={{ padding: "14px", borderRadius: "10px", background: "var(--cs-surface2)", border: "0.5px solid var(--cs-border)" }}>
              <div style={{ fontSize: "12px", color: "var(--cs-text2)", marginBottom: "10px" }}>
                Commentaires ({(selectedIncident.comments || []).length})
              </div>
              <div style={{ display: "grid", gap: "10px", marginBottom: "14px" }}>
                {(selectedIncident.comments || []).map((comment: any) => (
                  <div
                    key={comment.id}
                    style={{
                      padding: "12px",
                      borderRadius: "8px",
                      background: "var(--cs-surface)",
                      border: "0.5px solid var(--cs-border)",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px", fontSize: "12px" }}>
                      <span style={{ fontWeight: 600, color: "var(--cs-text)" }}>{comment.author}</span>
                      <span style={{ color: "var(--cs-text3)" }}>{formatDate(comment.timestamp)}</span>
                    </div>
                    <div style={{ fontSize: "14px", color: "var(--cs-text)" }}>{comment.content}</div>
                  </div>
                ))}
              </div>
              <div style={{ display: "flex", gap: "10px", alignItems: "flex-start" }}>
                <textarea
                  placeholder="Ajouter un commentaire..."
                  value={newComment}
                  onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setNewComment(e.target.value)}
                  rows={3}
                  style={{
                    width: "100%",
                    borderRadius: "10px",
                    background: "var(--cs-surface)",
                    border: "1px solid var(--cs-border)",
                    color: "var(--cs-text)",
                    fontSize: "14px",
                    outline: "none",
                    padding: "12px",
                    resize: "vertical",
                  }}
                />
                <Button onClick={handleAddComment}><Send size={16} /></Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}