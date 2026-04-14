import React, { useEffect, useMemo, useState } from "react";
import { incidentsAPI } from "../services/api";
import { AlertTriangle, Search, Calendar, User, Send, X } from "lucide-react";
import { Card, CardContent } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";

type IncidentStatus = "OPEN" | "IN_PROGRESS" | "RESOLVED" | "CLOSED" | string;

const statusOptions: { value: IncidentStatus; label: string; color: string }[] = [
  { value: "OPEN", label: "Ouvert", color: "var(--cs-red)" },
  { value: "IN_PROGRESS", label: "En cours", color: "var(--cs-amber)" },
  { value: "RESOLVED", label: "Résolu", color: "var(--cs-green)" },
  { value: "CLOSED", label: "Fermé", color: "var(--cs-text3)" },
];

function formatDate(value?: string) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString("fr-FR");
  } catch {
    return value;
  }
}

function severityColor(sev?: string) {
  const s = (sev || "").toUpperCase();
  if (s === "CRITICAL" || s === "CRITIQUE") return "var(--cs-red)";
  if (s === "HIGH" || s === "ELEVE" || s === "ÉLEVÉ") return "var(--cs-amber)";
  if (s === "MEDIUM" || s === "MOYEN") return "var(--cs-blue)";
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
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "2px 8px",
        borderRadius: "999px",
        fontSize: "10px",
        fontWeight: 600,
        background: `${severityColor(severity)}22`,
        color: severityColor(severity),
        border: `0.5px solid ${severityColor(severity)}55`,
      }}
    >
      {severity || "LOW"}
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
      }}
    >
      <Card className="bg-card/50 border-cyber-border hover:border-cyber-violet/30 transition-colors">
        <CardContent className="p-4">
          <div className="flex items-start justify-between gap-3 mb-3">
            <div>
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
              <div style={{ fontWeight: 600, marginBottom: "6px" }}>
                {incident.title || "Incident"}
              </div>
            </div>
            <SeverityPill severity={incident.severity} />
          </div>

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
              R {(incident.score_r ?? incident.scoreR ?? 0).toFixed?.(2) ??
                incident.score_r ??
                incident.scoreR ??
                0}
            </span>
          </div>

          <div style={{ fontSize: "11px", color: "var(--cs-text3)" }}>
            {formatDate(incident.created_at || incident.timestamp)}
          </div>
        </CardContent>
      </Card>
    </button>
  );
}

export default function Incidents() {
  const [incidents, setIncidents] = useState<any[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<any | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | "all">("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [newComment, setNewComment] = useState("");
  const [loading, setLoading] = useState(true);

  const loadIncidents = async () => {
    setLoading(true);
    try {
      const res = await incidentsAPI.getAll({ limit: 200 });
      setIncidents(res.incidents || []);
    } catch (e) {
      console.error("Incidents load error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, []);

  const filteredIncidents = useMemo(() => {
    return incidents.filter((incident) => {
      const q = searchQuery.toLowerCase();

      const matchesSearch =
        (incident.title || "").toLowerCase().includes(q) ||
        (incident.description || "").toLowerCase().includes(q) ||
        String(incident.id || "").toLowerCase().includes(q);

      const matchesStatus =
        statusFilter === "all" || (incident.status || "").toUpperCase() === statusFilter;

      const matchesSeverity =
        severityFilter === "all" ||
        (incident.severity || "").toLowerCase() === severityFilter.toLowerCase();

      return matchesSearch && matchesStatus && matchesSeverity;
    });
  }, [incidents, searchQuery, statusFilter, severityFilter]);

  const handleStatusChange = async (status: IncidentStatus) => {
    if (!selectedIncident?.id) return;

    try {
      await incidentsAPI.updateStatus(selectedIncident.id, status);
      const updated = { ...selectedIncident, status };
      setSelectedIncident(updated);
      setIncidents((prev) =>
        prev.map((inc) => (inc.id === selectedIncident.id ? { ...inc, status } : inc))
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
          <h1 className="text-2xl font-bold">Incidents</h1>
          <p className="text-sm text-muted-foreground">
            Gestion des incidents avec score R et SLA
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Badge variant="secondary" className="bg-cyber-red/10 text-cyber-red">
            <AlertTriangle size={12} className="mr-1" />
            {openCount} ouverts
          </Badge>
        </div>
      </div>

      <Card className="bg-card/50 border-cyber-border">
        <CardContent className="p-4">
          <div className="flex flex-wrap items-center gap-4">
            <div style={{ position: "relative", flex: 1, minWidth: 220 }}>
              <Search
                size={16}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
              />
              <input
                placeholder="Rechercher un incident..."
                value={searchQuery}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setSearchQuery(e.target.value)
                }
                className="w-full pl-10 pr-3 py-2 rounded-md bg-cyber-panel border border-cyber-border text-sm outline-none"
              />
            </div>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as IncidentStatus | "all")}
              className="px-3 py-2 rounded-md bg-cyber-panel border border-cyber-border text-sm"
            >
              <option value="all">Tous les statuts</option>
              {statusOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-2 rounded-md bg-cyber-panel border border-cyber-border text-sm"
            >
              <option value="all">Toutes sévérités</option>
              <option value="CRITICAL">Critique</option>
              <option value="HIGH">Élevé</option>
              <option value="MEDIUM">Moyen</option>
              <option value="LOW">Faible</option>
            </select>
          </div>
        </CardContent>
      </Card>

      {loading ? (
        <div style={{ color: "var(--cs-text2)", fontSize: "14px" }}>Chargement...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredIncidents.map((incident) => (
            <IncidentMiniCard
              key={incident.id}
              incident={incident}
              onClick={setSelectedIncident}
            />
          ))}
        </div>
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
                </div>
                <h2 style={{ fontSize: "22px", fontWeight: 700 }}>
                  {selectedIncident.title || "Incident"}
                </h2>
              </div>

              <button
                onClick={() => setSelectedIncident(null)}
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

            <div style={{ marginBottom: "18px" }}>
              <ScoreRBar score={selectedIncident.score_r ?? selectedIncident.scoreR} />
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "16px",
                marginBottom: "18px",
              }}
            >
              <div
                style={{
                  padding: "12px",
                  borderRadius: "10px",
                  background: "var(--cs-surface2)",
                  border: "0.5px solid var(--cs-border)",
                }}
              >
                <div style={{ fontSize: "11px", color: "var(--cs-text3)", marginBottom: "6px" }}>
                  Créé le
                </div>
                <div style={{ display: "flex", gap: "8px", alignItems: "center", fontSize: "14px" }}>
                  <Calendar size={14} />
                  {formatDate(selectedIncident.created_at || selectedIncident.timestamp)}
                </div>
              </div>

              <div
                style={{
                  padding: "12px",
                  borderRadius: "10px",
                  background: "var(--cs-surface2)",
                  border: "0.5px solid var(--cs-border)",
                }}
              >
                <div style={{ fontSize: "11px", color: "var(--cs-text3)", marginBottom: "6px" }}>
                  Assigné à
                </div>
                <div style={{ display: "flex", gap: "8px", alignItems: "center", fontSize: "14px" }}>
                  <User size={14} />
                  {selectedIncident.assigned_to || selectedIncident.assignedTo || "Non assigné"}
                </div>
              </div>
            </div>

            <div
              style={{
                padding: "14px",
                borderRadius: "10px",
                background: scoreBg(selectedIncident.score_r ?? selectedIncident.scoreR),
                border: "0.5px solid var(--cs-border)",
                marginBottom: "18px",
              }}
            >
              <div style={{ fontSize: "11px", color: "var(--cs-text3)", marginBottom: "6px" }}>
                Description
              </div>
              <div style={{ fontSize: "14px" }}>
                {selectedIncident.description || selectedIncident.summary || "—"}
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
                    variant={(selectedIncident.status || "").toUpperCase() === opt.value ? "default" : "outline"}
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

            <div
              style={{
                padding: "14px",
                borderRadius: "10px",
                background: "var(--cs-surface2)",
                border: "0.5px solid var(--cs-border)",
              }}
            >
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
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        marginBottom: "6px",
                        fontSize: "12px",
                      }}
                    >
                      <span style={{ fontWeight: 600 }}>{comment.author}</span>
                      <span style={{ color: "var(--cs-text3)" }}>
                        {formatDate(comment.timestamp)}
                      </span>
                    </div>
                    <div style={{ fontSize: "14px" }}>{comment.content}</div>
                  </div>
                ))}
              </div>

              <div style={{ display: "flex", gap: "10px", alignItems: "flex-start" }}>
                <textarea
                  placeholder="Ajouter un commentaire..."
                  value={newComment}
                  onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) =>
                    setNewComment(e.target.value)
                  }
                  rows={3}
                  className="w-full rounded-md bg-cyber-panel border border-cyber-border text-sm outline-none p-3"
                />
                <Button onClick={handleAddComment}>
                  <Send size={16} />
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}