import React, { useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { incidentsAPI } from "../services/api";
import { AlertTriangle, Search, Calendar, User, Send, X } from "lucide-react";
import { Card, CardContent } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";

type IncidentStatus =
  | "OPEN"
  | "IN_REVIEW"
  | "RESOLVED"
  | "FALSE_POSITIVE"
  | string;

const statusOptions: { value: IncidentStatus; label: string; color: string }[] = [
  { value: "OPEN", label: "Ouvert", color: "var(--cs-red)" },
  { value: "IN_REVIEW", label: "En revue", color: "var(--cs-amber)" },
  { value: "RESOLVED", label: "Résolu", color: "var(--cs-green)" },
  { value: "FALSE_POSITIVE", label: "Faux positif", color: "var(--cs-text3)" },
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
  if (s === "HIGH" || s === "ELEVE" || s === "ÉLEVÉ" || s === "ELEVÉ")
    return "var(--cs-amber)";
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

export default function Incidents() {
  const location = useLocation();
  const incidentIdFromState = (location.state as any)?.incidentId;

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
      const res = await incidentsAPI.getAll({ limit: 100 });

      const list = Array.isArray(res)
        ? res
        : Array.isArray((res as any)?.incidents)
        ? (res as any).incidents
        : Array.isArray((res as any)?.items)
        ? (res as any).items
        : Array.isArray((res as any)?.data)
        ? (res as any).data
        : [];

      console.log("Incidents API response:", res);
      console.log("Parsed incidents:", list);

      setIncidents(list);
    } catch (e) {
      console.error("Incidents load error:", e);
      setIncidents([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, []);

  useEffect(() => {
    if (!incidentIdFromState || incidents.length === 0) return;

    const found = incidents.find(
      (inc) => String(inc.id) === String(incidentIdFromState)
    );

    if (found) {
      setSelectedIncident(found);
    }
  }, [incidentIdFromState, incidents]);

  const filteredIncidents = useMemo(() => {
    return incidents.filter((incident) => {
      const q = searchQuery.toLowerCase();

      const matchesSearch =
        (incident.title || "").toLowerCase().includes(q) ||
        (incident.description || "").toLowerCase().includes(q) ||
        (incident.summary || "").toLowerCase().includes(q) ||
        String(incident.id || "").toLowerCase().includes(q);

      const matchesStatus =
        statusFilter === "all" ||
        (incident.status || "").toUpperCase() === statusFilter;

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
            className="bg-cyber-red/10 text-cyber-red"
            style={{
              border: "1px solid rgba(239,68,68,.25)",
              background: "rgba(239,68,68,.08)",
            }}
          >
            <AlertTriangle size={12} className="mr-1" />
            {openCount} ouverts
          </Badge>
        </div>
      </div>

      <Card
        className="bg-card/50 border-cyber-border"
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
                placeholder="Rechercher un incident..."
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
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
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
              <option value="all">Toutes sévérités</option>
              <option value="CRITICAL">Critique</option>
              <option value="HIGH">Élevé</option>
              <option value="MEDIUM">Moyen</option>
              <option value="LOW">Faible</option>
              <option value="FAIBLE">Faible</option>
            </select>
          </div>
        </CardContent>
      </Card>

      <div
        style={{
          fontSize: "13px",
          color: "var(--cs-text2)",
          padding: "0 2px",
        }}
      >
        Total incidents : <strong>{filteredIncidents.length}</strong>
      </div>

      {loading ? (
        <div style={{ color: "var(--cs-text2)", fontSize: "14px" }}>
          Chargement...
        </div>
      ) : filteredIncidents.length === 0 ? (
        <Card
          className="bg-card/50 border-cyber-border"
          style={{
            background: "var(--cs-surface)",
            border: "1px solid var(--cs-border)",
            borderRadius: "16px",
          }}
        >
          <CardContent className="p-8">
            <div
              style={{
                textAlign: "center",
                color: "var(--cs-text3)",
                fontSize: "14px",
              }}
            >
              Aucun incident trouvé
            </div>
          </CardContent>
        </Card>
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
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    marginBottom: "8px",
                  }}
                >
                  <span
                    style={{
                      fontSize: "11px",
                      fontFamily: "monospace",
                      color: "var(--cs-text3)",
                    }}
                  >
                    {selectedIncident.id}
                  </span>
                  <SeverityPill severity={selectedIncident.severity} />
                </div>

                <h2
                  style={{
                    fontSize: "22px",
                    fontWeight: 700,
                    color: "var(--cs-text)",
                  }}
                >
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
                <div
                  style={{
                    fontSize: "11px",
                    color: "var(--cs-text3)",
                    marginBottom: "6px",
                  }}
                >
                  Créé le
                </div>

                <div
                  style={{
                    display: "flex",
                    gap: "8px",
                    alignItems: "center",
                    fontSize: "14px",
                    color: "var(--cs-text)",
                  }}
                >
                  <Calendar size={14} />
                  {formatDate(
                    selectedIncident.created_at ||
                      selectedIncident.timestamp ||
                      selectedIncident.detected_at
                  )}
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
                <div
                  style={{
                    fontSize: "11px",
                    color: "var(--cs-text3)",
                    marginBottom: "6px",
                  }}
                >
                  Assigné à
                </div>

                <div
                  style={{
                    display: "flex",
                    gap: "8px",
                    alignItems: "center",
                    fontSize: "14px",
                    color: "var(--cs-text)",
                  }}
                >
                  <User size={14} />
                  {selectedIncident.assigned_to ||
                    selectedIncident.assignedTo ||
                    "Non assigné"}
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
              <div
                style={{
                  fontSize: "11px",
                  color: "var(--cs-text3)",
                  marginBottom: "6px",
                }}
              >
                Description
              </div>
              <div style={{ fontSize: "14px", color: "var(--cs-text)" }}>
                {selectedIncident.description || selectedIncident.summary || "—"}
              </div>
            </div>

            <div style={{ marginBottom: "18px" }}>
              <div
                style={{
                  fontSize: "12px",
                  color: "var(--cs-text2)",
                  marginBottom: "10px",
                }}
              >
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
                <div
                  style={{
                    fontSize: "11px",
                    color: "var(--cs-text3)",
                    marginBottom: "8px",
                  }}
                >
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
              <div
                style={{
                  fontSize: "12px",
                  color: "var(--cs-text2)",
                  marginBottom: "10px",
                }}
              >
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
                      <span style={{ fontWeight: 600, color: "var(--cs-text)" }}>
                        {comment.author}
                      </span>
                      <span style={{ color: "var(--cs-text3)" }}>
                        {formatDate(comment.timestamp)}
                      </span>
                    </div>
                    <div style={{ fontSize: "14px", color: "var(--cs-text)" }}>
                      {comment.content}
                    </div>
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