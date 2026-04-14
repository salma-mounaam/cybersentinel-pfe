// ============================================================
// pages/MITREMatrix.tsx — Connecté au vrai backend M6
// Version enrichie : Matrix + Explorer + fiche explicative
// Compatible sans input/scroll-area/dialog shadcn
// ============================================================
import React, { useEffect, useMemo, useState } from "react";
import {
  Search,
  Shield,
  Target,
  Info,
  Users,
  ExternalLink,
  X,
  BookOpen,
  Layers,
  Sparkles,
} from "lucide-react";
import { Card, CardContent } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { cn } from "../lib/utils";
import { mitreAPI } from "../services/api";

// ── Ordre officiel des tactiques ATT&CK v14 ──────────────────
const TACTICS = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

// ── Types ─────────────────────────────────────────────────────
type SeverityMap = Record<string, number>;

type MatrixTechnique = {
  technique_id: string;
  technique_name?: string;
  tactic?: string;
  total_count?: number;
  severities?: SeverityMap;
  description?: string;
  mitigation?: string;
  apt_groups?: string[];
  url?: string;
};

type TechniqueDetail = {
  technique_id?: string;
  technique_name?: string;
  tactic?: string;
  description?: string;
  mitigation?: string;
  apt_groups?: string[];
  url?: string;
  cvss_base?: number;
  detection?: string;
  platforms?: string[];
  data_sources?: string[];
  examples?: string[];
};

// ── Helpers UI ────────────────────────────────────────────────
function getCountColor(count: number) {
  if (count === 0) {
    return "bg-muted/20 border-muted/30 text-muted-foreground hover:bg-muted/30";
  }
  if (count >= 10) {
    return "bg-red-500/30 border-red-500/50 hover:bg-red-500/40";
  }
  if (count >= 5) {
    return "bg-amber-500/30 border-amber-500/50 hover:bg-amber-500/40";
  }
  if (count >= 2) {
    return "bg-blue-500/30 border-blue-500/50 hover:bg-blue-500/40";
  }
  return "bg-green-500/30 border-green-500/50 hover:bg-green-500/40";
}

function getCountLabel(count: number) {
  if (count === 0) return "";
  if (count >= 10) return "bg-red-500/10 text-red-400";
  if (count >= 5) return "bg-amber-500/10 text-amber-400";
  if (count >= 2) return "bg-blue-500/10 text-blue-400";
  return "bg-green-500/10 text-green-400";
}

function getSeverityClass(sev: string) {
  if (sev === "CRITIQUE") return "bg-red-500/15 text-red-400";
  if (sev === "ELEVE") return "bg-amber-500/15 text-amber-400";
  if (sev === "MOYEN") return "bg-blue-500/15 text-blue-400";
  return "bg-green-500/15 text-green-400";
}

function normalizeText(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) return value.join(" ").toLowerCase();
  return String(value).toLowerCase();
}

function buildSearchBlob(t: MatrixTechnique) {
  return [
    t.technique_id,
    t.technique_name,
    t.tactic,
    t.description,
    t.mitigation,
    t.url,
    ...(t.apt_groups || []),
  ]
    .map(normalizeText)
    .join(" ");
}

function explainTechniqueName(techniqueName?: string, techniqueId?: string) {
  if (techniqueName) return techniqueName;
  return techniqueId || "Technique MITRE";
}

function generateSimpleExplanation(detail: TechniqueDetail, selected: MatrixTechnique) {
  const name = explainTechniqueName(detail.technique_name, selected.technique_id);
  const tactic = detail.tactic || selected.tactic || "tactique inconnue";

  return `La technique ${name} (${selected.technique_id}) appartient à la tactique ${tactic}. Elle décrit une manière concrète utilisée par un attaquant pour progresser dans une intrusion. Dans CyberSentinel, cette technique permet d'expliquer pourquoi une alerte ou un finding est important, et de la rattacher à un comportement offensif reconnu par MITRE ATT&CK.`;
}

function generateDetectionExplanation(detail: TechniqueDetail, selected: MatrixTechnique) {
  const count = selected.total_count || 0;

  if (detail.detection) return detail.detection;

  if (count > 0) {
    return `Cette technique a été observée ${count} fois dans la plateforme. Elle peut être détectée via les alertes IDS, les findings SAST/DAST corrélés, ou les incidents enrichis par le backend M6.`;
  }

  return `Aucune détection active n'est remontée pour cette technique pour le moment, mais elle reste consultable comme connaissance de menace dans la base MITRE.`;
}

function generatePracticalExample(detail: TechniqueDetail, selected: MatrixTechnique) {
  if (detail.examples && detail.examples.length > 0) {
    return detail.examples[0];
  }

  return `Exemple d'usage : un attaquant exploite cette technique pour avancer dans une étape de la kill chain, puis CyberSentinel la relie à la tactique ${detail.tactic || selected.tactic || "correspondante"} afin d'améliorer l'explication et la priorisation du risque.`;
}

// ── Composant principal ───────────────────────────────────────
export function MITREMatrix() {
  const [matrix, setMatrix] = useState<MatrixTechnique[]>([]);
  const [selected, setSelected] = useState<MatrixTechnique | null>(null);
  const [detail, setDetail] = useState<TechniqueDetail | null>(null);
  const [loadDet, setLoadDet] = useState(false);
  const [hovered, setHovered] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [totalCount, setTotalCount] = useState(0);

  useEffect(() => {
    mitreAPI
      .getMatrix()
      .then((d: any) => {
        setMatrix(Array.isArray(d?.matrix) ? d.matrix : []);
        setTotalCount(d?.total_techniques || 0);
      })
      .catch((err: unknown) => {
        console.error("Erreur chargement matrice MITRE:", err);
        setMatrix([]);
        setTotalCount(0);
      })
      .finally(() => setLoading(false));
  }, []);

  const handleSelect = async (tech: MatrixTechnique) => {
    if (selected?.technique_id === tech.technique_id) {
      setSelected(null);
      setDetail(null);
      return;
    }

    setSelected(tech);
    setLoadDet(true);
    setDetail(null);

    try {
      const d = await mitreAPI.getTechnique(tech.technique_id);
      setDetail(d || null);
    } catch (err) {
      console.error("Erreur chargement détail technique:", err);
      setDetail(null);
    } finally {
      setLoadDet(false);
    }
  };

  const query = search.trim().toLowerCase();
  const isExplorerMode = query.length > 0;

  const filtered = useMemo(() => {
    if (!query) return matrix;

    return matrix.filter((t) => {
      const blob = buildSearchBlob(t);
      return blob.includes(query);
    });
  }, [matrix, query]);

  const byTactic: Record<string, MatrixTechnique[]> = {};
  filtered.forEach((t) => {
    const tac = t.tactic || "Unknown";
    if (!byTactic[tac]) byTactic[tac] = [];
    byTactic[tac].push(t);
  });

  const displayTactics = TACTICS.filter((t) => byTactic[t]?.length > 0);

  const totalDetections = matrix.reduce((s, t) => s + (t.total_count || 0), 0);
  const detectedTechniques = matrix.filter((t) => (t.total_count || 0) > 0).length;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="text-2xl font-bold">MITRE ATT&CK Matrix</h1>
          <p className="text-sm text-muted-foreground">
            M6 · {totalCount} techniques détectées · base de connaissance + enrichissement temps réel
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <Badge variant="secondary" className="bg-violet-500/10 text-violet-400">
            <Shield size={12} className="mr-1" />
            v14.0
          </Badge>

          <Badge variant="secondary" className="bg-blue-500/10 text-blue-400">
            {totalDetections} détections
          </Badge>

          <Badge variant="secondary" className="bg-emerald-500/10 text-emerald-400">
            {detectedTechniques} techniques actives
          </Badge>

          <Badge
            variant="secondary"
            className={cn(
              isExplorerMode
                ? "bg-amber-500/10 text-amber-400"
                : "bg-cyan-500/10 text-cyan-400"
            )}
          >
            {isExplorerMode ? "Mode Explorer" : "Mode Matrix"}
          </Badge>
        </div>
      </div>

      {/* Search */}
      <Card className="bg-card/50 border-cyber-border">
        <CardContent className="p-4">
          <div className="flex flex-col gap-3">
            <div className="relative max-w-2xl">
              <Search
                size={16}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
              />
              <input
                placeholder="Rechercher T1046, Discovery, Credential Dumping, Phishing..."
                value={search}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setSearch(e.target.value)
                }
                className="w-full pl-10 pr-10 py-2.5 rounded-md bg-card/50 border border-cyber-border text-sm outline-none"
              />
              {search && (
                <button
                  onClick={() => setSearch("")}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  aria-label="Effacer la recherche"
                >
                  <X size={14} />
                </button>
              )}
            </div>

            <div className="flex items-center gap-2 flex-wrap text-xs text-muted-foreground">
              <span className="font-medium">Recherche sur :</span>
              <Badge variant="secondary">Technique ID</Badge>
              <Badge variant="secondary">Nom</Badge>
              <Badge variant="secondary">Tactique</Badge>
              <Badge variant="secondary">Description</Badge>
              <Badge variant="secondary">APT Groups</Badge>
              <Badge variant="secondary">Mitigation</Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Explorer mode */}
      {isExplorerMode ? (
        <Card className="bg-card/50 border-cyber-border overflow-hidden">
          <CardContent className="p-4 space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div>
                <h2 className="text-lg font-semibold flex items-center gap-2">
                  <BookOpen size={18} className="text-amber-400" />
                  MITRE Explorer
                </h2>
                <p className="text-sm text-muted-foreground">
                  {filtered.length} résultat{filtered.length !== 1 ? "s" : ""} pour “{search}”
                </p>
              </div>

              <Badge variant="secondary" className="bg-amber-500/10 text-amber-400">
                Recherche active
              </Badge>
            </div>

            {loading ? (
              <div className="py-16 text-center text-sm text-muted-foreground">
                Chargement depuis le backend...
              </div>
            ) : filtered.length === 0 ? (
              <div className="py-16 text-center space-y-2">
                <p className="text-sm text-muted-foreground">
                  Aucun résultat trouvé pour cette recherche.
                </p>
                <p className="text-xs text-muted-foreground opacity-60">
                  Essaie un ID MITRE, un nom de technique, une tactique ou un mot-clé.
                </p>
              </div>
            ) : (
              <div className="grid gap-3">
                {filtered.map((tech) => (
                  <div
                    key={tech.technique_id}
                    onClick={() => handleSelect(tech)}
                    className={cn(
                      "rounded-xl border p-4 cursor-pointer transition-all duration-150",
                      "hover:shadow-lg hover:scale-[1.01]",
                      selected?.technique_id === tech.technique_id
                        ? "border-violet-500 bg-violet-500/10"
                        : "border-cyber-border bg-card/40 hover:bg-card/60"
                    )}
                  >
                    <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                      <div className="space-y-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-xs font-bold text-blue-400 bg-blue-500/10 px-2 py-1 rounded">
                            {tech.technique_id}
                          </span>

                          {tech.tactic && (
                            <Badge variant="secondary" className="text-xs">
                              <Target size={12} className="mr-1" />
                              {tech.tactic}
                            </Badge>
                          )}

                          {(tech.total_count || 0) > 0 && (
                            <Badge
                              variant="secondary"
                              className={cn("text-xs", getCountLabel(tech.total_count || 0))}
                            >
                              {tech.total_count} détection
                              {(tech.total_count || 0) > 1 ? "s" : ""}
                            </Badge>
                          )}
                        </div>

                        <h3 className="text-base font-semibold">
                          {tech.technique_name || tech.technique_id}
                        </h3>

                        <p className="text-sm text-muted-foreground leading-relaxed">
                          {tech.description
                            ? tech.description
                            : "Aperçu non disponible dans la réponse matrix. Clique pour ouvrir la fiche complète."}
                        </p>

                        {tech.apt_groups && tech.apt_groups.length > 0 && (
                          <div className="flex flex-wrap gap-1.5 pt-1">
                            {tech.apt_groups.slice(0, 5).map((group) => (
                              <Badge
                                key={group}
                                variant="secondary"
                                className="text-xs bg-red-500/10 text-red-400"
                              >
                                {group}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        <Badge variant="secondary" className="bg-cyan-500/10 text-cyan-400">
                          <Info size={12} className="mr-1" />
                          Voir détails
                        </Badge>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Matrix */}
          <Card className="bg-card/50 border-cyber-border overflow-hidden">
            <CardContent className="p-0">
              {loading ? (
                <div className="py-16 text-center text-sm text-muted-foreground">
                  Chargement depuis le backend...
                </div>
              ) : displayTactics.length === 0 ? (
                <div className="py-16 text-center space-y-2">
                  <p className="text-sm text-muted-foreground">
                    Aucune technique détectée pour l'instant.
                  </p>
                  <p className="text-xs text-muted-foreground opacity-60">
                    La matrice se remplit automatiquement avec les alertes M1 et les findings M4.
                  </p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <div style={{ minWidth: `${displayTactics.length * 130}px` }}>
                    {/* Headers tactiques */}
                    <div
                      className="grid gap-1 p-2 bg-card/80"
                      style={{ gridTemplateColumns: `repeat(${displayTactics.length}, 1fr)` }}
                    >
                      {displayTactics.map((tac) => (
                        <div
                          key={tac}
                          className={cn(
                            "p-2 text-center text-xs font-medium cursor-pointer rounded transition-colors",
                            hovered === tac
                              ? "bg-violet-500/20 text-violet-300"
                              : "hover:bg-card text-muted-foreground"
                          )}
                          onMouseEnter={() => setHovered(tac)}
                          onMouseLeave={() => setHovered(null)}
                        >
                          <div className="h-10 flex items-center justify-center">
                            <span className="line-clamp-2 leading-tight">{tac}</span>
                          </div>
                          <div className="text-[9px] opacity-50 mt-0.5">
                            {byTactic[tac]?.length || 0} technique
                            {byTactic[tac]?.length !== 1 ? "s" : ""}
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Cellules techniques */}
                    <div
                      className="grid gap-1 p-2"
                      style={{ gridTemplateColumns: `repeat(${displayTactics.length}, 1fr)` }}
                    >
                      {displayTactics.map((tac) => (
                        <div key={tac} className="space-y-1 min-h-[80px]">
                          {(byTactic[tac] || []).map((tech) => (
                            <div
                              key={tech.technique_id}
                              onClick={() => handleSelect(tech)}
                              className={cn(
                                "p-2 rounded border cursor-pointer transition-all duration-150",
                                "hover:scale-105 hover:z-10 hover:shadow-lg",
                                selected?.technique_id === tech.technique_id
                                  ? "border-violet-500 bg-violet-500/25 scale-105"
                                  : getCountColor(tech.total_count || 0)
                              )}
                              title={tech.technique_name || tech.technique_id}
                            >
                              <p className="text-[10px] font-mono font-bold">
                                {tech.technique_id}
                              </p>

                              {tech.technique_name && (
                                <p className="text-[10px] mt-1 line-clamp-2 opacity-90">
                                  {tech.technique_name}
                                </p>
                              )}

                              {(tech.total_count || 0) > 0 && (
                                <span
                                  className={cn(
                                    "text-[9px] px-1 py-0.5 rounded mt-1 inline-block",
                                    getCountLabel(tech.total_count || 0)
                                  )}
                                >
                                  {tech.total_count}×
                                </span>
                              )}
                            </div>
                          ))}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Légende */}
          <div className="flex items-center justify-center gap-6 text-xs text-muted-foreground flex-wrap">
            {[
              { color: "bg-red-500/30 border-red-500/50", label: "≥ 10 détections" },
              { color: "bg-amber-500/30 border-amber-500/50", label: "5–9 détections" },
              { color: "bg-blue-500/30 border-blue-500/50", label: "2–4 détections" },
              { color: "bg-green-500/30 border-green-500/50", label: "1 détection" },
            ].map(({ color, label }) => (
              <span key={label} className="flex items-center gap-1.5">
                <span className={cn("w-4 h-4 rounded border", color)} />
                {label}
              </span>
            ))}
          </div>
        </>
      )}

      {/* Modal détail technique */}
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
          onClick={() => {
            setSelected(null);
            setDetail(null);
          }}
        >
          <div
            style={{
              width: "100%",
              maxWidth: "920px",
              maxHeight: "85vh",
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
                marginBottom: "16px",
                gap: "12px",
              }}
            >
              <div>
                <div className="flex items-center gap-2 mb-2 flex-wrap">
                  <span className="font-mono text-sm font-bold text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded">
                    {selected.technique_id}
                  </span>

                  <Badge
                    variant="secondary"
                    className={cn("text-[10px]", getCountLabel(selected.total_count || 0))}
                  >
                    {selected.total_count || 0} détection
                    {(selected.total_count || 0) !== 1 ? "s" : ""}
                  </Badge>

                  <Badge variant="secondary">
                    <Target size={12} className="mr-1" />
                    {detail?.tactic || selected.tactic || "—"}
                  </Badge>
                </div>

                <h2 className="text-lg font-semibold">
                  {loadDet
                    ? "Chargement..."
                    : detail?.technique_name ||
                      selected.technique_name ||
                      selected.technique_id}
                </h2>
              </div>

              <button
                onClick={() => {
                  setSelected(null);
                  setDetail(null);
                }}
                style={{
                  border: "none",
                  background: "transparent",
                  color: "var(--cs-text2)",
                  cursor: "pointer",
                  flexShrink: 0,
                }}
              >
                <X size={20} />
              </button>
            </div>

            {loadDet ? (
              <div className="py-8 text-center text-sm text-muted-foreground">
                Chargement des détails depuis le backend...
              </div>
            ) : (
              <div className="space-y-5 pr-1">
                {/* Résumé pédagogique */}
                <div className="rounded-xl border border-cyber-border bg-card/40 p-4">
                  <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                    <Sparkles size={14} className="text-violet-400" />
                    Explication simple
                  </h4>
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {generateSimpleExplanation(detail || {}, selected)}
                  </p>
                </div>

                {/* Description */}
                {(detail?.description || selected.description) && (
                  <div>
                    <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                      <Info size={14} /> Description
                    </h4>
                    <p className="text-sm text-muted-foreground leading-relaxed">
                      {detail?.description || selected.description}
                    </p>
                  </div>
                )}

                {/* Exemple concret */}
                <div>
                  <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                    <BookOpen size={14} /> Exemple concret
                  </h4>
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {generatePracticalExample(detail || {}, selected)}
                  </p>
                </div>

                {/* Détection */}
                <div>
                  <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                    <Layers size={14} /> Comment la détecter dans CyberSentinel
                  </h4>
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {generateDetectionExplanation(detail || {}, selected)}
                  </p>
                </div>

                {/* Groupes APT */}
                {(detail?.apt_groups?.length || selected.apt_groups?.length) ? (
                  <div>
                    <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                      <Users size={14} /> Groupes APT associés
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {(detail?.apt_groups || selected.apt_groups || []).map((g: string) => (
                        <Badge
                          key={g}
                          variant="secondary"
                          className="text-xs bg-red-500/10 text-red-400"
                        >
                          {g}
                        </Badge>
                      ))}
                    </div>
                  </div>
                ) : null}

                {/* Sévérités */}
                {selected.severities && Object.keys(selected.severities).length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">
                      Sévérités des alertes détectées
                    </h4>
                    <div className="flex gap-2 flex-wrap">
                      {Object.entries(selected.severities).map(([sev, cnt]) => (
                        <div
                          key={sev}
                          className={cn(
                            "px-3 py-1.5 rounded-lg text-xs font-medium",
                            getSeverityClass(sev)
                          )}
                        >
                          {sev} · {cnt as number}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Mitigation */}
                {(detail?.mitigation || selected.mitigation) && (
                  <div>
                    <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                      <Shield size={14} /> Mitigation
                    </h4>
                    <p className="text-sm text-muted-foreground leading-relaxed">
                      {detail?.mitigation || selected.mitigation}
                    </p>
                  </div>
                )}

                {/* Data sources / platforms */}
                <div className="grid md:grid-cols-2 gap-4">
                  {detail?.platforms && detail.platforms.length > 0 && (
                    <div className="p-3 rounded-lg bg-card/50 border border-cyber-border">
                      <p className="text-xs text-muted-foreground mb-2">Plateformes</p>
                      <div className="flex flex-wrap gap-1.5">
                        {detail.platforms.map((p) => (
                          <Badge key={p} variant="secondary" className="text-xs">
                            {p}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {detail?.data_sources && detail.data_sources.length > 0 && (
                    <div className="p-3 rounded-lg bg-card/50 border border-cyber-border">
                      <p className="text-xs text-muted-foreground mb-2">Sources de données</p>
                      <div className="flex flex-wrap gap-1.5">
                        {detail.data_sources.map((s) => (
                          <Badge key={s} variant="secondary" className="text-xs">
                            {s}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Métriques */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="p-3 rounded-lg bg-card/50 border border-cyber-border">
                    <p className="text-xs text-muted-foreground mb-1">CVSS base</p>
                    <p
                      className={cn(
                        "text-lg font-bold font-mono",
                        (detail?.cvss_base || 0) >= 9
                          ? "text-red-400"
                          : (detail?.cvss_base || 0) >= 7
                          ? "text-amber-400"
                          : "text-blue-400"
                      )}
                    >
                      {detail?.cvss_base?.toFixed?.(1) || "—"}
                    </p>
                  </div>

                  <div className="p-3 rounded-lg bg-card/50 border border-cyber-border">
                    <p className="text-xs text-muted-foreground mb-1">Détections totales</p>
                    <p className="text-lg font-bold font-mono text-violet-400">
                      {selected.total_count || 0}
                    </p>
                  </div>

                  <div className="p-3 rounded-lg bg-card/50 border border-cyber-border">
                    <p className="text-xs text-muted-foreground mb-1">Technique ID</p>
                    <p className="text-lg font-bold font-mono text-cyan-400">
                      {selected.technique_id}
                    </p>
                  </div>
                </div>

                {/* Lien MITRE */}
                {(detail?.url || selected.url) && (
                  <a
                    href={detail?.url || selected.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 text-sm text-blue-400 hover:text-blue-300 transition-colors"
                  >
                    <ExternalLink size={14} />
                    Voir sur attack.mitre.org
                  </a>
                )}

                {!detail && (
                  <div className="py-2 text-sm text-muted-foreground">
                    Certaines données détaillées ne sont pas disponibles depuis le backend pour cette technique.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default MITREMatrix;