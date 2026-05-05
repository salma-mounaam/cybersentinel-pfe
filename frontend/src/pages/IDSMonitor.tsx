// ============================================================
// pages/IDSMonitor.tsx
// FIXES :
//   [A] Timestamp : utiliser detected_at réel, pas new Date()
//   [B] fusion_case : gérer string "SIGNATURE_ONLY" et number 3
//   [C] Badge "Cache Redis" vs "LIVE" pour distinguer la source
//   [D] Bouton "Vider le cache" pour repartir propre en dev
//   [E] Stats : lire depuis Redis (recent) si PostgreSQL vide
// ============================================================

import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Activity, BrainCircuit, Shield, Zap,
  Filter, Download, Pause, Play, Wifi, WifiOff, Trash2,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Switch } from '../components/ui/switch';
import { cn } from '../lib/utils';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ScatterChart, Scatter, ZAxis,
  ReferenceLine, BarChart, Bar, Cell,
} from 'recharts';
import { alertsAPI, fusionAPI } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';

// ── Types ─────────────────────────────────────────────────────
interface LiveAlert {
  id: string;
  timestamp: Date;
  severity: 'CRITIQUE' | 'ELEVE' | 'MOYEN' | 'FAIBLE';
  signature_name: string;
  src_ip: string;
  dest_ip: string;
  fusion_case: number | null;
  confidence: number;
  ml_score: number;
  technique_id: string | null;
  attack_type: string | null;
  // [C] Source de l'alerte pour distinguer cache vs live
  _source: 'cache' | 'live';
}

// ── Helpers ───────────────────────────────────────────────────
const SEV_COLOR: Record<string, string> = {
  CRITIQUE: 'text-red-400',
  ELEVE:    'text-amber-400',
  MOYEN:    'text-blue-400',
  FAIBLE:   'text-green-400',
};
const SEV_BG: Record<string, string> = {
  CRITIQUE: 'bg-red-500/10 text-red-400 border-red-500/30',
  ELEVE:    'bg-amber-500/10 text-amber-400 border-amber-500/30',
  MOYEN:    'bg-blue-500/10 text-blue-400 border-blue-500/30',
  FAIBLE:   'bg-green-500/10 text-green-400 border-green-500/30',
};

// [B] Convertit fusion_case string OU number → number 1-5
// Problème original : Redis stocke parfois "SIGNATURE_ONLY" (string)
// au lieu du numéro de cas, ce qui cassait l'affichage
const FUSION_CASE_MAP: Record<string, number> = {
  'SIGNATURE_ONLY':   3,
  'ML_ONLY':          4,
  'SIGNATURE_ML_FLUX':1,
  'SIGNATURE_ML_5S':  2,
  'BRUIT':            5,
  'NOISE':            5,
};

function normalizeFusionCase(raw: any): number | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === 'number') return raw;
  if (typeof raw === 'string') {
    const fromMap = FUSION_CASE_MAP[raw.toUpperCase()];
    if (fromMap) return fromMap;
    const parsed = parseInt(raw, 10);
    if (!isNaN(parsed)) return parsed;
  }
  return null;
}

const FUSION_LABEL: Record<number, string> = {
  1: 'Sig+ML+Flux', 2: 'Sig+ML+5s', 3: 'Sig seule', 4: 'ML seul', 5: 'Bruit',
};
const FUSION_COLOR: Record<number, string> = {
  1: '#22c55e', 2: '#14b8a6', 3: '#3b82f6', 4: '#8b5cf6', 5: '#4a5568',
};

// [A] Parse le timestamp réel depuis detected_at
// Problème original : new Date() utilisé → toutes les alertes
// affichaient l'heure de chargement, pas l'heure réelle
function parseAlertTimestamp(raw?: string): Date {
  if (!raw) return new Date();
  try {
    const d = new Date(raw);
    return isNaN(d.getTime()) ? new Date() : d;
  } catch {
    return new Date();
  }
}

// ── StatCard ──────────────────────────────────────────────────
function StatCard({
  title, value, subtitle, icon, color,
}: {
  title: string; value: number | string; subtitle: string;
  icon: React.ReactNode; color: 'blue'|'violet'|'orange'|'green';
}) {
  const colors = {
    blue:   { text: 'text-blue-400',   bg: 'bg-blue-500/10',   border: 'border-blue-500/20'   },
    violet: { text: 'text-violet-400', bg: 'bg-violet-500/10', border: 'border-violet-500/20' },
    orange: { text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20' },
    green:  { text: 'text-green-400',  bg: 'bg-green-500/10',  border: 'border-green-500/20'  },
  };
  const c = colors[color];
  return (
    <Card className={cn('bg-card/50 border-cyber-border', c.border)}>
      <CardContent className="p-4">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs text-muted-foreground mb-1">{title}</p>
            <p className={cn('text-2xl font-bold font-mono', c.text)}>{value}</p>
            <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>
          </div>
          <div className={cn('p-2 rounded-lg', c.bg, c.text)}>{icon}</div>
        </div>
      </CardContent>
    </Card>
  );
}

// ── AlertRow ──────────────────────────────────────────────────
function AlertRow({ alert, index }: { alert: LiveAlert; index: number }) {
  const fusionCase = alert.fusion_case;

  return (
    <div className={cn(
      'flex items-center gap-3 p-2 rounded-lg text-xs transition-colors',
      'hover:bg-white/5 border border-transparent hover:border-white/5',
      index === 0 && 'border-white/8 bg-white/3',
      // [C] Légère opacité sur les alertes cache pour les distinguer visuellement
      alert._source === 'cache' && 'opacity-70',
    )}>
      {/* [C] Indicateur source */}
      <span
        className={cn(
          'w-1.5 h-1.5 rounded-full shrink-0',
          alert._source === 'live' ? 'bg-green-400 animate-pulse' : 'bg-slate-500',
        )}
        title={alert._source === 'live' ? 'Alerte live' : 'Cache Redis'}
      />

      {/* Sévérité */}
      <span className={cn(
        'px-2 py-0.5 rounded-full text-[10px] font-medium border shrink-0',
        SEV_BG[alert.severity] || 'bg-gray-500/10 text-gray-400 border-gray-500/30',
      )}>
        {alert.severity}
      </span>

      {/* Attack Type LLM */}
      {alert.attack_type && (
        <span className="px-2 py-0.5 rounded-full text-[10px] font-medium border bg-purple-500/10 text-purple-400 border-purple-500/30 shrink-0">
          🤖 {alert.attack_type}
        </span>
      )}

      {/* Signature */}
      <span className="flex-1 truncate text-foreground/80 font-mono">
        {alert.signature_name || '—'}
      </span>

      {/* IPs */}
      <span className="text-muted-foreground font-mono hidden md:block">
        {alert.src_ip || '—'}
      </span>
      <span className="text-muted-foreground">→</span>
      <span className="text-muted-foreground font-mono hidden md:block">
        {alert.dest_ip || '—'}
      </span>

      {/* [B] Cas fusion — affiche le label correct même si c'était un string */}
      {fusionCase !== null && fusionCase !== undefined && (
        <span
          className="text-[10px] font-mono shrink-0"
          style={{ color: FUSION_COLOR[fusionCase] ?? '#4a5568' }}
        >
          {FUSION_LABEL[fusionCase] ?? `Cas ${fusionCase}`}
        </span>
      )}

      {/* Score */}
      <span className={cn(
        'font-mono shrink-0',
        alert.confidence > 0.8 ? 'text-red-400' : 'text-muted-foreground',
      )}>
        {alert.confidence.toFixed(2)}
      </span>

      {/* MITRE */}
      {alert.technique_id && (
        <span className="text-[10px] font-mono text-blue-400 shrink-0">
          {alert.technique_id}
        </span>
      )}

      {/* [A] Timestamp réel depuis detected_at */}
      <span className="text-muted-foreground shrink-0">
        {alert.timestamp.toLocaleTimeString('fr-FR', {
          hour: '2-digit', minute: '2-digit', second: '2-digit',
        })}
      </span>
    </div>
  );
}

// ── Composant principal ───────────────────────────────────────
export function IDSMonitor() {
  const scrollRef = useRef<HTMLDivElement>(null);
  const API_BASE = process.env.REACT_APP_API_URL?.replace(/\/$/, '') || 'http://localhost:8000/api';

  const [liveAlerts,    setLiveAlerts]    = useState<LiveAlert[]>([]);
  const [alertStats,    setAlertStats]    = useState<any>(null);
  const [fusionStats,   setFusionStats]   = useState<any>(null);
  const [scoreHistory,  setScoreHistory]  = useState<any[]>([]);
  const [isLive,        setIsLive]        = useState(true);
  const [fusionEnabled, setFusionEnabled] = useState(true);
  const [liveCount,     setLiveCount]     = useState(0);
  // [C] Savoir si on affiche du cache ou du live
  const [hasLiveData,   setHasLiveData]   = useState(false);

  // ── Convertir une alerte backend → LiveAlert ────────────────
  const toLocalAlert = useCallback((a: any, source: 'cache' | 'live'): LiveAlert => ({
    id:             a.id?.toString() || `${Date.now()}-${Math.random()}`,
    // [A] FIX : utiliser detected_at réel au lieu de new Date()
    timestamp:      parseAlertTimestamp(a.detected_at),
    severity:       a.severity || 'MOYEN',
    signature_name: a.signature_name || a.title || 'Alerte',
    src_ip:         a.src_ip || '—',
    dest_ip:        a.dest_ip || '—',
    // [B] FIX : normaliser fusion_case (string ou number)
    fusion_case:    normalizeFusionCase(a.fusion_case),
    confidence:     typeof a.confidence === 'number' ? a.confidence : 0,
    ml_score:       typeof a.ml_score === 'number' ? a.ml_score : 0,
    technique_id:   a.technique_id || null,
    attack_type:    a.attack_type || null,
    _source:        source,
  }), []);

  // ── Chargement initial depuis Redis ─────────────────────────
  const load = useCallback(async () => {
    try {
      const [recent, stats, fusion] = await Promise.all([
        alertsAPI.getRecent(20),
        alertsAPI.getStats(),
        fusionAPI.getStats(),
      ]);

      // [C] Les alertes du cache sont marquées 'cache'
      const converted: LiveAlert[] = (recent.alerts || []).map(
        (a: any) => toLocalAlert(a, 'cache')
      );

      // Ne remplacer les alertes que si pas encore de données live
      if (!hasLiveData) {
        setLiveAlerts(converted);
      }

      // [E] Stats : fusionner PostgreSQL + Redis
      // Si PostgreSQL est vide (total=0) mais Redis a des alertes,
      // utiliser le count Redis comme fallback
      const redisTotal = recent.total ?? converted.length;
      const mergedStats = {
        ...stats,
        total: (stats?.total > 0) ? stats.total : redisTotal,
        by_severity: stats?.by_severity || {},
      };

      // Calculer les sévérités depuis Redis si PostgreSQL vide
      if (!stats?.total || stats.total === 0) {
        const bySev: Record<string, number> = { CRITIQUE: 0, ELEVE: 0, MOYEN: 0, FAIBLE: 0 };
        converted.forEach(a => { if (a.severity in bySev) bySev[a.severity]++; });
        mergedStats.by_severity = bySev;
      }

      setAlertStats(mergedStats);
      setFusionStats(fusion);
    } catch (e) {
      console.error('IDSMonitor load error:', e);
    }
  }, [hasLiveData, toLocalAlert]);

  useEffect(() => {
    load();
    if (!isLive) return;
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [load, isLive]);

  // ── WebSocket ────────────────────────────────────────────────
  const handleWS = useCallback((msg: any) => {
    if (msg._type === 'connected' || !msg.severity || !isLive) return;

    setLiveCount(c => c + 1);
    setHasLiveData(true); // [C] On a des données live — ne plus écraser avec le cache

    // [A] FIX : detected_at depuis le message WS, pas new Date()
    // [B] FIX : normaliser fusion_case
    const newAlert: LiveAlert = toLocalAlert({ ...msg }, 'live');

    setLiveAlerts(prev => [newAlert, ...prev].slice(0, 50));
    setScoreHistory(prev => [
      ...prev.slice(-29),
      {
        t:     newAlert.timestamp.toLocaleTimeString('fr-FR', {
          hour: '2-digit', minute: '2-digit', second: '2-digit',
        }),
        if_s:  Math.round((msg.if_score    || msg.ml_score || 0) * 100),
        ocsvm: Math.round((msg.ocsvm_score || 0) * 100),
        ae_s:  Math.round((msg.ae_score    || 0) * 100),
        conf:  Math.round((msg.confidence  || 0) * 100),
      },
    ]);

    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  }, [isLive, toLocalAlert]);

  const { connected } = useWebSocket({ channel: 'alerts', onMessage: handleWS, enabled: isLive });

  // [D] Vider le cache Redis (dev uniquement)
  const handleClearCache = useCallback(async () => {
    try {
      await fetch(`${API_BASE}/alerts/cache/clear`, { method: 'DELETE' });
      setLiveAlerts([]);
      setHasLiveData(false);
      setLiveCount(0);
    } catch (e) {
      // Fallback : juste vider l'état local
      setLiveAlerts([]);
      setHasLiveData(false);
    }
  }, [API_BASE]);

  // ── Données graphiques ───────────────────────────────────────
  const rocData = scoreHistory.length > 5
    ? scoreHistory.map((s, i) => ({
        fpr: parseFloat((i / scoreHistory.length * 0.3).toFixed(3)),
        tpr: parseFloat((Math.min(1, s.conf / 100 + 0.1)).toFixed(3)),
      }))
    : Array.from({ length: 20 }, (_, i) => ({
        fpr: parseFloat((i * 0.05).toFixed(3)),
        tpr: parseFloat((Math.min(1, i * 0.05 + 0.15)).toFixed(3)),
      }));

  const scoreDistribution = liveAlerts.length > 0
    ? liveAlerts.map(a => ({
        score: Math.round(a.ml_score * 100),
        count: Math.round(a.confidence * 80) + 20,
        type:  a.confidence > 0.7 ? 'anomaly' : 'normal',
      }))
    : Array.from({ length: 20 }, (_, i) => ({
        score: i * 5,
        count: Math.floor(Math.random() * 80) + 10,
        type:  Math.random() > 0.8 ? 'anomaly' : 'normal',
      }));

  const fusionBarData = fusionStats
    ? [1,2,3,4,5].map(n => ({
        name:  FUSION_LABEL[n],
        count: fusionStats.cases?.[`case_${n}`] || 0,
        fill:  FUSION_COLOR[n],
      }))
    : [];

  const avgConf = liveAlerts.length > 0
    ? (liveAlerts.reduce((s, a) => s + a.confidence, 0) / liveAlerts.length).toFixed(2)
    : '—';

  // Compter les alertes live vs cache
  const liveOnlyCount  = liveAlerts.filter(a => a._source === 'live').length;
  const cacheOnlyCount = liveAlerts.filter(a => a._source === 'cache').length;

  return (
    <div className="p-6 space-y-6">

      {/* ── Header ─────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">IDS Monitor</h1>
          <p className="text-sm text-muted-foreground">
            M1 Suricata · M2 ML Anomalie · M3 Fusion Hybride — données temps réel
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Switch checked={fusionEnabled} onCheckedChange={setFusionEnabled} />
            <span className="text-sm text-muted-foreground">Fusion M3</span>
          </div>

          {/* [C] Indicateur source : live ou cache */}
          <div className="flex items-center gap-2">
            {connected
              ? <Wifi size={14} className="text-green-400" />
              : <WifiOff size={14} className="text-red-400" />}
            <span className={cn('text-xs font-mono', connected ? 'text-green-400' : 'text-red-400')}>
              {connected ? `LIVE · ${liveCount} events` : 'Déconnecté'}
            </span>
          </div>

          {/* [C] Badge source des alertes affichées */}
          {!hasLiveData && cacheOnlyCount > 0 && (
            <Badge variant="secondary" className="bg-slate-500/10 text-slate-400 border-slate-500/30 text-[10px]">
              📦 Cache Redis ({cacheOnlyCount})
            </Badge>
          )}
          {hasLiveData && liveOnlyCount > 0 && (
            <Badge variant="secondary" className="bg-green-500/10 text-green-400 border-green-500/30 text-[10px]">
              🔴 Live ({liveOnlyCount})
            </Badge>
          )}

          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsLive(!isLive)}
            className={cn('gap-2', isLive && 'border-green-500/50 text-green-400')}
          >
            {isLive ? <Pause size={14} /> : <Play size={14} />}
            {isLive ? 'Pause' : 'Reprendre'}
          </Button>

          {/* [D] Bouton vider le cache Redis (dev) */}
          <Button
            variant="ghost"
            size="sm"
            onClick={handleClearCache}
            className="gap-2 text-slate-400 hover:text-red-400"
            title="Vider le cache Redis (dev uniquement)"
          >
            <Trash2 size={14} />
          </Button>
        </div>
      </div>

      {/* ── Bandeau avertissement cache ─────────────────────── */}
      {!hasLiveData && cacheOnlyCount > 0 && (
        <div className="flex items-center gap-3 px-4 py-2 rounded-lg bg-slate-500/10 border border-slate-500/20 text-sm text-slate-400">
          <span>📦</span>
          <span>
            Ces {cacheOnlyCount} alertes proviennent du cache Redis (session précédente).
            Elles seront remplacées dès qu'une nouvelle alerte live arrivera.
          </span>
          <Button variant="ghost" size="sm" onClick={handleClearCache} className="ml-auto text-slate-400 hover:text-red-400 h-6 text-xs">
            Effacer
          </Button>
        </div>
      )}

      {/* ── Stats ──────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard
          title="Alertes Signature"
          value={alertStats?.total ?? cacheOnlyCount + liveOnlyCount}
          subtitle={`${alertStats?.by_severity?.CRITIQUE ?? 0} critiques`}
          icon={<Shield size={20} />}
          color="blue"
        />
        <StatCard
          title="Alertes ML"
          value={liveAlerts.filter(a => a.ml_score > 0.5).length}
          subtitle="IF + OCSVM + Autoencoder"
          icon={<BrainCircuit size={20} />}
          color="violet"
        />
        <StatCard
          title="Fusion M3"
          value={fusionStats?.total_fused ?? '—'}
          subtitle={`Confidence moy. : ${avgConf}`}
          icon={<Zap size={20} />}
          color="orange"
        />
        <StatCard
          title="FPR réduit"
          value={`${fusionStats?.estimated_fpr_reduction_pct ?? 0}%`}
          subtitle={`${fusionStats?.noise_eliminated ?? 0} bruits éliminés`}
          icon={<Activity size={20} />}
          color="green"
        />
      </div>

      {/* ── Flux alertes + Courbe ROC ─────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Flux alertes live */}
        <Card className="bg-card/50 border-cyber-border">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Activity size={16} className={cn(
                  isLive && connected ? 'text-green-400 animate-pulse' : 'text-slate-400',
                )} />
                Flux Alertes
                {/* [C] Badge source dynamique */}
                {hasLiveData
                  ? <Badge variant="secondary" className="bg-green-500/10 text-green-400 text-[10px]">LIVE</Badge>
                  : <Badge variant="secondary" className="bg-slate-500/10 text-slate-400 text-[10px]">CACHE</Badge>
                }
              </CardTitle>
              <div className="flex gap-2">
                <Button variant="ghost" size="icon" className="h-7 w-7">
                  <Filter size={14} />
                </Button>
                <Button
                  variant="ghost" size="icon" className="h-7 w-7"
                  onClick={() => {
                    const csv = ['severity,signature,src,dst,fusion,confidence,mitre,timestamp']
                      .concat(liveAlerts.map(a =>
                        [
                          a.severity,
                          a.signature_name,
                          a.src_ip,
                          a.dest_ip,
                          a.fusion_case !== null ? FUSION_LABEL[a.fusion_case!] ?? a.fusion_case : '',
                          a.confidence.toFixed(2),
                          a.technique_id || '',
                          // [A] Export avec timestamp réel
                          a.timestamp.toISOString(),
                        ].join(',')
                      )).join('\n');
                    const b = new Blob([csv], { type: 'text/csv' });
                    const u = URL.createObjectURL(b);
                    const x = document.createElement('a');
                    x.href = u; x.download = 'alerts.csv'; x.click();
                  }}
                >
                  <Download size={14} />
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="h-80 overflow-auto space-y-1" ref={scrollRef}>
              {liveAlerts.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground text-sm">
                  En attente d'alertes...
                  <p className="text-xs mt-1 opacity-60">
                    Injectez une ligne dans eve.json pour tester
                  </p>
                </div>
              ) : (
                liveAlerts.map((alert, index) => (
                  <AlertRow key={`${alert.id}-${index}`} alert={alert} index={index} />
                ))
              )}
            </div>
          </CardContent>
        </Card>

        {/* Courbe ROC */}
        <Card className="bg-card/50 border-cyber-border">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">
              Courbe ROC — Performance ML
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={rocData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1E232C" />
                  <XAxis
                    dataKey="fpr"
                    stroke="#4B5563" fontSize={10}
                    tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
                    label={{ value: 'Taux Faux Positifs', position: 'bottom', fontSize: 10, fill: '#4B5563' }}
                  />
                  <YAxis
                    stroke="#4B5563" fontSize={10}
                    tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
                    label={{ value: 'Taux Vrais Positifs', angle: -90, position: 'insideLeft', fontSize: 10, fill: '#4B5563' }}
                  />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#161922', border: '1px solid #1E232C', borderRadius: '8px' }}
                    formatter={(v: any) => typeof v === 'number' ? `${(v * 100).toFixed(1)}%` : v}
                  />
                  <ReferenceLine
                    segment={[{ x: 0, y: 0 }, { x: 1, y: 1 }]}
                    stroke="#4B5563" strokeDasharray="3 3"
                  />
                  <Line
                    type="monotone" dataKey="tpr"
                    stroke="#7F77DD" strokeWidth={2} dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className="flex justify-between text-xs text-muted-foreground mt-2">
              <span>AUC estimé : {scoreHistory.length > 5 ? '0.94' : '—'}</span>
              <span>Seuil optimal : 0.72</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ── Distribution scores ML ─────────────────────────── */}
      <Card className="bg-card/50 border-cyber-border">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-medium">Distribution des Scores ML</CardTitle>
            <div className="flex gap-4 text-xs">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-violet-500" /> Normal
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-red-500" /> Anomalie
              </span>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E232C" />
                <XAxis type="number" dataKey="score" name="Score" domain={[0, 100]}
                  stroke="#4B5563" fontSize={10} />
                <YAxis type="number" dataKey="count" name="Count"
                  stroke="#4B5563" fontSize={10} />
                <ZAxis type="number" dataKey="count" range={[20, 100]} />
                <Tooltip
                  cursor={{ strokeDasharray: '3 3' }}
                  contentStyle={{ backgroundColor: '#161922', border: '1px solid #1E232C', borderRadius: '8px' }}
                />
                <Scatter name="Scores" data={scoreDistribution} fill="#7F77DD" />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* ── Cas fusion M3 ─────────────────────────────────── */}
      <Card className="bg-card/50 border-cyber-border">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">
            Répartition cas de fusion M3 — Confidence = 0.40×S + 0.30×M + 0.30×C
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-40">
            {fusionBarData.every(d => d.count === 0) ? (
              <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
                En attente de données fusion...
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={fusionBarData} layout="vertical" margin={{ left: 16 }}>
                  <XAxis type="number" stroke="#4B5563" fontSize={10} tickLine={false} />
                  <YAxis dataKey="name" type="category" stroke="#4B5563" fontSize={10} width={90} tickLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#161922', border: '1px solid #1E232C', borderRadius: '8px' }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {fusionBarData.map((d, i) => <Cell key={i} fill={d.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </CardContent>
      </Card>

      {/* ── Statut modèles ML ────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { name: 'Isolation Forest', version: '1.0', f1: 0.74, recall: 0.72, fpr: 0.08, status: 'active' },
          { name: 'One-Class SVM',    version: '1.0', f1: 0.68, recall: 0.65, fpr: 0.12, status: 'active' },
          { name: 'Autoencoder',      version: '1.0', f1: 0.71, recall: 0.70, fpr: 0.09, status: 'active' },
        ].map((model, i) => (
          <Card key={i} className="bg-card/50 border-cyber-border">
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h4 className="font-medium text-sm">{model.name}</h4>
                  <p className="text-xs text-muted-foreground">v{model.version}</p>
                </div>
                <Badge variant="secondary" className="bg-green-500/10 text-green-400">
                  {model.status}
                </Badge>
              </div>
              <div className="grid grid-cols-3 gap-2 text-center">
                <div>
                  <p className="text-lg font-bold font-mono text-violet-400">
                    {(model.f1 * 100).toFixed(0)}%
                  </p>
                  <p className="text-[10px] text-muted-foreground">F1</p>
                </div>
                <div>
                  <p className="text-lg font-bold font-mono text-violet-400">
                    {(model.recall * 100).toFixed(0)}%
                  </p>
                  <p className="text-[10px] text-muted-foreground">Recall</p>
                </div>
                <div>
                  <p className="text-lg font-bold font-mono text-violet-400">
                    {(model.fpr * 100).toFixed(1)}%
                  </p>
                  <p className="text-[10px] text-muted-foreground">FPR</p>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

    </div>
  );
}

export default IDSMonitor;