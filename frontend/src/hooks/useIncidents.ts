// useIncidents.ts — hook incidents
import { useState, useEffect, useCallback } from "react";
import { incidentsAPI } from "../services/api";

export function useIncidents(params?: { severity?: string; status?: string; limit?: number }) {
  const [incidents, setIncidents] = useState<any[]>([]);
  const [stats,     setStats]     = useState<any>(null);
  const [loading,   setLoading]   = useState(true);

  const load = useCallback(async () => {
    try {
      const [inc, s] = await Promise.all([
        incidentsAPI.getAll({ ...params, limit: params?.limit || 50 }),
        incidentsAPI.getStats(),
      ]);
      setIncidents(inc.incidents || []);
      setStats(s);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  }, [JSON.stringify(params)]);

  useEffect(() => {
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, [load]);

  return { incidents, stats, loading, reload: load };
}

export default useIncidents;