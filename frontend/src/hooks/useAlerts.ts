// useAlerts.ts — hook alertes
import { useState, useEffect, useCallback } from "react";
import { alertsAPI } from "../services/api";

export function useAlerts(limit = 20) {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [stats,  setStats]  = useState<any>(null);
  const [loading,setLoading]= useState(true);

  const load = useCallback(async () => {
    try {
      const [a, s] = await Promise.all([
        alertsAPI.getRecent(limit),
        alertsAPI.getStats(),
      ]);
      setAlerts(a.alerts || []);
      setStats(s);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  }, [limit]);

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [load]);

  return { alerts, stats, loading, reload: load };
}

export default useAlerts;