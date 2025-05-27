// === src/components/SystemStats.jsx ===
import { useEffect, useState } from "react";
import { Clock, AlertTriangle, Server, Activity, Zap } from 'lucide-react';
import api from "../api/api";

export default function SystemStats() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get("/alerts/stats/summary")
      .then(res => setStats(res.data))
      .catch(() => setStats(null))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <p className="text-gray-500">Ładowanie statystyk systemu...</p>;
  if (!stats) return <p className="text-red-500">Błąd ładowania danych</p>;

  const items = [
    { label: "Wszystkie alerty", value: stats.total, icon: Server, color: "bg-blue-100 text-blue-600" },
    { label: "Ostatnie 24h", value: stats.recent_alerts, icon: Clock, color: "bg-green-100 text-green-600" },
    { label: "Syntetyczne alerty", value: stats.synthetic_alerts, icon: Zap, color: "bg-yellow-100 text-yellow-600" },
    { label: "Alerty z CVE", value: stats.cve_alerts, icon: Activity, color: "bg-purple-100 text-purple-600" },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
      {items.map(({ label, value, icon: Icon, color }, i) => (
        <div key={i} className="flex items-center p-4 bg-white rounded-xl shadow border-l-4 border-gray-200">
          <div className={`w-12 h-12 flex items-center justify-center rounded-full mr-4 ${color}`}>
            <Icon size={24} />
          </div>
          <div>
            <h4 className="text-sm text-gray-500">{label}</h4>
            <p className="text-2xl font-semibold text-gray-800 dark:text-white">{value}</p>
          </div>
        </div>
      ))}
    </div>
  );
}
