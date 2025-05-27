
import { useEffect, useState } from "react";
import api from "../api/api";
import DatePicker from "react-datepicker";
import "react-datepicker/dist/react-datepicker.css";
import toast from "react-hot-toast";

export default function AlertTable({ onlyCritical = false }) {
  const [alerts, setAlerts] = useState([]);
  const [page, setPage] = useState(1);
  const [priority, setPriority] = useState(onlyCritical ? "1" : "");
  const [srcIp, setSrcIp] = useState("");
  const [destIp, setDestIp] = useState("");
  const [dateFrom, setDateFrom] = useState(null);
  const [dateTo, setDateTo] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    const params = {
      priority: priority ? [priority] : undefined,
      start_date: dateFrom ? dateFrom.toISOString() : undefined,
      end_date: dateTo ? dateTo.toISOString() : undefined,
      page,
    };

    api.get("/alerts", { params })
      .then(res => setAlerts(res.data.items || []))
      .catch(() => setAlerts([]))
      .finally(() => setLoading(false));
  }, [page, priority, srcIp, destIp, dateFrom, dateTo]);

  useEffect(() => {
    const interval = setInterval(() => {
      const params = {
        priority: priority ? [priority] : undefined,
        page,
      };
      api.get("/alerts", { params })
        .then(res => {
          const newAlerts = res.data.items || [];
          if (newAlerts.length > alerts.length) {
            toast.success("🔄 Nowe alerty dostępne – kliknij, aby odświeżyć");
          }
        })
        .catch(() => {});
    }, 30000);
    return () => clearInterval(interval);
  }, [alerts, page, priority]);

  const rowColor = (prio) => {
    switch (prio) {
      case 1: return "bg-red-100 dark:bg-red-900";
      case 2: return "bg-orange-100 dark:bg-orange-900";
      case 3: return "bg-yellow-100 dark:bg-yellow-900";
      default: return "bg-white dark:bg-gray-800";
    }
  };

  const exportToCSV = () => {
    if (alerts.length === 0) return;
    import("papaparse").then(Papa => {
      import("file-saver").then(({ saveAs }) => {
        const csv = Papa.unparse(alerts);
        const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
        saveAs(blob, `alerts_${new Date().toISOString().slice(0, 10)}.csv`);
      });
    });
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl shadow p-6">
      <div className="mb-4 flex justify-between items-center">
        <h2 className="text-xl font-semibold">🧾 Filtrowane alerty</h2>
        <button
          onClick={exportToCSV}
          className="px-3 py-1 rounded bg-green-600 text-white hover:bg-green-700"
        >
          📤 Eksportuj CSV
        </button>
      </div>

      {!onlyCritical && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <input
            placeholder="Priorytet"
            value={priority}
            onChange={(e) => setPriority(e.target.value)}
            className="border px-2 py-1 rounded text-black"
          />
          <input
            placeholder="Źródło IP"
            value={srcIp}
            onChange={(e) => setSrcIp(e.target.value)}
            className="border px-2 py-1 rounded text-black"
          />
          <input
            placeholder="Cel IP"
            value={destIp}
            onChange={(e) => setDestIp(e.target.value)}
            className="border px-2 py-1 rounded text-black"
          />
          <DatePicker
            selected={dateFrom}
            onChange={setDateFrom}
            placeholderText="Data od"
            dateFormat="yyyy-MM-dd"
            className="border px-2 py-1 rounded text-black"
          />
          <DatePicker
            selected={dateTo}
            onChange={setDateTo}
            placeholderText="Data do"
            dateFormat="yyyy-MM-dd"
            className="border px-2 py-1 rounded text-black"
          />
        </div>
      )}

      {loading ? (
        <p className="text-gray-500">Ładowanie alertów...</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-200 dark:bg-gray-700 text-left">
              <tr>
                <th className="p-2">Czas</th>
                <th className="p-2">Źródło</th>
                <th className="p-2">Cel</th>
                <th className="p-2">Priorytet</th>
                <th className="p-2">Wiadomość</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr><td className="p-3 text-gray-500" colSpan={5}>Brak danych</td></tr>
              ) : (
                alerts.map((a, i) => (
                  <tr key={i} className={`${rowColor(a.priority)} border-b border-gray-300 dark:border-gray-700`}>
                    <td className="p-2">{a.created_at}</td>
                    <td className="p-2">{a.event?.src_ip}</td>
                    <td className="p-2">{a.event?.dest_ip}</td>
                    <td className="p-2">{a.priority}</td>
                    <td className="p-2">{a.event?.alert?.signature || "Brak sygnatury"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      <div className="mt-4 flex gap-4">
        <button
          onClick={() => setPage(p => Math.max(1, p - 1))}
          className="px-3 py-1 rounded bg-gray-300 hover:bg-gray-400 dark:bg-gray-700 dark:hover:bg-gray-600"
        >
          ← Poprzednia
        </button>
        <button
          onClick={() => setPage(p => p + 1)}
          className="px-3 py-1 rounded bg-gray-300 hover:bg-gray-400 dark:bg-gray-700 dark:hover:bg-gray-600"
        >
          Następna →
        </button>
      </div>
    </div>
  );
}