import { useEffect, useState } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import api from "../api/api";

export default function AlertTimelineChart() {
  const [data, setData] = useState([]);
  const [error, setError] = useState(false);

  useEffect(() => {
    api.get("/alerts/stats/timeline")
      .then(res => setData(res.data))
      .catch(err => {
        console.error("Błąd pobierania danych timeline:", err);
        setError(true);
        setData([]);
      });
  }, []);

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl shadow p-6 mt-8">
      <h2 className="text-xl font-semibold mb-4">📈 Alerty na przestrzeni czasu</h2>

      {error || data.length === 0 ? (
        <p className="text-gray-400 italic">Brak danych do wyświetlenia</p>
      ) : (
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={data}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="date" />
            <YAxis allowDecimals={false} />
            <Tooltip />
            <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
