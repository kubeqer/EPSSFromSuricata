
import { useEffect, useState } from "react";
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";
import api from "../api/api";

const COLORS = ["#00bcd4", "#4caf50", "#ff9800", "#f44336", "#9c27b0"];

export default function PieChartStats() {
  const [data, setData] = useState([]);

  useEffect(() => {
    api.get("/alerts/stats/summary")
      .then((res) => {
        const raw = res.data.by_priority;
        const converted = Object.entries(raw).map(([key, value]) => ({ name: `Priorytet ${key}`, value }));
        setData(converted);
      })
      .catch((err) => {
        console.error("Błąd pobierania wykresu:", err);
        setData([]);
      });
  }, []);

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl shadow p-6">
      <h2 className="text-xl font-semibold mb-4">Wykres alertów wg priorytetów</h2>
      {data.length === 0 ? (
        <p className="text-gray-500">Brak danych do wyświetlenia</p>
      ) : (
        <ResponsiveContainer width="100%" height={300}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              outerRadius={100}
              label
            >
              {data.map((_, i) => (
                <Cell key={i} fill={COLORS[i % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
