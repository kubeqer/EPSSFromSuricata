import { useState } from "react";

export default function Settings() {
  const [refreshInterval, setRefreshInterval] = useState(30);
  const [emailAlerts, setEmailAlerts] = useState(true);
  const [darkMode, setDarkMode] = useState(() =>
    localStorage.getItem("dark") === "true"
  );

  const handleSave = () => {
    localStorage.setItem("refreshInterval", refreshInterval);
    localStorage.setItem("emailAlerts", emailAlerts);
    alert("✅ Ustawienia zapisane!");
  };

  return (
    <div className="bg-white dark:bg-gray-800 p-6 rounded shadow max-w-xl">
      <h2 className="text-2xl font-bold mb-4">⚙️ Ustawienia</h2>

      <div className="space-y-4">
        {/* Odświeżanie */}
        <div>
          <label className="block font-semibold mb-1">Częstotliwość odświeżania (sekundy):</label>
          <input
            type="number"
            value={refreshInterval}
            onChange={(e) => setRefreshInterval(Number(e.target.value))}
            className="w-full px-3 py-1 border rounded text-black"
            min={5}
          />
        </div>

        {/* Powiadomienia e-mail */}
        <div>
          <label className="block font-semibold mb-1">Powiadomienia e-mail:</label>
          <select
            value={emailAlerts ? "yes" : "no"}
            onChange={(e) => setEmailAlerts(e.target.value === "yes")}
            className="w-full px-3 py-1 border rounded text-black"
          >
            <option value="yes">Włączone</option>
            <option value="no">Wyłączone</option>
          </select>
        </div>

        {/* Tryb ciemny */}
        <div>
          <label className="block font-semibold mb-1">Tryb ciemny:</label>
          <p className="text-gray-500">Można przełączać w sidebarze.</p>
        </div>

        <button
          onClick={handleSave}
          className="mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          💾 Zapisz ustawienia
        </button>
      </div>
    </div>
  );
}
