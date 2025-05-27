import { Link, useLocation } from "react-router-dom";
import { Moon, Sun, LayoutDashboard, AlertCircle, Settings } from "lucide-react";
import { useEffect, useState } from "react";
import { AlertTriangle } from "lucide-react";

export default function Layout({ children }) {
  const location = useLocation();
  const [dark, setDark] = useState(() => localStorage.getItem("dark") === "true");

  useEffect(() => {
    if (dark) {
      document.documentElement.classList.add("dark");
      localStorage.setItem("dark", "true");
    } else {
      document.documentElement.classList.remove("dark");
      localStorage.setItem("dark", "false");
    }
  }, [dark]);

  const navItems = [
    { name: "Dashboard", path: "/", icon: LayoutDashboard },
    { name: "Alerts", path: "/alerts", icon: AlertCircle },
    { name: "Settings", path: "/settings", icon: Settings },
    { name: "Krytyczne", path: "/alerts/critical", icon: AlertTriangle },

  ];

  return (
    <div className="flex min-h-screen bg-gray-100 dark:bg-gray-900 text-gray-900 dark:text-gray-100 transition-colors">
      {/* Sidebar */}
      <aside className="w-64 bg-white dark:bg-gray-800 shadow-lg flex flex-col">
        <div className="px-6 py-4 text-xl font-bold border-b border-gray-200 dark:border-gray-700">
          🛡️ Suricata UI
        </div>
        <nav className="flex-1 p-4 space-y-2">
          {navItems.map(({ name, path, icon: Icon }) => (
            <Link
              key={name}
              to={path}
              className={`flex items-center gap-3 p-2 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700 ${
                location.pathname === path ? "bg-gray-200 dark:bg-gray-700 font-semibold" : ""
              }`}
            >
              <Icon size={20} />
              <span>{name}</span>
            </Link>
          ))}
        </nav>
        <div className="p-4 border-t border-gray-200 dark:border-gray-700">
          <button
            onClick={() => setDark(!dark)}
            className="flex items-center gap-2 px-3 py-1.5 w-full justify-center bg-gray-200 dark:bg-gray-700 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition"
          >
            {dark ? <Sun size={16} /> : <Moon size={16} />}
            {dark ? "Light Mode" : "Dark Mode"}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 p-6 bg-gray-50 dark:bg-gray-900 transition-colors">
        {children}
      </main>
    </div>
  );
}
