import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import Settings from "./pages/Settings";
import AlertsCritical from "./pages/AlertsCritical";


function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/alerts/critical" element={<AlertsCritical />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;
