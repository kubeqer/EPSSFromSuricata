import SystemStats from "../components/SystemStats";
import PieChartStats from "../components/PieChartStats";
import AlertTable from "../components/AlertTable";
import AlertTimelineChart from "../components/AlertTimelineChart";

export default function Dashboard() {
  return (
    <div className="space-y-12">
      {/* Statystyki systemowe */}
      <section>
        <h2 className="text-2xl font-bold mb-4">📊 Statystyki systemowe</h2>
        <SystemStats />
      </section>

      {/* Wykres alertów wg priorytetu */}
      <section>
        <h2 className="text-2xl font-bold mb-4">🥧 Wykres alertów wg priorytetu</h2>
        <PieChartStats />
      </section>

      {/* Wykres czasowy */}
      <section>
        <h2 className="text-2xl font-bold mb-4">📈 Liczba alertów w czasie</h2>
        <AlertTimelineChart />
      </section>

      {/* Tabela alertów */}
      <section>
        <h2 className="text-2xl font-bold mb-4">🧾 Ostatnie alerty</h2>
        <AlertTable />
      </section>
    </div>
  );
}
