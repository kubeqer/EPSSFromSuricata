import AlertTable from "../components/AlertTable";

export default function AlertsCritical() {
  return (
    <div>
      <h2 className="text-2xl font-bold mb-4">🚨 Krytyczne alerty (priorytet 1)</h2>
      <AlertTable onlyCritical={true} />
    </div>
  );
}
