const STATUS_LABELS = {
  safe: "Düşük risk",
  suspicious: "Şüpheli",
  dangerous: "Yüksek risk",
};

function RiskGauge({ risk, status }) {
  const safeRisk = Math.max(0, Math.min(100, Number(risk) || 0));
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (safeRisk / 100) * circumference;

  return (
    <div className={`risk-gauge risk-gauge-${status}`} aria-label={`Risk skoru ${safeRisk}, ${STATUS_LABELS[status] ?? status}`}>
      <svg viewBox="0 0 128 128" role="img" aria-hidden="true">
        <circle className="gauge-track" cx="64" cy="64" r={radius} />
        <circle
          className="gauge-value"
          cx="64"
          cy="64"
          r={radius}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="gauge-label"><strong>{safeRisk}</strong><span>/100</span></div>
      <p>{STATUS_LABELS[status] ?? status}</p>
    </div>
  );
}

export default RiskGauge;
