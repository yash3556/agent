import type { Health } from "../types";

type ServiceHealthStripProps = {
  health: Health | null;
  hasError: boolean;
};

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

export function ServiceHealthStrip({ health, hasError }: ServiceHealthStripProps) {
  const unavailable = hasError || !health;
  const services = [
    {
      label: "API",
      value: unavailable ? "Unavailable" : health.status,
      detail: "Health endpoint",
      state: unavailable ? "bad" : health.status === "ok" ? "good" : "neutral",
    },
    {
      label: "Database",
      value: unavailable ? "Unknown" : health.db,
      detail: "Persistence connectivity",
      state: unavailable ? "neutral" : health.db === "connected" ? "good" : "bad",
    },
    {
      label: "AI provider",
      value: unavailable ? "Unknown" : health.ai,
      detail: health?.ai === "configured"
        ? "Configured; request success is reported per analysis"
        : health?.ai === "disabled"
          ? "Optional analysis is disabled"
          : health?.ai === "unavailable"
            ? "Provider configuration unavailable"
            : "Reported by backend",
      state: unavailable ? "neutral" : health.ai === "unavailable" ? "bad" : health.ai === "configured" ? "configured" : "neutral",
    },
  ];

  return (
    <section className="operations-health" aria-label="System health">
      <div className="health-heading">
        <span className="eyebrow">LIVE SERVICE SIGNALS</span>
        <span className="count-note">
          {unavailable ? "Health data unavailable" : `Last checked ${formatTime(health.time)}`}
        </span>
      </div>
      <div className="health-signals">
        {services.map((service) => (
          <div className="health-signal" key={service.label}>
            <span className={`signal-dot ${service.state}`} aria-hidden="true" />
            <span className="health-signal-copy">
              <span>{service.label}</span>
              <strong>{service.value}</strong>
              <small>{service.detail}</small>
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}
