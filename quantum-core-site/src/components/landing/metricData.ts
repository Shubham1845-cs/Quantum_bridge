import { QuantumMetric } from './MetricCard';

/**
 * Metric data constants for the landing page
 * 
 * These metrics are displayed in the Quantum Bridge section
 * with animated counters and sparklines.
 */
export const QUANTUM_METRICS: QuantumMetric[] = [
  {
    label: "Requests Proxied Today",
    value: 247,
    display: (v) => `${Math.round(v)}k+`,
    trend: "+12.4%",
    trendUp: true,
    glow: "rgba(34,211,238,0.45)",
    accent: "#22d3ee",
    accent2: "#67e8f9",
    spark: [0.3, 0.42, 0.38, 0.55, 0.5, 0.62, 0.7, 0.65, 0.78, 0.85, 0.82, 0.94],
  },
  {
    label: "Signature Success Rate",
    value: 99.99,
    display: (v) => `${v.toFixed(2)}%`,
    trend: "+0.01%",
    trendUp: true,
    glow: "rgba(192,132,252,0.45)",
    accent: "#c084fc",
    accent2: "#e9d5ff",
    spark: [0.86, 0.9, 0.88, 0.92, 0.94, 0.93, 0.96, 0.97, 0.95, 0.98, 0.99, 0.99],
  },
  {
    label: "Average Proxy Latency",
    value: 50,
    display: (v) => `<${Math.round(v)}ms`,
    trend: "-8ms",
    trendUp: true,
    glow: "rgba(74,222,128,0.45)",
    accent: "#4ade80",
    accent2: "#bbf7d0",
    spark: [0.7, 0.62, 0.66, 0.55, 0.58, 0.48, 0.42, 0.46, 0.38, 0.34, 0.3, 0.26],
  },
  {
    label: "Legacy Systems Modified",
    value: 0,
    display: () => `0`,
    trend: "zero touch",
    trendUp: true,
    glow: "rgba(244,114,182,0.4)",
    accent: "#f472b6",
    accent2: "#fbcfe8",
    spark: [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5],
  },
];
