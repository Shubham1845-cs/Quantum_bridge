import { motion } from "framer-motion";
import { useEffect, useState } from "react";
import { ShieldCheck, Cpu, Lock, Radio, Activity, AlertTriangle, Zap, Radiation } from "lucide-react";

type Algo = {
  name: string;
  type: string;
  today: boolean;
  postQ: boolean;
  icon: typeof ShieldCheck;
};

const ALGOS: Algo[] = [
  { name: "ECDSA P-256", type: "CLASSICAL SIG", today: true, postQ: false, icon: Lock },
  { name: "ML-DSA-65", type: "POST-QUANTUM SIG", today: true, postQ: true, icon: ShieldCheck },
  { name: "AES-256-GCM", type: "SYMMETRIC CIPHER", today: true, postQ: true, icon: Cpu },
];

// CRT phosphor palette — cyan-shifted to match QuantumBridge brand
const P = {
  bg: "#020812",
  deep: "#04101a",
  green: "#67e8f9",
  greenDim: "#22d3ee",
  greenDark: "#0a2233",
  amber: "#ffb347",
  red: "#ff5c6c",
  scan: "rgba(103,232,249,0.08)",
};

function Flicker({ children, intensity = 0.06 }: { children: React.ReactNode; intensity?: number }) {
  return (
    <motion.div
      animate={{ opacity: [1, 1 - intensity, 1, 1 - intensity / 2, 1] }}
      transition={{ duration: 3.6, repeat: Infinity, ease: "easeInOut" }}
      style={{ display: "contents" }}
    >
      {children}
    </motion.div>
  );
}

function BlinkDot({ color = P.green, size = 6 }: { color?: string; size?: number }) {
  return (
    <motion.span
      animate={{ opacity: [1, 0.2, 1] }}
      transition={{ duration: 1.3, repeat: Infinity, ease: "easeInOut" }}
      className="inline-block rounded-full"
      style={{ width: size, height: size, background: color, boxShadow: `0 0 8px ${color}, 0 0 14px ${color}` }}
    />
  );
}

function StatusChip({ ok, label }: { ok: boolean; label: string }) {
  const color = ok ? P.green : P.red;
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-sm px-1.5 py-[2px] font-mono text-[9px] tracking-[0.18em]"
      style={{
        color,
        background: `${color}10`,
        border: `1px solid ${color}55`,
        textShadow: `0 0 6px ${color}`,
      }}
    >
      <BlinkDot color={color} size={5} />
      {label}
    </span>
  );
}

function TelemetryBar({ label, value, max = 100 }: { label: string; value: number; max?: number }) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div className="font-mono text-[10px]" style={{ color: P.green }}>
      <div className="flex justify-between mb-1 opacity-80">
        <span className="tracking-[0.2em]">{label}</span>
        <span className="tabular-nums" style={{ textShadow: `0 0 6px ${P.green}` }}>
          {value.toFixed(0).padStart(3, "0")}/{max}
        </span>
      </div>
      <div
        className="relative h-2 overflow-hidden rounded-[1px]"
        style={{ background: P.greenDark, border: `1px solid ${P.green}33` }}
      >
        <motion.div
          className="absolute inset-y-0 left-0"
          style={{
            background: `linear-gradient(90deg, ${P.greenDim}, ${P.green})`,
            boxShadow: `0 0 10px ${P.green}, inset 0 0 6px ${P.green}`,
          }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.8, ease: "easeOut" }}
        />
        {/* segments */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            backgroundImage:
              "repeating-linear-gradient(90deg, transparent 0 7px, rgba(0,0,0,0.55) 7px 8px)",
          }}
        />
      </div>
    </div>
  );
}

function Radar() {
  return (
    <div
      className="relative aspect-square w-full rounded-full overflow-hidden"
      style={{
        background:
          `radial-gradient(circle, ${P.greenDark} 0%, ${P.deep} 70%, ${P.bg} 100%)`,
        border: `1px solid ${P.green}55`,
        boxShadow: `0 0 30px ${P.green}33, inset 0 0 30px ${P.green}22`,
      }}
    >
      {/* Rings */}
      {[25, 50, 75, 100].map((r) => (
        <div
          key={r}
          className="absolute rounded-full pointer-events-none"
          style={{
            inset: `${(100 - r) / 2}%`,
            border: `1px solid ${P.green}33`,
          }}
        />
      ))}
      {/* Crosshair */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute left-1/2 top-0 bottom-0 w-px" style={{ background: `${P.green}33` }} />
        <div className="absolute top-1/2 left-0 right-0 h-px" style={{ background: `${P.green}33` }} />
      </div>
      {/* Sweep */}
      <motion.div
        className="absolute inset-0 origin-center"
        animate={{ rotate: 360 }}
        transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
        style={{
          background: `conic-gradient(from 0deg, ${P.green}00 0deg, ${P.green}66 50deg, ${P.green}00 60deg, ${P.green}00 360deg)`,
          mixBlendMode: "screen",
        }}
      />
      {/* Blips */}
      {[
        { top: "30%", left: "60%", d: 0 },
        { top: "60%", left: "35%", d: 0.7 },
        { top: "45%", left: "70%", d: 1.4 },
      ].map((b, i) => (
        <motion.span
          key={i}
          className="absolute rounded-full"
          style={{
            top: b.top,
            left: b.left,
            width: 6,
            height: 6,
            background: P.green,
            boxShadow: `0 0 10px ${P.green}, 0 0 16px ${P.green}`,
          }}
          animate={{ opacity: [1, 0.1, 1], scale: [1, 1.4, 1] }}
          transition={{ duration: 2.5, delay: b.d, repeat: Infinity }}
        />
      ))}
      {/* Center */}
      <div
        className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full"
        style={{ width: 8, height: 8, background: P.green, boxShadow: `0 0 12px ${P.green}` }}
      />
    </div>
  );
}

function ScrollingLog() {
  const lines = [
    "> HANDSHAKE INIT :: KEM=ML-KEM-768",
    "> ECDSA-P256 :: SIG OK [0x9F2A]",
    "> ML-DSA-65 :: SIG OK [0xC1B8]",
    "> AES-256-GCM :: SEAL OK",
    "> POLICY VERIFY :: DUAL-SIG ENFORCED",
    "> UPLINK :: 192.168.1.4 -> SAT-7",
    "> ENTROPY POOL :: 4096b OK",
    "> THREAT SCAN :: NO ANOMALY",
    "> QUANTUM CHANNEL :: STABLE",
    "> HARVEST DETECT :: 0 EVENTS",
  ];
  return (
    <div
      className="relative h-32 overflow-hidden rounded-sm font-mono text-[10px] leading-[1.6]"
      style={{
        background: P.deep,
        border: `1px solid ${P.green}33`,
        color: P.green,
        padding: "8px 10px",
        textShadow: `0 0 6px ${P.green}`,
      }}
    >
      <motion.div
        animate={{ y: [0, -lines.length * 16] }}
        transition={{ duration: lines.length * 1.4, repeat: Infinity, ease: "linear" }}
      >
        {[...lines, ...lines].map((l, i) => (
          <div key={i} className="whitespace-nowrap">
            {l}
          </div>
        ))}
      </motion.div>
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            `linear-gradient(180deg, ${P.deep} 0%, transparent 18%, transparent 82%, ${P.deep} 100%)`,
        }}
      />
    </div>
  );
}

function AlgoRow({ a, i }: { a: Algo; i: number }) {
  const Icon = a.icon;
  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      whileInView={{ opacity: 1, x: 0 }}
      viewport={{ once: true }}
      transition={{ delay: 0.1 + i * 0.1, duration: 0.5 }}
      className="relative flex items-center gap-3 px-3 py-2.5 rounded-sm overflow-hidden"
      style={{
        background: `linear-gradient(90deg, ${P.green}08, transparent)`,
        border: `1px solid ${P.green}33`,
      }}
    >
      <motion.div
        className="absolute left-0 top-0 bottom-0 w-[2px]"
        style={{ background: P.green, boxShadow: `0 0 8px ${P.green}` }}
        animate={{ opacity: [0.4, 1, 0.4] }}
        transition={{ duration: 1.8, repeat: Infinity, delay: i * 0.3 }}
      />
      <div
        className="grid place-content-center rounded-sm shrink-0"
        style={{
          width: 32,
          height: 32,
          background: `${P.green}10`,
          border: `1px solid ${P.green}55`,
          boxShadow: `inset 0 0 8px ${P.green}33`,
        }}
      >
        <Icon size={14} color={P.green} style={{ filter: `drop-shadow(0 0 4px ${P.green})` }} />
      </div>
      <div className="flex-1 min-w-0">
        <div
          className="font-mono text-[12px] font-bold tracking-[0.08em] truncate"
          style={{ color: P.green, textShadow: `0 0 6px ${P.green}` }}
        >
          {a.name}
        </div>
        <div className="font-mono text-[9px] tracking-[0.22em] opacity-70" style={{ color: P.greenDim }}>
          {a.type}
        </div>
      </div>
      <div className="flex flex-col gap-1 items-end shrink-0">
        <StatusChip ok={a.today} label="TODAY" />
        <StatusChip ok={a.postQ} label="POST-Q" />
      </div>
    </motion.div>
  );
}

export default function QuantumDefenseConsole() {
  const [ops, setOps] = useState(8421);
  const [latency, setLatency] = useState(42);
  const [shield, setShield] = useState(94);
  const [entropy, setEntropy] = useState(78);
  const [uptime, setUptime] = useState(0);
  const [clock, setClock] = useState("00:00:00");

  useEffect(() => {
    const t = setInterval(() => {
      setOps((v) => v + Math.floor(Math.random() * 9) + 1);
      setLatency(38 + Math.floor(Math.random() * 14));
      setShield(90 + Math.floor(Math.random() * 9));
      setEntropy(72 + Math.floor(Math.random() * 22));
      setUptime((u) => u + 1);
      const d = new Date();
      setClock(
        `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}:${String(
          d.getUTCSeconds()
        ).padStart(2, "0")}`
      );
    }, 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <section
      className="relative overflow-hidden py-24 md:py-32"
      style={{
        background: `radial-gradient(1200px 700px at 50% 50%, #04101a, ${P.bg} 70%)`,
      }}
    >
      {/* ambient bloom */}
      <div
        aria-hidden
        className="absolute inset-0 pointer-events-none"
        style={{
          background: `radial-gradient(700px 400px at 50% 40%, ${P.green}1a, transparent 60%)`,
        }}
      />

      <div className="relative mx-auto max-w-7xl px-6 lg:px-10">
        {/* Section header */}
        <div className="text-center mb-10">
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="inline-flex items-center gap-2 font-mono text-[10px] tracking-[0.3em] uppercase mb-4 px-3 py-1 rounded-sm"
            style={{
              color: P.green,
              border: `1px solid ${P.green}55`,
              background: `${P.green}08`,
              textShadow: `0 0 6px ${P.green}`,
            }}
          >
            <AlertTriangle size={11} /> THREAT VECTOR :: HARVEST-NOW DECRYPT-LATER
          </motion.div>
          <h2
            className="font-mono"
            style={{
              fontSize: "clamp(1.8rem, 4vw, 3rem)",
              color: P.green,
              textShadow: `0 0 14px ${P.green}, 0 0 28px ${P.greenDim}88`,
              letterSpacing: "0.06em",
            }}
          >
            QUANTUM SECURITY CORE
          </h2>
          <p
            className="mt-3 max-w-2xl mx-auto font-mono text-xs tracking-wide"
            style={{ color: `${P.green}cc` }}
          >
            // DUAL-SIGNATURE VERIFIER · ML-DSA-65 + ECDSA-P256 · NIST PQC FINALIST ACTIVE
          </p>
        </div>

        {/* MAIN CRT CONSOLE */}
        <Flicker>
          <div
            className="relative rounded-2xl p-3 md:p-4"
            style={{
              background: `linear-gradient(180deg, #0a1a2a, #04101a)`,
              border: `1px solid ${P.green}55`,
              boxShadow: `0 40px 120px ${P.green}22, 0 0 60px ${P.green}1a, inset 0 1px 0 ${P.green}22`,
            }}
          >
            {/* Bezel header */}
            <div
              className="flex items-center justify-between px-4 py-2 mb-3 rounded-md font-mono text-[10px] tracking-[0.25em]"
              style={{
                background: `linear-gradient(180deg, #05172a, #021014)`,
                border: `1px solid ${P.green}33`,
                color: P.green,
                textShadow: `0 0 6px ${P.green}`,
              }}
            >
              <div className="flex items-center gap-3">
                <BlinkDot />
                <span>QDM://CORE.CONSOLE</span>
                <span className="opacity-50">v2.4.1</span>
              </div>
              <div className="hidden md:flex items-center gap-4 opacity-80">
                <span>UTC {clock}</span>
                <span>UP {String(uptime).padStart(5, "0")}s</span>
                <span style={{ color: P.green }}>● ONLINE</span>
              </div>
            </div>

            {/* SCREEN */}
            <div
              className="relative rounded-xl overflow-hidden"
              style={{
                background: `radial-gradient(ellipse at center, ${P.deep} 0%, ${P.bg} 100%)`,
                border: `1px solid ${P.green}55`,
                boxShadow: `inset 0 0 80px ${P.green}33, inset 0 0 200px rgba(0,0,0,0.7)`,
              }}
            >
              {/* CRT curvature mask */}
              <div
                aria-hidden
                className="absolute inset-0 pointer-events-none z-30 rounded-xl"
                style={{
                  background:
                    "radial-gradient(ellipse at center, transparent 55%, rgba(0,0,0,0.55) 100%)",
                }}
              />
              {/* Scanlines */}
              <div
                aria-hidden
                className="absolute inset-0 pointer-events-none z-20 mix-blend-overlay"
                style={{
                  backgroundImage:
                    "repeating-linear-gradient(0deg, rgba(0,0,0,0.35) 0px, rgba(0,0,0,0.35) 1px, transparent 1px, transparent 3px)",
                }}
              />
              {/* Noise */}
              <motion.div
                aria-hidden
                className="absolute inset-0 pointer-events-none z-20 opacity-[0.08]"
                animate={{ backgroundPosition: ["0 0", "100px 100px"] }}
                transition={{ duration: 0.6, repeat: Infinity, ease: "linear" }}
                style={{
                  backgroundImage:
                    "radial-gradient(rgba(255,255,255,0.4) 1px, transparent 1px)",
                  backgroundSize: "3px 3px",
                }}
              />
              {/* Moving scan sweep */}
              <motion.div
                aria-hidden
                className="absolute left-0 right-0 h-24 pointer-events-none z-20"
                style={{
                  background: `linear-gradient(180deg, transparent, ${P.green}22, transparent)`,
                  filter: "blur(2px)",
                }}
                animate={{ top: ["-10%", "110%"] }}
                transition={{ duration: 7, repeat: Infinity, ease: "linear" }}
              />

              {/* Grid backdrop */}
              <div
                aria-hidden
                className="absolute inset-0 opacity-25 pointer-events-none"
                style={{
                  backgroundImage: `linear-gradient(${P.green}22 1px, transparent 1px), linear-gradient(90deg, ${P.green}22 1px, transparent 1px)`,
                  backgroundSize: "40px 40px",
                  maskImage:
                    "radial-gradient(ellipse at center, black 40%, transparent 80%)",
                }}
              />

              {/* CONTENT GRID */}
              <div className="relative z-10 grid grid-cols-12 gap-3 p-4 md:p-6">
                {/* LEFT TELEMETRY COL */}
                <div className="col-span-12 md:col-span-3 space-y-4">
                  <div
                    className="rounded-sm p-3"
                    style={{ border: `1px solid ${P.green}33`, background: `${P.green}05` }}
                  >
                    <div
                      className="font-mono text-[9px] tracking-[0.25em] mb-3 flex items-center gap-2"
                      style={{ color: P.green }}
                    >
                      <Activity size={10} /> TELEMETRY
                    </div>
                    <div className="space-y-3">
                      <TelemetryBar label="SHIELD" value={shield} />
                      <TelemetryBar label="ENTROPY" value={entropy} />
                      <TelemetryBar label="LATENCY" value={latency} max={120} />
                    </div>
                  </div>

                  <div
                    className="rounded-sm p-3 font-mono text-[10px]"
                    style={{
                      border: `1px solid ${P.green}33`,
                      background: `${P.green}05`,
                      color: P.green,
                    }}
                  >
                    <div className="tracking-[0.25em] mb-2 flex items-center gap-2">
                      <Zap size={10} /> METRICS
                    </div>
                    <div className="flex justify-between py-1 border-b" style={{ borderColor: `${P.green}22` }}>
                      <span className="opacity-70">OPS/SEC</span>
                      <span className="tabular-nums" style={{ textShadow: `0 0 6px ${P.green}` }}>
                        {ops.toLocaleString()}
                      </span>
                    </div>
                    <div className="flex justify-between py-1 border-b" style={{ borderColor: `${P.green}22` }}>
                      <span className="opacity-70">UPLINK</span>
                      <span style={{ color: P.green }}>● SECURE</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span className="opacity-70">THREATS</span>
                      <span className="tabular-nums">000</span>
                    </div>
                  </div>
                </div>

                {/* CENTER: ALGOS */}
                <div className="col-span-12 md:col-span-6">
                  <div
                    className="rounded-sm p-4"
                    style={{
                      border: `1px solid ${P.green}55`,
                      background: `linear-gradient(180deg, ${P.green}06, transparent)`,
                      boxShadow: `inset 0 0 30px ${P.green}11`,
                    }}
                  >
                    <div className="flex items-center justify-between mb-4">
                      <div
                        className="font-mono text-[10px] tracking-[0.25em] flex items-center gap-2"
                        style={{ color: P.green, textShadow: `0 0 6px ${P.green}` }}
                      >
                        <ShieldCheck size={12} /> DUAL-SIGNATURE VERIFIER
                      </div>
                      <motion.div
                        animate={{ rotate: 360 }}
                        transition={{ duration: 12, repeat: Infinity, ease: "linear" }}
                        className="grid place-content-center rounded-full"
                        style={{
                          width: 28,
                          height: 28,
                          border: `1px dashed ${P.green}66`,
                          boxShadow: `0 0 10px ${P.green}33`,
                        }}
                      >
                        <Radiation size={14} color={P.green} style={{ filter: `drop-shadow(0 0 4px ${P.green})` }} />
                      </motion.div>
                    </div>

                    <div className="space-y-2.5">
                      {ALGOS.map((a, i) => (
                        <AlgoRow key={a.name} a={a} i={i} />
                      ))}
                    </div>

                    {/* Data transmission */}
                    <div
                      className="relative mt-4 h-5 overflow-hidden rounded-sm"
                      style={{ background: P.deep, border: `1px solid ${P.green}33` }}
                    >
                      <motion.div
                        className="absolute top-1/2 -translate-y-1/2 h-px w-1/3"
                        style={{ background: `linear-gradient(90deg, transparent, ${P.green}, transparent)`, boxShadow: `0 0 8px ${P.green}` }}
                        animate={{ x: ["-100%", "400%"] }}
                        transition={{ duration: 2.4, repeat: Infinity, ease: "linear" }}
                      />
                      <div className="absolute inset-0 flex items-center justify-center font-mono text-[9px] tracking-[0.3em]" style={{ color: `${P.green}aa` }}>
                        DATA STREAM :: ENCRYPTED :: AES-256-GCM
                      </div>
                    </div>
                  </div>

                  {/* Policy warning */}
                  <motion.div
                    animate={{ boxShadow: [`0 0 0 ${P.green}00`, `0 0 20px ${P.green}55`, `0 0 0 ${P.green}00`] }}
                    transition={{ duration: 2.6, repeat: Infinity }}
                    className="relative mt-3 flex items-start gap-3 p-3 rounded-sm font-mono text-[11px]"
                    style={{
                      border: `1px solid ${P.green}66`,
                      background: `${P.green}08`,
                      color: P.green,
                      textShadow: `0 0 5px ${P.green}`,
                    }}
                  >
                    <ShieldCheck size={16} className="shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold">[POLICY]</span> Both signatures must verify. If either fails, request is rejected and threat flagged.
                    </div>
                  </motion.div>
                </div>

                {/* RIGHT: RADAR */}
                <div className="col-span-12 md:col-span-3 space-y-3">
                  <div
                    className="rounded-sm p-3"
                    style={{ border: `1px solid ${P.green}33`, background: `${P.green}05` }}
                  >
                    <div
                      className="font-mono text-[9px] tracking-[0.25em] mb-3 flex items-center justify-between"
                      style={{ color: P.green }}
                    >
                      <span className="flex items-center gap-2"><Radio size={10} /> RADAR</span>
                      <BlinkDot />
                    </div>
                    <Radar />
                    <div className="mt-3 font-mono text-[9px] tracking-[0.2em] flex justify-between" style={{ color: `${P.green}aa` }}>
                      <span>RNG 4096</span>
                      <span>SWP 4.0s</span>
                    </div>
                  </div>
                </div>

                {/* BOTTOM: SCROLLING LOG */}
                <div className="col-span-12">
                  <div
                    className="flex items-center justify-between font-mono text-[9px] tracking-[0.25em] mb-1"
                    style={{ color: P.green }}
                  >
                    <span>// SYS.LOG</span>
                    <span className="opacity-70">tail -f /var/log/qdm.log</span>
                  </div>
                  <ScrollingLog />
                </div>

                {/* BOTTOM INDICATORS */}
                <div className="col-span-12 grid grid-cols-2 md:grid-cols-5 gap-2">
                  {[
                    { l: "PQC", v: "ML-DSA-65" },
                    { l: "KEM", v: "ML-KEM-768" },
                    { l: "CIPHER", v: "AES-256" },
                    { l: "HASH", v: "SHA3-512" },
                    { l: "MODE", v: "DUAL-SIG" },
                  ].map((x, i) => (
                    <motion.div
                      key={x.l}
                      animate={{ opacity: [0.7, 1, 0.7] }}
                      transition={{ duration: 2 + i * 0.3, repeat: Infinity }}
                      className="rounded-sm px-2 py-1.5 font-mono text-[9px] tracking-[0.2em] flex items-center justify-between"
                      style={{
                        border: `1px solid ${P.green}33`,
                        background: `${P.green}06`,
                        color: P.green,
                      }}
                    >
                      <span className="opacity-60">{x.l}</span>
                      <span style={{ textShadow: `0 0 5px ${P.green}` }}>{x.v}</span>
                    </motion.div>
                  ))}
                </div>
              </div>
            </div>

            {/* Bezel footer */}
            <div
              className="mt-3 px-4 py-2 rounded-md font-mono text-[10px] tracking-[0.25em] flex items-center justify-between"
              style={{
                background: `linear-gradient(180deg, #05172a, #021014)`,
                border: `1px solid ${P.green}33`,
                color: `${P.green}cc`,
              }}
            >
              <span>QUANTUMBRIDGE :: DEFENSE CORE</span>
              <span className="flex items-center gap-2">
                <BlinkDot color={P.green} /> NIST PQC COMPLIANT
              </span>
            </div>
          </div>
        </Flicker>
      </div>
    </section>
  );
}
