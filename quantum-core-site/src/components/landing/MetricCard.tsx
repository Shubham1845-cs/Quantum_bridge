import { useEffect, useRef, useState } from "react";
import { motion, useInView, useMotionValue, animate as fmAnimate } from "framer-motion";
import Sparkline from "./Sparkline";

export interface QuantumMetric {
  label: string;
  value: number;
  display: (v: number) => string;
  trend: string;
  trendUp?: boolean;
  glow: string;       // hex/rgba for glow
  accent: string;     // primary accent
  accent2: string;    // secondary gradient stop
  spark: number[];    // 0..1 sparkline points
}

interface MetricCardProps {
  m: QuantumMetric;
  index: number;
}

function AnimatedNumber({ value, display, active }: { value: number; display: (v: number) => string; active: boolean }) {
  const mv = useMotionValue(0);
  const [text, setText] = useState(display(0));
  useEffect(() => {
    if (!active) return;
    const controls = fmAnimate(mv, value, {
      duration: 1.8,
      ease: [0.22, 1, 0.36, 1],
      onUpdate: (v) => setText(display(v)),
    });
    return () => controls.stop();
  }, [active, value, display, mv]);
  return <span>{text}</span>;
}

export default function MetricCard({ m, index }: MetricCardProps) {
  const ref = useRef<HTMLDivElement | null>(null);
  const inView = useInView(ref, { once: true, margin: "-10% 0px" });
  
  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 30 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.7, delay: index * 0.1, ease: [0.22, 1, 0.36, 1] }}
      whileHover={{ y: -6, rotateX: -4, rotateY: 4 }}
      style={{
        position: "relative",
        borderRadius: 20,
        padding: "18px 18px 14px",
        background:
          "linear-gradient(155deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.02) 60%, rgba(255,255,255,0.01) 100%)",
        border: "1px solid rgba(255,255,255,0.09)",
        backdropFilter: "blur(20px)",
        WebkitBackdropFilter: "blur(20px)",
        boxShadow: `0 1px 0 rgba(255,255,255,0.06) inset, 0 20px 60px -30px ${m.glow}, 0 0 0 1px rgba(255,255,255,0.02)`,
        transformStyle: "preserve-3d",
        overflow: "hidden",
        cursor: "default",
      }}
    >
      {/* Ambient gradient blob */}
      <motion.div
        aria-hidden
        animate={{ opacity: [0.55, 0.85, 0.55], scale: [1, 1.08, 1] }}
        transition={{ duration: 5, repeat: Infinity, ease: "easeInOut" }}
        style={{
          position: "absolute",
          top: -40,
          right: -40,
          width: 160,
          height: 160,
          borderRadius: "50%",
          background: `radial-gradient(circle, ${m.glow} 0%, transparent 70%)`,
          filter: "blur(20px)",
          pointerEvents: "none",
        }}
      />
      
      {/* Holographic shimmer */}
      <motion.div
        aria-hidden
        initial={{ x: "-120%" }}
        animate={inView ? { x: "120%" } : {}}
        transition={{ duration: 1.6, delay: 0.3 + index * 0.1, ease: "easeOut" }}
        style={{
          position: "absolute",
          inset: 0,
          background:
            "linear-gradient(115deg, transparent 30%, rgba(255,255,255,0.08) 50%, transparent 70%)",
          pointerEvents: "none",
        }}
      />
      
      {/* Trend chip */}
      <div className="flex items-center justify-between" style={{ position: "relative", zIndex: 2 }}>
        <div
          style={{
            fontSize: 9,
            letterSpacing: "0.16em",
            textTransform: "uppercase",
            color: "rgba(255,255,255,0.5)",
            fontWeight: 600,
          }}
        >
          Live
        </div>
        <div
          style={{
            fontSize: 10,
            fontWeight: 700,
            padding: "3px 8px",
            borderRadius: 999,
            color: m.trendUp === false ? "#fca5a5" : "#86efac",
            background:
              m.trendUp === false
                ? "rgba(248,113,113,0.12)"
                : "rgba(34,197,94,0.12)",
            border: `1px solid ${m.trendUp === false ? "rgba(248,113,113,0.25)" : "rgba(34,197,94,0.25)"}`,
          }}
        >
          {m.trend}
        </div>
      </div>

      {/* Big number */}
      <div
        style={{
          position: "relative",
          zIndex: 2,
          marginTop: 14,
          fontWeight: 800,
          fontSize: "clamp(1.6rem, 2.4vw, 2rem)",
          letterSpacing: "-0.02em",
          background: `linear-gradient(135deg, ${m.accent} 0%, ${m.accent2} 100%)`,
          WebkitBackgroundClip: "text",
          WebkitTextFillColor: "transparent",
          backgroundClip: "text",
          textShadow: `0 0 30px ${m.glow}`,
          lineHeight: 1.05,
        }}
      >
        <AnimatedNumber value={m.value} display={m.display} active={inView} />
      </div>

      {/* Label */}
      <div
        style={{
          position: "relative",
          zIndex: 2,
          marginTop: 6,
          fontSize: 10.5,
          letterSpacing: "0.14em",
          textTransform: "uppercase",
          color: "rgba(255,255,255,0.62)",
          fontWeight: 500,
        }}
      >
        {m.label}
      </div>

      {/* Sparkline */}
      <div style={{ position: "relative", zIndex: 2, marginTop: 12, opacity: 0.95 }}>
        <Sparkline points={m.spark} color={m.accent} active={inView} />
      </div>
    </motion.div>
  );
}
