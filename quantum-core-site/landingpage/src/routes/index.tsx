import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence, useScroll, useTransform, useSpring, useInView, useMotionValue, animate as fmAnimate } from "framer-motion";
import {
  ArrowRightCircle,
  Zap,
  LockKeyhole,
  Fingerprint,
  Menu,
  X,
} from "lucide-react";
import RotaryTimeline from "@/components/RotaryTimeline";
import SeamlessVideoLoop from "@/components/SeamlessVideoLoop";
import QuantumDefenseConsole from "@/components/QuantumDefenseConsole";
import QuantumPricing from "@/components/QuantumPricing";
import GlobalAtmosphere from "@/components/GlobalAtmosphere";

/**
 * SectionBridge — soft atmospheric overlap rendered between sections.
 * Eliminates hard breaks by blending colored glow + light streaks across
 * the seam between two components, so the page reads as one continuous scene.
 */
function SectionBridge({
  height = 160,
  from = "rgba(103,232,249,0.10)",
  to = "rgba(192,132,252,0.10)",
}: {
  height?: number;
  from?: string;
  to?: string;
}) {
  return (
    <div
      aria-hidden
      className="relative w-full pointer-events-none -mt-px -mb-px"
      style={{ height }}
    >
      <div
        className="absolute inset-0"
        style={{
          background: `radial-gradient(70% 100% at 50% 0%, ${from}, transparent 70%), radial-gradient(70% 100% at 50% 100%, ${to}, transparent 70%)`,
          filter: "blur(20px)",
        }}
      />
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 top-0 bottom-0 w-px"
        style={{
          background:
            "linear-gradient(180deg, transparent, rgba(103,232,249,0.4), rgba(192,132,252,0.4), transparent)",
        }}
        animate={{ opacity: [0.25, 0.8, 0.25] }}
        transition={{ duration: 5, repeat: Infinity, ease: "easeInOut" }}
      />
    </div>
  );
}

/* Cinematic transition atmosphere layer:
   spans hero + bridge with scroll-linked parallax, grid, particles, streaks, glow. */
function QuantumAtmosphere({ scrollRef }: { scrollRef: React.RefObject<HTMLDivElement | null> }) {
  const { scrollYProgress } = useScroll({
    target: scrollRef,
    offset: ["start start", "end start"],
  });
  const smooth = useSpring(scrollYProgress, { stiffness: 80, damping: 25, mass: 0.5 });

  const yGridSlow = useTransform(smooth, [0, 1], ["0%", "-25%"]);
  const yOrbA = useTransform(smooth, [0, 1], ["0%", "-60%"]);
  const yOrbB = useTransform(smooth, [0, 1], ["0%", "-35%"]);
  const yStreaks = useTransform(smooth, [0, 1], ["-10%", "20%"]);
  const heroDissolve = useTransform(smooth, [0, 0.55, 1], [0, 0.55, 0.95]);
  const shimmerY = useTransform(smooth, [0, 1], ["-10%", "10%"]);

  return (
    <div aria-hidden className="pointer-events-none absolute inset-0 overflow-hidden" style={{ zIndex: 1 }}>
      {/* Animated grid (continues across both sections) */}
      <motion.div
        style={{
          position: "absolute",
          inset: "-10% -5%",
          y: yGridSlow,
          backgroundImage:
            "linear-gradient(rgba(103,232,249,0.07) 1px, transparent 1px), linear-gradient(90deg, rgba(192,132,252,0.06) 1px, transparent 1px)",
          backgroundSize: "60px 60px",
          maskImage:
            "radial-gradient(ellipse 80% 60% at 50% 40%, #000 30%, transparent 80%)",
          WebkitMaskImage:
            "radial-gradient(ellipse 80% 60% at 50% 40%, #000 30%, transparent 80%)",
          opacity: 0.55,
        }}
      />

      {/* Hero dissolve veil — fades hero video into dark quantum space */}
      <motion.div
        style={{
          position: "absolute",
          inset: 0,
          background:
            "linear-gradient(180deg, rgba(0,0,0,0) 0%, rgba(0,0,0,0.2) 35%, rgba(5,2,15,0.8) 70%, #000 100%)",
          opacity: heroDissolve,
        }}
      />

      {/* Soft radial volumetric glow merging the two backgrounds */}
      <motion.div
        style={{
          position: "absolute",
          left: "50%",
          top: "100vh",
          width: 1200,
          height: 1200,
          transform: "translate(-50%, -50%)",
          y: yOrbA,
          background:
            "radial-gradient(circle, rgba(192,132,252,0.22) 0%, rgba(103,232,249,0.12) 35%, transparent 70%)",
          filter: "blur(60px)",
        }}
      />
      <motion.div
        style={{
          position: "absolute",
          right: "-10%",
          top: "60vh",
          width: 700,
          height: 700,
          y: yOrbB,
          background:
            "radial-gradient(circle, rgba(103,232,249,0.18) 0%, transparent 70%)",
          filter: "blur(80px)",
        }}
      />
      <motion.div
        style={{
          position: "absolute",
          left: "-10%",
          top: "130vh",
          width: 800,
          height: 800,
          y: yOrbB,
          background:
            "radial-gradient(circle, rgba(192,132,252,0.16) 0%, transparent 70%)",
          filter: "blur(80px)",
        }}
      />

      {/* Vertical light streaks flowing downward */}
      <motion.div style={{ position: "absolute", inset: 0, y: yStreaks, opacity: 0.6 }}>
        {[12, 28, 44, 62, 78, 91].map((leftPct, i) => (
          <motion.span
            key={i}
            style={{
              position: "absolute",
              left: `${leftPct}%`,
              top: "30vh",
              width: 1,
              height: "120vh",
              background: `linear-gradient(180deg, transparent, ${i % 2 ? "#67e8f9" : "#c084fc"}, transparent)`,
              opacity: 0.35,
              filter: "blur(0.5px)",
            }}
            animate={{ opacity: [0.1, 0.45, 0.1], scaleY: [0.85, 1.1, 0.85] }}
            transition={{ duration: 5 + i, repeat: Infinity, ease: "easeInOut", delay: i * 0.4 }}
          />
        ))}
      </motion.div>

      {/* Continuous drifting particles — span hero -> bridge */}
      <div style={{ position: "absolute", inset: 0 }}>
        {Array.from({ length: 34 }).map((_, i) => {
          const cyan = i % 2 === 0;
          const size = (i % 4 === 0 ? 3 : 2);
          return (
            <motion.span
              key={i}
              style={{
                position: "absolute",
                left: `${(i * 41) % 100}%`,
                top: `${(i * 73) % 200}vh`,
                width: size,
                height: size,
                borderRadius: "50%",
                background: cyan ? "#67e8f9" : "#c084fc",
                boxShadow: `0 0 ${10 + (i % 4) * 4}px ${cyan ? "#67e8f9" : "#c084fc"}`,
              }}
              animate={{
                y: [0, -180 - (i % 5) * 40, 0],
                opacity: [0.15, 0.85, 0.15],
              }}
              transition={{
                duration: 10 + (i % 7),
                repeat: Infinity,
                delay: i * 0.25,
                ease: "easeInOut",
              }}
            />
          );
        })}
      </div>

      {/* Holographic shimmer sweep */}
      <motion.div
        style={{
          position: "absolute",
          inset: "-20% 0",
          y: shimmerY,
          background:
            "linear-gradient(180deg, transparent 30%, rgba(103,232,249,0.06) 48%, rgba(192,132,252,0.06) 52%, transparent 70%)",
          mixBlendMode: "screen",
          filter: "blur(20px)",
        }}
        animate={{ opacity: [0.4, 0.8, 0.4] }}
        transition={{ duration: 6, repeat: Infinity, ease: "easeInOut" }}
      />

      {/* Quantum energy flow — vertical pulse line through the seam */}
      <motion.div
        style={{
          position: "absolute",
          left: "50%",
          top: "85vh",
          width: 2,
          height: "40vh",
          transform: "translateX(-50%)",
          background:
            "linear-gradient(180deg, transparent, rgba(103,232,249,0.7), rgba(192,132,252,0.7), transparent)",
          filter: "blur(1px)",
          boxShadow: "0 0 24px rgba(103,232,249,0.5)",
        }}
        animate={{ opacity: [0.3, 1, 0.3], scaleY: [0.85, 1.15, 0.85] }}
        transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
      />
    </div>
  );
}

export const Route = createFileRoute("/")({
  component: Index,
  head: () => ({
    meta: [
      { title: "VaultShield — Ironclad Password Security" },
      {
        name: "description",
        content:
          "VaultShield keeps you covered with unbreakable storage, one-tap access, and pro-grade tools for your non-stop world.",
      },
    ],
  }),
});

const NAV_LINKS = ["Vault", "Plans", "Install", "News", "Help"];

const Logo = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width="32"
    height="32"
    fill="none"
    overflow="visible"
    viewBox="0 0 256 256"
  >
    <path
      d="M 64 128 L 64.5 128 L 32 95 L 0 64 L 0 0 L 64 0 L 128 64 L 128 64.5 L 161 32 L 192 0 L 256 0 L 256 64 L 192 128 L 128 128 L 128 192 L 96 223 L 63.5 256 L 0 256 L 0 192 Z M 256 192 L 224 223 L 191.5 256 L 128 256 L 128 192 L 192 128 L 256 128 Z"
      fill="#FFFFFF"
    />
  </svg>
);

const fadeUp = {
  hidden: { opacity: 0, y: 28 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.15, duration: 0.6, ease: [0.22, 1, 0.36, 1] as const },
  }),
};

type QuantumMetric = {
  label: string;
  value: number;
  display: (v: number) => string;
  trend: string;
  trendUp?: boolean;
  glow: string;       // hex/rgba for glow
  accent: string;     // primary accent
  accent2: string;    // secondary gradient stop
  spark: number[];    // 0..1 sparkline points
};

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
  }, [active, value]); // eslint-disable-line react-hooks/exhaustive-deps
  return <span>{text}</span>;
}

function Sparkline({ points, color, active }: { points: number[]; color: string; active: boolean }) {
  const W = 220;
  const H = 52;
  const N = points.length;
  const pathRef = useRef<SVGPathElement>(null);
  const areaRef = useRef<SVGPathElement>(null);
  const glowRef = useRef<SVGPathElement>(null);
  const gradId = `spark-fill-${color.replace(/[^a-z0-9]/gi, "")}`;
  const flowId = `spark-flow-${color.replace(/[^a-z0-9]/gi, "")}`;
  const blurId = `spark-blur-${color.replace(/[^a-z0-9]/gi, "")}`;

  useEffect(() => {
    if (!active) return;
    let raf = 0;
    const start = performance.now();
    const seed = points.reduce((a, b) => a + b, 0); // unique per card
    const tick = (now: number) => {
      const t = (now - start) / 1000;
      const animated = points.map((p, i) => {
        const wave =
          Math.sin(t * 1.1 + i * 0.55 + seed) * 0.045 +
          Math.sin(t * 0.65 + i * 0.32 + seed * 1.3) * 0.03 +
          Math.sin(t * 2.3 + i * 0.9) * 0.012;
        return Math.max(0.04, Math.min(0.98, p + wave));
      });
      let max = -Infinity;
      let min = Infinity;
      for (const v of animated) {
        if (v > max) max = v;
        if (v < min) min = v;
      }
      const range = max - min || 1;
      const step = W / (N - 1);
      const coords: Array<[number, number]> = animated.map((p, i) => [
        i * step,
        H - ((p - min) / range) * (H - 10) - 5,
      ]);
      let d = `M${coords[0][0].toFixed(1)},${coords[0][1].toFixed(2)}`;
      for (let i = 1; i < coords.length; i++) {
        const [x0, y0] = coords[i - 1];
        const [x1, y1] = coords[i];
        const cx = (x0 + x1) / 2;
        d += ` C${cx.toFixed(1)},${y0.toFixed(2)} ${cx.toFixed(1)},${y1.toFixed(2)} ${x1.toFixed(1)},${y1.toFixed(2)}`;
      }
      const area = `${d} L${W.toFixed(1)},${H} L0,${H} Z`;
      if (pathRef.current) pathRef.current.setAttribute("d", d);
      if (glowRef.current) glowRef.current.setAttribute("d", d);
      if (areaRef.current) areaRef.current.setAttribute("d", area);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [active, points]);

  return (
    <svg
      width="100%"
      height={H}
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      style={{ display: "block", overflow: "visible" }}
    >
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.42" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
        <linearGradient id={flowId} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor={color} stopOpacity="0.55" />
          <stop offset="45%" stopColor="#ffffff" stopOpacity="1" />
          <stop offset="55%" stopColor="#ffffff" stopOpacity="1" />
          <stop offset="100%" stopColor={color} stopOpacity="0.55" />
          <animate
            attributeName="x1"
            values="-1;0;1"
            dur="3.2s"
            repeatCount="indefinite"
          />
          <animate
            attributeName="x2"
            values="0;1;2"
            dur="3.2s"
            repeatCount="indefinite"
          />
        </linearGradient>
        <filter id={blurId} x="-20%" y="-50%" width="140%" height="200%">
          <feGaussianBlur stdDeviation="3" />
        </filter>
      </defs>

      {/* soft neon bloom under the line */}
      <motion.path
        ref={glowRef}
        d=""
        fill="none"
        stroke={color}
        strokeWidth={3.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        filter={`url(#${blurId})`}
        animate={{ opacity: active ? [0.45, 0.75, 0.45] : 0 }}
        transition={{ duration: 2.6, repeat: Infinity, ease: "easeInOut" }}
      />

      {/* gradient area fill with subtle pulse */}
      <motion.path
        ref={areaRef}
        d=""
        fill={`url(#${gradId})`}
        initial={{ opacity: 0 }}
        animate={{ opacity: active ? [0.7, 1, 0.7] : 0 }}
        transition={{ duration: 3.2, repeat: Infinity, ease: "easeInOut" }}
      />

      {/* main animated line with flowing gradient */}
      <motion.path
        ref={pathRef}
        d=""
        fill="none"
        stroke={`url(#${flowId})`}
        strokeWidth={1.7}
        strokeLinecap="round"
        strokeLinejoin="round"
        initial={{ opacity: 0 }}
        animate={{ opacity: active ? 1 : 0 }}
        transition={{ duration: 0.8 }}
        style={{ filter: `drop-shadow(0 0 4px ${color})` }}
      />
    </svg>
  );
}


function MetricCard({ m, index }: { m: QuantumMetric; index: number }) {
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

const QUANTUM_METRICS: QuantumMetric[] = [
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


function Index() {
  const [menuOpen, setMenuOpen] = useState(false);
  const cinematicRef = useRef<HTMLDivElement | null>(null);

  return (
    <div
      className="relative w-full"
      style={{ fontFamily: "var(--font-body)", color: "#FFFFFF", background: "transparent" }}
    >
      {/* Page-wide cinematic atmosphere — fixed behind all sections */}
      <GlobalAtmosphere />

      {/* All content sits above the global layer */}
      <div className="relative" style={{ zIndex: 1 }}>

      {/* Cinematic continuous scene: hero + quantum bridge share local atmosphere */}
      <div ref={cinematicRef} className="relative w-full">
        <QuantumAtmosphere scrollRef={cinematicRef} />

      {/* HERO BLOCK */}
      <div className="relative w-full min-h-screen overflow-hidden">
      {/* Background video — seamless dual-buffer crossfade loop */}
      <SeamlessVideoLoop
        src="https://res.cloudinary.com/dashtm8a6/video/upload/mp__qqmqfc.mp4"
        crossfade={1.4}
        style={{
          maskImage:
            "linear-gradient(180deg, #000 0%, #000 60%, rgba(0,0,0,0.55) 82%, transparent 100%)",
          WebkitMaskImage:
            "linear-gradient(180deg, #000 0%, #000 60%, rgba(0,0,0,0.55) 82%, transparent 100%)",
        }}
      />

      {/* Hero -> bridge seamless bottom fade */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 bottom-0 h-64"
        style={{
          background:
            "linear-gradient(180deg, transparent 0%, rgba(5,2,15,0.6) 55%, #000 100%)",
        }}
      />


      {/* Navbar */}
      <header className="relative z-10 mx-auto max-w-[1280px] px-5 sm:px-8 py-4 sm:py-5 flex items-center justify-between">
        <a href="/" aria-label="VaultShield home" className="flex items-center">
          <Logo />
        </a>

        <nav className="hidden md:flex items-center gap-8">
          {NAV_LINKS.map((l) => (
            <a
              key={l}
              href={`#${l.toLowerCase()}`}
              className="text-sm font-medium transition-opacity hover:opacity-60"
              style={{ color: "rgba(255,255,255,0.85)" }}
            >
              {l}
            </a>
          ))}
        </nav>

        <div className="hidden md:flex items-center gap-3">
          <a
            href="#start"
            className="relative group overflow-hidden rounded-full px-5 py-2.5 text-sm font-semibold text-white bg-white/[0.08] backdrop-blur-2xl border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.35),inset_0_1px_1px_rgba(255,255,255,0.2)] transition-transform hover:scale-[1.03]"
          >
            <span className="relative z-10">Start For Free</span>
            <div className="absolute inset-0 rounded-full bg-gradient-to-b from-white/40 via-white/10 to-transparent opacity-70" />
            <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition duration-500 bg-[#c084fc]/25" />
          </a>
          <a
            href="#signin"
            className="relative group overflow-hidden rounded-full px-5 py-2.5 text-sm font-semibold text-white bg-white/[0.08] backdrop-blur-2xl border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.35),inset_0_1px_1px_rgba(255,255,255,0.2)] transition-transform hover:scale-[1.03]"
          >
            <span className="relative z-10">Sign In</span>
            <div className="absolute inset-0 rounded-full bg-gradient-to-b from-white/40 via-white/10 to-transparent opacity-70" />
            <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition duration-500 bg-[#c084fc]/25" />
          </a>
        </div>

        <button
          type="button"
          aria-label="Open menu"
          onClick={() => setMenuOpen(true)}
          className="md:hidden p-2"
          style={{ color: "rgba(255,255,255,0.85)" }}
        >
          <Menu size={28} />
        </button>
      </header>

      {/* Hero */}
      <section
        className="relative z-10 mx-auto max-w-[1280px] px-5 sm:px-8"
        style={{ paddingTop: "clamp(40px, 8vw, 72px)" }}
      >
        <div style={{ maxWidth: 560 }}>
          <motion.h1
            initial="hidden"
            animate="visible"
            custom={0}
            variants={fadeUp}
            style={{
              fontFamily: "var(--font-heading)",
              fontSize: "clamp(1.65rem, 5vw, 3rem)",
              lineHeight: 1.05,
              letterSpacing: "-0.01em",
              color: "#FFFFFF",
              marginBottom: 24,
            }}
          >
            <Zap
              size={24}
              color="#67e8f9"
              style={{ display: "inline", verticalAlign: "middle", position: "relative", top: -2, marginRight: 6 }}
            />
            Lock Down Your Passwords{" "}
            <LockKeyhole
              size={24}
              color="#67e8f9"
              style={{ display: "inline", verticalAlign: "middle", position: "relative", top: -2, margin: "0 6px" }}
            />{" "}
            with Ironclad Security
            <Fingerprint
              size={24}
              color="#67e8f9"
              style={{ display: "inline", verticalAlign: "middle", position: "relative", top: -2, marginLeft: 6 }}
            />
          </motion.h1>

          <motion.p
            initial="hidden"
            animate="visible"
            custom={1}
            variants={fadeUp}
            style={{
              fontFamily: "var(--font-body)",
              fontSize: "clamp(0.9rem, 2.5vw, 1.1rem)",
              lineHeight: 1.65,
              color: "rgba(255,255,255,0.75)",
              maxWidth: 560,
              marginBottom: 32,
            }}
          >
            Zero stress, total control. VaultShield keeps you covered with
            unbreakable storage, one-tap access, and pro-grade tools for your
            non-stop world.
          </motion.p>

          <motion.button
            initial="hidden"
            animate="visible"
            custom={2}
            variants={fadeUp}
            whileHover={{ scale: 1.04 }}
            whileTap={{ scale: 0.96 }}
            className="relative group overflow-hidden rounded-full px-7 py-4 text-white font-semibold bg-white/[0.08] backdrop-blur-2xl border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.35),inset_0_1px_1px_rgba(255,255,255,0.2)] inline-flex items-center justify-between"
            style={{
              fontFamily: "var(--font-body)",
              fontSize: "clamp(0.9rem, 2vw, 1rem)",
              minWidth: 210,
              gap: 32,
            }}
          >
            <span className="relative z-10 flex items-center gap-2">Get It Free</span>
            <ArrowRightCircle size={20} className="relative z-10" />
            <div className="absolute inset-0 rounded-full bg-gradient-to-b from-white/40 via-white/10 to-transparent opacity-70" />
            <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition duration-500 bg-[#c084fc]/25" />
          </motion.button>
        </div>
      </section>
      </div>
      {/* END HERO BLOCK */}

      {/* Quantum Bridge Proxy Engine — continuation section */}
      <section className="relative z-10 mx-auto max-w-[1280px] px-5 sm:px-8 pt-24 sm:pt-32 pb-32">
        {/* Blend bridge from hero */}
        <div
          aria-hidden
          className="pointer-events-none absolute -top-40 left-0 right-0 h-64"
          style={{
            background:
              "linear-gradient(180deg, rgba(0,0,0,0) 0%, rgba(192,132,252,0.06) 40%, rgba(103,232,249,0.04) 70%, rgba(0,0,0,0) 100%)",
            filter: "blur(40px)",
          }}
        />
        {/* Ambient particles */}
        <div aria-hidden className="pointer-events-none absolute inset-0 overflow-hidden">
          {Array.from({ length: 18 }).map((_, i) => (
            <motion.span
              key={i}
              className="absolute rounded-full"
              style={{
                left: `${(i * 53) % 100}%`,
                top: `${(i * 37) % 100}%`,
                width: i % 3 === 0 ? 3 : 2,
                height: i % 3 === 0 ? 3 : 2,
                background: i % 2 === 0 ? "#c084fc" : "#67e8f9",
                boxShadow: `0 0 12px ${i % 2 === 0 ? "#c084fc" : "#67e8f9"}`,
                opacity: 0.5,
              }}
              animate={{ y: [0, -30, 0], opacity: [0.2, 0.8, 0.2] }}
              transition={{ duration: 6 + (i % 5), repeat: Infinity, delay: i * 0.3, ease: "easeInOut" }}
            />
          ))}
        </div>

        <motion.div
          initial={{ opacity: 0, y: 40 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-100px" }}
          transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          className="relative grid lg:grid-cols-2 gap-12 items-center"
        >
          {/* Left: copy */}
          <div>
            <motion.span
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ delay: 0.1, duration: 0.6 }}
              className="inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium tracking-wider uppercase"
              style={{
                borderColor: "rgba(103,232,249,0.35)",
                color: "#67e8f9",
                background: "rgba(103,232,249,0.06)",
              }}
            >
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: "#67e8f9", boxShadow: "0 0 10px #67e8f9" }} />
              Quantum Bridge · Live
            </motion.span>

            <h2
              style={{
                fontFamily: "var(--font-heading)",
                fontSize: "clamp(1.8rem, 4.5vw, 3rem)",
                lineHeight: 1.05,
                letterSpacing: "-0.01em",
                color: "#FFFFFF",
                marginTop: 20,
                marginBottom: 20,
              }}
            >
              Proxy Engine bridging{" "}
              <span style={{ color: "#67e8f9" }}>classical</span> and{" "}
              <span style={{ color: "#c084fc" }}>post-quantum</span> crypto.
            </h2>
            <p
              style={{
                color: "rgba(255,255,255,0.75)",
                fontSize: "clamp(0.95rem, 1.6vw, 1.05rem)",
                lineHeight: 1.7,
                maxWidth: 520,
              }}
            >
              Every request is dual-signed with ECDSA P-256 and ML-DSA-65 (NIST FIPS 204).
              Verified at the edge, forwarded in under 50ms — quantum-safe, today.
            </p>

            <div
              className="mt-8 grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-xl"
              style={{ perspective: 1200 }}
            >
              {QUANTUM_METRICS.map((m, i) => (
                <MetricCard key={m.label} m={m} index={i} />
              ))}
            </div>
          </div>

          {/* Left: 3D Card (bent to the left) */}
          <div className="flex justify-center lg:justify-start lg:order-first" style={{ perspective: 1200 }}>
            <motion.div
              initial={{ rotateX: 0, rotateY: 0 }}
              whileHover={{ rotateX: -10, rotateY: 18 }}
              transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
              style={{
                width: 340,
                height: 480,
                borderRadius: 40,
                transformStyle: "preserve-3d",
                background:
                  "linear-gradient(135deg, rgba(76,29,149,0.85) 0%, rgba(15,15,30,0.95) 100%)",
                boxShadow:
                  "0 40px 80px -20px rgba(192,132,252,0.25), 0 0 60px rgba(103,232,249,0.08), inset 0 1px 1px rgba(255,255,255,0.08)",
                position: "relative",
              }}
            >
              {/* Glass overlay */}
              <div
                style={{
                  position: "absolute",
                  inset: 10,
                  borderRadius: 45,
                  borderTopLeftRadius: "100%",
                  background:
                    "linear-gradient(0deg, rgba(103,232,249,0.05) 0%, rgba(192,132,252,0.18) 100%)",
                  borderRight: "1px solid rgba(255,255,255,0.12)",
                  borderBottom: "1px solid rgba(255,255,255,0.12)",
                  transform: "translate3d(0,0,30px)",
                  transformStyle: "preserve-3d",
                }}
              />

              {/* Logo orbs */}
              <div style={{ position: "absolute", left: 0, top: 0, transformStyle: "preserve-3d" }}>
                {[
                  { size: 160, z: 25, top: 10, left: 10, op: 0.18 },
                  { size: 130, z: 45, top: 12, left: 12, op: 0.22 },
                  { size: 100, z: 65, top: 15, left: 15, op: 0.28 },
                  { size: 70, z: 85, top: 20, left: 20, op: 0.4 },
                ].map((c, i) => (
                  <span
                    key={i}
                    style={{
                      position: "absolute",
                      display: "block",
                      width: c.size,
                      height: c.size,
                      borderRadius: "50%",
                      top: c.top,
                      left: c.left,
                      transform: `translate3d(0,0,${c.z}px)`,
                      background: `radial-gradient(circle at 30% 30%, rgba(192,132,252,${c.op}), rgba(103,232,249,${c.op * 0.5}))`,
                      boxShadow: "0 10px 30px rgba(0,0,0,0.4)",
                    }}
                  />
                ))}
                <span
                  style={{
                    position: "absolute",
                    width: 40,
                    height: 40,
                    borderRadius: "50%",
                    top: 25,
                    left: 25,
                    transform: "translate3d(0,0,105px)",
                    background: "linear-gradient(135deg, #c084fc, #67e8f9)",
                    display: "grid",
                    placeContent: "center",
                    boxShadow: "0 0 30px rgba(192,132,252,0.6)",
                  }}
                >
                  <LockKeyhole size={18} color="#fff" />
                </span>
              </div>

              {/* Content */}
              <div style={{ padding: "90px 25px 0 25px", transform: "translate3d(0,0,31px)" }}>
                <div className="flex items-center gap-3 mb-4">
                  <div className="flex-1">
                    <div style={{ color: "#67e8f9", fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 4 }}>
                      Classical Layer
                    </div>
                    <div style={{ color: "#fff", fontWeight: 700, fontSize: 14 }}>ECDSA P-256</div>
                    <div style={{ color: "rgba(255,255,255,0.6)", fontSize: 11 }}>Current standard · Fast</div>
                  </div>
                  <div style={{ width: 1, height: 50, background: "linear-gradient(180deg, transparent, rgba(192,132,252,0.5), transparent)" }} />
                  <div className="flex-1">
                    <div style={{ color: "#c084fc", fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 4 }}>
                      Quantum Layer
                    </div>
                    <div style={{ color: "#fff", fontWeight: 700, fontSize: 14 }}>ML-DSA-65</div>
                    <div style={{ color: "rgba(255,255,255,0.6)", fontSize: 11 }}>NIST FIPS 204 · Lattice</div>
                  </div>
                </div>

                <div
                  className="flex items-center gap-2 rounded-lg px-3 py-2.5"
                  style={{
                    background: "rgba(103,232,249,0.08)",
                    border: "1px solid rgba(103,232,249,0.3)",
                  }}
                >
                  <span style={{ color: "#67e8f9", fontWeight: 700 }}>✓</span>
                  <span style={{ color: "#67e8f9", fontWeight: 600, fontSize: 11, flex: 1 }}>
                    Dual Signature Verified
                  </span>
                  <span style={{ color: "rgba(103,232,249,0.5)", fontSize: 9 }}>a3f9c2b1</span>
                </div>
              </div>

              {/* Metrics */}
              <div style={{ display: "flex", gap: 8, padding: "16px 25px", transform: "translate3d(0,0,31px)" }}>
                {[
                  { v: "8,688", l: "Requests" },
                  { v: "49ms", l: "Latency" },
                  { v: "99.99%", l: "Success" },
                ].map((m) => (
                  <div
                    key={m.l}
                    style={{
                      flex: 1,
                      background: "rgba(255,255,255,0.05)",
                      borderRadius: 10,
                      padding: "10px 6px",
                      textAlign: "center",
                      border: "1px solid rgba(255,255,255,0.06)",
                    }}
                  >
                    <div style={{ color: "#fff", fontWeight: 800, fontSize: 14 }}>{m.v}</div>
                    <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 9, marginTop: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                      {m.l}
                    </div>
                  </div>
                ))}
              </div>

              {/* Bottom CTA */}
              <div
                style={{
                  position: "absolute",
                  bottom: 20,
                  left: 25,
                  right: 25,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  transform: "translate3d(0,0,31px)",
                }}
              >
                <button
                  className="rounded-full px-4 py-2 text-xs font-semibold"
                  style={{
                    background: "linear-gradient(135deg, #c084fc, #67e8f9)",
                    color: "#0a0a0a",
                  }}
                >
                  Explore →
                </button>
                <div style={{ color: "rgba(255,255,255,0.5)", fontSize: 10, letterSpacing: "0.08em" }}>
                  v2.4 · STABLE
                </div>
              </div>
            </motion.div>
          </div>
        </motion.div>
      </section>
      </div>
      {/* END cinematic scene */}



      {/* Metrics Header — transparent, blends into global atmosphere */}
      <section
        className="relative w-full overflow-hidden"
        style={{ background: "transparent" }}
      >
        <div
          aria-hidden
          className="absolute inset-0 pointer-events-none"
          style={{
            background:
              "radial-gradient(900px 320px at 20% 120%, rgba(0,212,255,0.08), transparent 60%), radial-gradient(800px 320px at 80% 120%, rgba(192,132,252,0.08), transparent 60%), radial-gradient(600px 220px at 50% 140%, rgba(245,158,11,0.06), transparent 65%)",
          }}
        />
        <div className="relative mx-auto max-w-[1280px] px-5 sm:px-8 pt-12 sm:pt-16 pb-6 sm:pb-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6 sm:gap-10">
            {[
              { v: "0ms", l: "Legacy Code Changes" },
              { v: "2x", l: "Signature Algorithms" },
              { v: "90d", l: "Auto Key Rotation" },
              { v: "$0", l: "To Start" },
            ].map((m, i) => (
              <motion.div
                key={m.l}
                initial={{ opacity: 0, y: 24 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.08, duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
                className="text-center"
              >
                <div
                  style={{
                    fontFamily: "var(--font-heading)",
                    color: "#00d4ff",
                    fontSize: "clamp(2rem, 5vw, 3.25rem)",
                    fontWeight: 800,
                    lineHeight: 1,
                    textShadow: "0 0 24px rgba(0,212,255,0.35)",
                  }}
                >
                  {m.v}
                </div>
                <div
                  style={{
                    color: "rgba(255,255,255,0.55)",
                    fontSize: 11,
                    marginTop: 10,
                    letterSpacing: "0.14em",
                    textTransform: "uppercase",
                    fontWeight: 600,
                  }}
                >
                  {m.l}
                </div>
              </motion.div>
            ))}
          </div>

          <div className="relative mt-10">
            <motion.div
              aria-hidden
              className="h-px w-full"
              style={{
                background:
                  "linear-gradient(90deg, transparent, rgba(0,212,255,0.6), rgba(192,132,252,0.6), rgba(245,158,11,0.5), transparent)",
                boxShadow:
                  "0 0 18px rgba(0,212,255,0.35), 0 0 36px rgba(192,132,252,0.25)",
              }}
              animate={{ opacity: [0.55, 1, 0.55] }}
              transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
            />
          </div>
        </div>
      </section>

      {/* Soft bridge: Stats → RotaryTimeline */}
      <SectionBridge height={140} from="rgba(0,212,255,0.10)" to="rgba(192,132,252,0.10)" />

      <RotaryTimeline />

      {/* Soft bridge: RotaryTimeline → DefenseConsole */}
      <SectionBridge height={120} from="rgba(245,158,11,0.08)" to="rgba(124,255,178,0.10)" />

      <QuantumDefenseConsole />

      {/* Soft bridge: DefenseConsole → Pricing */}
      <SectionBridge height={120} from="rgba(124,255,178,0.08)" to="rgba(192,132,252,0.10)" />

      <QuantumPricing />




      {/* Mobile menu */}
      <AnimatePresence>
        {menuOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3 }}
              onClick={() => setMenuOpen(false)}
              className="fixed inset-0 z-40"
              style={{
                background: "rgba(0,0,0,0.55)",
                backdropFilter: "blur(4px)",
                WebkitBackdropFilter: "blur(4px)",
              }}
            />
            <motion.aside
              initial={{ x: "100%" }}
              animate={{ x: 0 }}
              exit={{ x: "100%" }}
              transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
              className="fixed right-0 top-0 z-50 flex flex-col"
              style={{
                width: "min(88vw, 360px)",
                height: "100dvh",
                background: "#0a0a0a",
                boxShadow: "-12px 0 48px rgba(25,40,55,0.18)",
              }}
            >
              <div className="flex items-center justify-between px-6 py-5">
                <Logo />
                <button
                  aria-label="Close menu"
                  onClick={() => setMenuOpen(false)}
                  style={{ color: "#FFFFFF" }}
                >
                  <X size={26} />
                </button>
              </div>
              <div style={{ height: 1, background: "rgba(255,255,255,0.15)" }} />

              <nav className="flex flex-col gap-5 px-6 py-8">
                {NAV_LINKS.map((l, i) => (
                  <motion.a
                    key={l}
                    href={`#${l.toLowerCase()}`}
                    onClick={() => setMenuOpen(false)}
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.18 + i * 0.07, duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
                    className="text-lg font-semibold"
                    style={{ color: "#FFFFFF" }}
                  >
                    {l}
                  </motion.a>
                ))}
              </nav>

              <div className="mt-auto flex flex-col gap-3 px-6 pb-8">
                <a
                  href="#start"
                  className="relative group overflow-hidden rounded-full px-5 py-3 text-sm font-semibold text-white text-center bg-white/[0.08] backdrop-blur-2xl border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.35),inset_0_1px_1px_rgba(255,255,255,0.2)]"
                >
                  <span className="relative z-10">Start For Free</span>
                  <div className="absolute inset-0 rounded-full bg-gradient-to-b from-white/40 via-white/10 to-transparent opacity-70" />
                  <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition duration-500 bg-[#c084fc]/25" />
                </a>
                <a
                  href="#signin"
                  className="relative group overflow-hidden rounded-full px-5 py-3 text-sm font-semibold text-white text-center bg-white/[0.08] backdrop-blur-2xl border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.35),inset_0_1px_1px_rgba(255,255,255,0.2)]"
                >
                  <span className="relative z-10">Sign In</span>
                  <div className="absolute inset-0 rounded-full bg-gradient-to-b from-white/40 via-white/10 to-transparent opacity-70" />
                  <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition duration-500 bg-[#c084fc]/25" />
                </a>
              </div>
            </motion.aside>
          </>
        )}
      </AnimatePresence>
      </div>
      {/* end zIndex content wrapper */}
    </div>
  );
}
