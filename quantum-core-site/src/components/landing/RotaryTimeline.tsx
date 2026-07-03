import { useEffect, useMemo, useRef, useState } from "react";
import {
  motion,
  AnimatePresence,
  useMotionValue,
  useTransform,
  useMotionValueEvent,
  animate,
  type PanInfo,
} from "framer-motion";
import { Link2, Key, Shield, BarChart3 } from "lucide-react";

type TimelineItem = {
  year: string;
  eyebrow: string;
  title: string;
  desc: string;
  Icon: React.ComponentType<{ className?: string }>;
};

const timelineData: TimelineItem[] = [
  {
    year: "01",
    eyebrow: "How It Works",
    title: "Register your API",
    desc: "Point QuantumBridge at your existing legacy API URL. We validate it's reachable over HTTPS. No code changes on your side.",
    Icon: Link2,
  },
  {
    year: "02",
    eyebrow: "How It Works",
    title: "Get your proxy URL",
    desc: "Receive a unique proxy URL and API key. Your PQC keypair (ECDSA + ML-DSA-65) is auto-generated and encrypted with AES-256-GCM.",
    Icon: Key,
  },
  {
    year: "03",
    eyebrow: "How It Works",
    title: "Route traffic through",
    desc: "All requests flow through QuantumBridge. Every response is dual-signed. Clients can verify both signatures independently.",
    Icon: Shield,
  },
  {
    year: "04",
    eyebrow: "How It Works",
    title: "Monitor on dashboard",
    desc: "Real-time logs, signature verification rates, threat detection, and auto key rotation every 90 days. Full audit trail.",
    Icon: BarChart3,
  },
];

const RADIUS = 180;
const STEP = 22; // degrees between items
const TICK_COUNT = 72;
const TICK_RADIUS = 400;

export default function RotaryTimeline() {
  const [activeIndex, setActiveIndex] = useState(0);
  const [isPaused, setIsPaused] = useState(false);
  const [scrollActive, setScrollActive] = useState(false);
  const rotation = useMotionValue(-0 * STEP);
  const containerRef = useRef<HTMLDivElement>(null);
  const wheelLockRef = useRef(0);
  const activeIndexRef = useRef(0);
  const scrollActiveRef = useRef(false);
  activeIndexRef.current = activeIndex;
  scrollActiveRef.current = scrollActive;

  const snapTo = (index: number) => {
    const clamped = Math.max(0, Math.min(timelineData.length - 1, index));
    setActiveIndex(clamped);
    animate(rotation, -clamped * STEP, {
      type: "spring",
      stiffness: 120,
      damping: 18,
      mass: 0.8,
    });
  };

  useMotionValueEvent(rotation, "change", (latest) => {
    const idx = Math.round(-latest / STEP);
    const clamped = Math.max(0, Math.min(timelineData.length - 1, idx));
    if (clamped !== activeIndex) setActiveIndex(clamped);
  });

  const handleDragEnd = (_: unknown, info: PanInfo) => {
    const projected = rotation.get() + info.velocity.y * 0.05;
    const nearest = Math.round(-projected / STEP);
    snapTo(nearest);
  };

  // Mouse wheel scroll → change timeline (only after click-activated)
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      if (!scrollActiveRef.current) return; // let page scroll normally
      e.preventDefault();
      const now = Date.now();
      if (now - wheelLockRef.current < 320) return;
      if (Math.abs(e.deltaY) < 4) return;
      wheelLockRef.current = now;
      setIsPaused(true);
      const dir = e.deltaY > 0 ? 1 : -1;
      snapTo(activeIndexRef.current + dir);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  // Deactivate scroll-mode when clicking outside the wheel area
  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      const el = containerRef.current;
      if (!el) return;
      if (!el.contains(e.target as Node)) setScrollActive(false);
    };
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, []);

  // Auto-advance every 3s, looping
  useEffect(() => {
    if (isPaused) return;
    const id = setInterval(() => {
      const next = (activeIndexRef.current + 1) % timelineData.length;
      snapTo(next);
    }, 3000);
    return () => clearInterval(id);
  }, [isPaused]);

  const active = timelineData[activeIndex];

  return (
    <div
      ref={containerRef}
      className="relative min-h-screen w-full overflow-hidden bg-[#0a0a0a] text-white font-sans"
    >
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute right-[-10%] top-1/2 h-[900px] w-[900px] -translate-y-1/2 rounded-full bg-amber-500/[0.06] blur-3xl" />
      </div>

      <div className="relative mx-auto flex min-h-screen max-w-7xl items-center px-10">
        {/* Left content panel */}
        <div className="z-10 w-full max-w-lg">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeIndex}
              initial={{ opacity: 0, y: 16, filter: "blur(8px)" }}
              animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
              exit={{ opacity: 0, y: -16, filter: "blur(8px)" }}
              transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
            >
              <div className="mb-10 inline-flex items-center gap-2.5 rounded-full bg-amber-500/10 px-3 py-1.5 ring-1 ring-amber-500/30">
                <span className="flex h-4 w-4 items-center justify-center rounded-full bg-amber-500">
                  <active.Icon className="h-2.5 w-2.5 text-black" />
                </span>
                <span className="font-mono text-xs font-medium text-amber-400">
                  {active.year}
                </span>
              </div>

              <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.2em] text-amber-500/90">
                {active.eyebrow}
              </div>
              <h1 className="mb-5 text-5xl font-semibold tracking-tight text-white">
                {active.title}
              </h1>
              <p className="max-w-md text-[15px] leading-relaxed text-white/55">
                {active.desc}
              </p>
            </motion.div>
          </AnimatePresence>

          <div className="mt-12 font-mono text-xs tracking-widest text-white/35">
            {String(activeIndex + 1).padStart(2, "0")} / {String(timelineData.length).padStart(2, "0")}
          </div>
        </div>

        {/* Right rotary wheel */}
        <div
          onMouseDown={() => setScrollActive(true)}
          className="absolute left-1/2 top-1/2 h-[600px] w-[600px] -translate-x-1/2 -translate-y-1/2 select-none transition-shadow"
          style={{ marginLeft: 260 }}
        >
          <WheelDial
            activeIndex={activeIndex}
            rotation={rotation}
            onSnap={snapTo}
            onDragEnd={handleDragEnd}
          />
        </div>
      </div>
    </div>
  );
}

function WheelDial({
  activeIndex,
  rotation,
  onSnap,
  onDragEnd,
}: {
  activeIndex: number;
  rotation: ReturnType<typeof useMotionValue<number>>;
  onSnap: (i: number) => void;
  onDragEnd: (e: unknown, info: PanInfo) => void;
}) {
  const ticks = useMemo(() => Array.from({ length: TICK_COUNT }), []);

  return (
    <motion.div
      className="absolute inset-0 cursor-grab active:cursor-grabbing"
      drag="y"
      dragConstraints={{ top: 0, bottom: 0 }}
      dragElastic={0.15}
      onDrag={(_, info) => {
        rotation.set(rotation.get() + info.delta.y * 0.22);
      }}
      onDragEnd={onDragEnd}
    >
      {/* Tick ring */}
      <div className="absolute inset-0">
        {ticks.map((_, i) => {
          const tickAngle = (i / TICK_COUNT) * 360;
          return <Tick key={i} tickAngle={tickAngle} rotation={rotation} />;
        })}
      </div>

      {/* Timeline pills */}
      <div className="absolute inset-0">
        {timelineData.map((item, index) => (
          <Pill
            key={item.year}
            item={item}
            index={index}
            activeIndex={activeIndex}
            rotation={rotation}
            onClick={() => onSnap(index)}
          />
        ))}
      </div>
    </motion.div>
  );
}

function Pill({
  item,
  index,
  activeIndex,
  rotation,
  onClick,
}: {
  item: TimelineItem;
  index: number;
  activeIndex: number;
  rotation: ReturnType<typeof useMotionValue<number>>;
  onClick: () => void;
}) {
  const baseAngle = index * STEP;
  const angle = useTransform(rotation, (r) => baseAngle + r);

  // Apex at LEFT side of wheel container -> x = -cos*R, y = sin*R
  const x = useTransform(angle, (a) => -Math.cos((a * Math.PI) / 180) * RADIUS);
  const y = useTransform(angle, (a) => Math.sin((a * Math.PI) / 180) * RADIUS);

  const opacity = useTransform(angle, (a) => {
    const dist = Math.abs(a);
    return Math.max(0.18, 1 - dist / 70);
  });
  const scale = useTransform(angle, (a) => {
    const dist = Math.abs(a);
    return Math.max(0.72, 1 - dist / 260);
  });

  const isActive = index === activeIndex;
  const Icon = item.Icon;

  return (
    <motion.button
      onClick={onClick}
      style={{ x, y, opacity, scale }}
      className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2"
    >
      <motion.div
        animate={{
          backgroundColor: isActive ? "rgba(255,255,255,0.06)" : "rgba(255,255,255,0)",
          borderColor: isActive ? "rgba(255,255,255,0.15)" : "rgba(255,255,255,0.05)",
        }}
        transition={{ duration: 0.3 }}
        className="flex items-center gap-3 whitespace-nowrap rounded-full border px-3 py-2.5 pr-5 backdrop-blur-md"
      >
        <motion.div
          animate={{
            backgroundColor: isActive ? "rgb(245, 158, 11)" : "rgba(255,255,255,0.06)",
            boxShadow: isActive
              ? "0 0 28px rgba(245,158,11,0.55)"
              : "0 0 0 rgba(0,0,0,0)",
          }}
          transition={{ duration: 0.3 }}
          className="flex h-9 w-9 items-center justify-center rounded-full"
        >
          <Icon
            className={`h-4 w-4 ${isActive ? "text-black" : "text-white/70"}`}
          />
        </motion.div>
        <div className="flex flex-col text-left leading-tight">
          <span
            className={`font-mono text-[10px] tracking-wider ${
              isActive ? "text-amber-400" : "text-white/40"
            }`}
          >
            {item.year}
          </span>
          <span
            className={`text-sm ${
              isActive ? "font-medium text-white" : "text-white/65"
            }`}
          >
            {item.title}
          </span>
        </div>
      </motion.div>
    </motion.button>
  );
}

function Tick({
  tickAngle,
  rotation,
}: {
  tickAngle: number;
  rotation: ReturnType<typeof useMotionValue<number>>;
}) {
  const effectiveAngle = useTransform(rotation, (r) => {
    const a = (((tickAngle + r) % 360) + 540) % 360 - 180;
    return a;
  });

  const x = useTransform(effectiveAngle, (a) => Math.cos((a * Math.PI) / 180) * TICK_RADIUS);
  const y = useTransform(effectiveAngle, (a) => Math.sin((a * Math.PI) / 180) * TICK_RADIUS);
  const rotate = useTransform(effectiveAngle, (a) => a + 90);

  // Distance to nearest horizontal apex (0° = right, 180° = left)
  const apexDist = useTransform(effectiveAngle, (a) => {
    const ab = Math.abs(a);
    return Math.min(ab, 180 - ab);
  });
  // Distance to LEFT apex only (where pills live) — drives the amber accent
  const leftDist = useTransform(effectiveAngle, (a) => Math.abs(180 - Math.abs(a)));

  const scaleY = useTransform(apexDist, (d) => {
    if (d > 55) return 0.6;
    return 1.8 - d / 60;
  });
  const opacity = useTransform(apexDist, (d) => {
    if (d > 55) return 0;
    return Math.max(0.15, 1 - d / 70);
  });
  const bg = useTransform(leftDist, (d) => {
    if (d < 8) return "rgb(245, 158, 11)";
    if (d < 22) return "rgba(245, 158, 11, 0.7)";
    if (d < 45) return "rgba(255,255,255,0.55)";
    return "rgba(255,255,255,0.3)";
  });

  return (
    <motion.div
      style={{ x, y, rotate, opacity }}
      className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2"
    >
      <motion.div
        style={{ scaleY, backgroundColor: bg }}
        className="h-4 w-[2px] origin-center rounded-full"
      />
    </motion.div>
  );
}
