import { motion, useScroll, useTransform, useSpring } from 'framer-motion';

/**
 * QuantumAtmosphere Component
 * 
 * Scroll-linked parallax atmosphere layer for hero section and bridge transition.
 * 
 * Features:
 * - Scroll-linked parallax effects using useScroll with target ref
 * - Animated grid with vertical movement
 * - Three volumetric glow orbs
 * - Vertical light streaks (6 streaks)
 * - Continuous drifting particles (34 particles)
 * - Hero dissolve veil (fades video into dark space)
 * - Quantum energy flow pulse line
 * 
 * Scroll Configuration:
 * - Uses useScroll with target ref and offset ["start start", "end start"]
 * - Applies useSpring for smooth interpolation (stiffness: 80, damping: 25, mass: 0.5)
 * 
 * Transform Mappings:
 * - Grid: 0% → -25% vertical movement
 * - Orb A: 0% → -60% vertical movement
 * - Orb B: 0% → -35% vertical movement
 * - Streaks: -10% → 20% vertical movement
 * - Hero dissolve: 0 → 0.95 opacity (fades video out)
 */

interface QuantumAtmosphereProps {
  scrollRef: React.RefObject<HTMLDivElement | null>;
}

export default function QuantumAtmosphere({ scrollRef }: QuantumAtmosphereProps): React.JSX.Element {
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
