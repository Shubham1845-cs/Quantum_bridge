import { useEffect, useState } from "react";
import { motion, useScroll, useSpring, useTransform } from "framer-motion";

/**
 * Page-wide cinematic atmosphere.
 * Rendered once at the root of the landing page as a fixed, full-viewport
 * layer behind all content. Creates the feeling of one continuous quantum
 * environment as the user scrolls through every section.
 */
export default function GlobalAtmosphere() {
  const { scrollYProgress } = useScroll();
  const smooth = useSpring(scrollYProgress, { stiffness: 60, damping: 22, mass: 0.6 });

  // Global hue shift as the user descends deeper into the "system"
  const hueA = useTransform(smooth, [0, 0.5, 1], [
    "rgba(103,232,249,0.18)",
    "rgba(192,132,252,0.20)",
    "rgba(124,255,178,0.18)",
  ]);
  const hueB = useTransform(smooth, [0, 0.5, 1], [
    "rgba(192,132,252,0.14)",
    "rgba(245,158,11,0.14)",
    "rgba(103,232,249,0.16)",
  ]);

  const orbAY = useTransform(smooth, [0, 1], ["-15%", "25%"]);
  const orbBY = useTransform(smooth, [0, 1], ["20%", "-25%"]);
  const orbCY = useTransform(smooth, [0, 1], ["-25%", "30%"]);
  const gridY = useTransform(smooth, [0, 1], ["0%", "-12%"]);
  const streakY = useTransform(smooth, [0, 1], ["-5%", "10%"]);

  const orbABg = useTransform(
    hueA,
    (c) => `radial-gradient(circle, ${c} 0%, transparent 65%)`
  );
  const orbBBg = useTransform(
    hueB,
    (c) => `radial-gradient(circle, ${c} 0%, transparent 65%)`
  );

  // viewport height to scatter particles deterministically
  const [vh, setVh] = useState(800);
  useEffect(() => {
    const update = () => setVh(window.innerHeight);
    update();
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, []);

  return (
    <div
      aria-hidden
      className="pointer-events-none fixed inset-0"
      style={{ zIndex: 0, overflow: "hidden" }}
    >
      {/* Deep base — never pure black, always tinted to feel "alive" */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          background:
            "radial-gradient(ellipse 100% 70% at 50% 0%, #0a0818 0%, #050410 40%, #020207 100%)",
        }}
      />

      {/* Slow, large drifting grid — same pattern across the whole page */}
      <motion.div
        style={{
          position: "absolute",
          inset: "-10% -5%",
          y: gridY,
          backgroundImage:
            "linear-gradient(rgba(103,232,249,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(192,132,252,0.05) 1px, transparent 1px)",
          backgroundSize: "80px 80px",
          maskImage:
            "radial-gradient(ellipse 90% 70% at 50% 50%, #000 30%, transparent 85%)",
          WebkitMaskImage:
            "radial-gradient(ellipse 90% 70% at 50% 50%, #000 30%, transparent 85%)",
          opacity: 0.55,
        }}
      />

      {/* Three massive ambient orbs that follow scroll — color-shifts with depth */}
      <motion.div
        style={{
          position: "absolute",
          left: "10%",
          top: "10%",
          width: 900,
          height: 900,
          y: orbAY,
          background: orbABg,
          filter: "blur(80px)",
        }}
      />
      <motion.div
        style={{
          position: "absolute",
          right: "-10%",
          top: "30%",
          width: 1100,
          height: 1100,
          y: orbBY,
          background: orbBBg,
          filter: "blur(100px)",
        }}
      />
      <motion.div
        style={{
          position: "absolute",
          left: "-15%",
          top: "60%",
          width: 1000,
          height: 1000,
          y: orbCY,
          background:
            "radial-gradient(circle, rgba(103,232,249,0.14) 0%, transparent 65%)",
          filter: "blur(90px)",
        }}
      />

      {/* Vertical light streaks — quantum energy spine, drifts with scroll */}
      <motion.div style={{ position: "absolute", inset: 0, y: streakY, opacity: 0.55 }}>
        {[8, 22, 38, 52, 68, 82, 94].map((leftPct, i) => (
          <motion.span
            key={i}
            style={{
              position: "absolute",
              left: `${leftPct}%`,
              top: 0,
              width: 1,
              height: "100%",
              background: `linear-gradient(180deg, transparent, ${i % 2 ? "#67e8f9" : "#c084fc"}, transparent)`,
              opacity: 0.3,
              filter: "blur(0.5px)",
            }}
            animate={{ opacity: [0.08, 0.4, 0.08], scaleY: [0.9, 1.1, 0.9] }}
            transition={{ duration: 6 + i, repeat: Infinity, ease: "easeInOut", delay: i * 0.5 }}
          />
        ))}
      </motion.div>

      {/* Continuous floating particles — viewport-bound, always visible */}
      <div style={{ position: "absolute", inset: 0 }}>
        {Array.from({ length: 28 }).map((_, i) => {
          const cyan = i % 3 === 0;
          const purple = i % 3 === 1;
          const color = cyan ? "#67e8f9" : purple ? "#c084fc" : "#7cffb2";
          const size = (i % 4 === 0 ? 3 : 2);
          return (
            <motion.span
              key={i}
              style={{
                position: "absolute",
                left: `${(i * 37) % 100}%`,
                top: `${(i * 53) % 100}%`,
                width: size,
                height: size,
                borderRadius: "50%",
                background: color,
                boxShadow: `0 0 ${10 + (i % 4) * 4}px ${color}`,
              }}
              animate={{
                y: [0, -(60 + (i % 5) * 30), 0],
                opacity: [0.1, 0.7, 0.1],
              }}
              transition={{
                duration: 8 + (i % 7),
                repeat: Infinity,
                delay: i * 0.3,
                ease: "easeInOut",
              }}
            />
          );
        })}
      </div>

      {/* Holographic shimmer sweep — slow, breathing */}
      <motion.div
        style={{
          position: "absolute",
          inset: "-20% 0",
          background:
            "linear-gradient(180deg, transparent 30%, rgba(103,232,249,0.05) 48%, rgba(192,132,252,0.05) 52%, transparent 70%)",
          mixBlendMode: "screen",
          filter: "blur(24px)",
        }}
        animate={{ opacity: [0.3, 0.7, 0.3], y: ["-5%", "5%", "-5%"] }}
        transition={{ duration: 10, repeat: Infinity, ease: "easeInOut" }}
      />

      {/* Soft top + bottom vignette to keep content readable but not boxed */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          background:
            "linear-gradient(180deg, rgba(0,0,0,0.35) 0%, transparent 12%, transparent 88%, rgba(0,0,0,0.35) 100%)",
        }}
      />

      {/* Faint scanlines for "live system" feel */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          backgroundImage:
            "repeating-linear-gradient(0deg, rgba(255,255,255,0.012) 0px, rgba(255,255,255,0.012) 1px, transparent 1px, transparent 3px)",
          opacity: 0.6,
          mixBlendMode: "overlay",
        }}
      />
    </div>
  );
}
