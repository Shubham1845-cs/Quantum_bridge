import { motion } from 'framer-motion';

/**
 * SectionBridge Component
 * 
 * Soft atmospheric overlap rendered between sections.
 * Eliminates hard breaks by blending colored glow + light streaks across
 * the seam between two components, so the page reads as one continuous scene.
 * 
 * Features:
 * - Radial gradient glow blending two colors
 * - Vertical light streak with pulsing animation
 * - Configurable height and colors
 */

interface SectionBridgeProps {
  height?: number;      // Height in pixels (default: 160)
  from?: string;        // Top gradient color (rgba)
  to?: string;          // Bottom gradient color (rgba)
}

export default function SectionBridge({ 
  height = 160, 
  from = "rgba(103,232,249,0.10)", 
  to = "rgba(192,132,252,0.10)" 
}: SectionBridgeProps) {
  return (
    <div
      aria-hidden
      className="relative w-full pointer-events-none -mt-px -mb-px"
      style={{ height }}
    >
      {/* Radial gradient glow blending two colors */}
      <div
        className="absolute inset-0"
        style={{
          background: `radial-gradient(70% 100% at 50% 0%, ${from}, transparent 70%), radial-gradient(70% 100% at 50% 100%, ${to}, transparent 70%)`,
          filter: "blur(20px)",
        }}
      />
      
      {/* Vertical light streak with pulsing animation */}
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
