import { useEffect, useRef } from "react";
import { motion } from "framer-motion";

/**
 * Sparkline Component
 * 
 * Real-time animated sparkline chart with wave effects.
 * 
 * Features:
 * - SVG-based line chart with smooth Bézier curves
 * - requestAnimationFrame-based animation for 60fps performance
 * - Wave function calculations for organic movement
 * - Gradient fill with flowing highlight
 * - Neon glow effect with pulsing animation
 * 
 * @param points - Data points (0..1 normalized values)
 * @param color - Line color (hex/rgba)
 * @param active - Animation active state (typically controlled by useInView)
 */

interface SparklineProps {
  points: number[];
  color: string;
  active: boolean;
}

export default function Sparkline({ points, color, active }: SparklineProps) {
  const W = 220;
  const H = 52;
  const N = points.length;
  const pathRef = useRef<SVGPathElement>(null);
  const areaRef = useRef<SVGPathElement>(null);
  const glowRef = useRef<SVGPathElement>(null);
  
  // Generate unique IDs for gradients and filters based on color
  const gradId = `spark-fill-${color.replace(/[^a-z0-9]/gi, "")}`;
  const flowId = `spark-flow-${color.replace(/[^a-z0-9]/gi, "")}`;
  const blurId = `spark-blur-${color.replace(/[^a-z0-9]/gi, "")}`;

  useEffect(() => {
    if (!active) return;
    
    let raf = 0;
    const start = performance.now();
    const seed = points.reduce((a, b) => a + b, 0); // unique seed per card for variation
    
    const tick = (now: number) => {
      const t = (now - start) / 1000;
      
      // Apply wave functions to create organic movement
      const animated = points.map((p, i) => {
        const wave =
          Math.sin(t * 1.1 + i * 0.55 + seed) * 0.045 +
          Math.sin(t * 0.65 + i * 0.32 + seed * 1.3) * 0.03 +
          Math.sin(t * 2.3 + i * 0.9) * 0.012;
        return Math.max(0.04, Math.min(0.98, p + wave));
      });
      
      // Calculate min/max for normalization
      let max = -Infinity;
      let min = Infinity;
      for (const v of animated) {
        if (v > max) max = v;
        if (v < min) min = v;
      }
      const range = max - min || 1;
      
      // Map points to SVG coordinates
      const step = W / (N - 1);
      const coords: Array<[number, number]> = animated.map((p, i) => [
        i * step,
        H - ((p - min) / range) * (H - 10) - 5,
      ]);
      
      // Build smooth curve path using Bézier control points
      let d = `M${coords[0][0].toFixed(1)},${coords[0][1].toFixed(2)}`;
      for (let i = 1; i < coords.length; i++) {
        const [x0, y0] = coords[i - 1];
        const [x1, y1] = coords[i];
        const cx = (x0 + x1) / 2;
        d += ` C${cx.toFixed(1)},${y0.toFixed(2)} ${cx.toFixed(1)},${y1.toFixed(2)} ${x1.toFixed(1)},${y1.toFixed(2)}`;
      }
      
      // Create area fill path (line + bottom edge)
      const area = `${d} L${W.toFixed(1)},${H} L0,${H} Z`;
      
      // Update SVG paths directly for performance
      if (pathRef.current) pathRef.current.setAttribute("d", d);
      if (glowRef.current) glowRef.current.setAttribute("d", d);
      if (areaRef.current) areaRef.current.setAttribute("d", area);
      
      raf = requestAnimationFrame(tick);
    };
    
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [active, points, N, W, H]);

  return (
    <svg
      width="100%"
      height={H}
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      style={{ display: "block", overflow: "visible" }}
    >
      <defs>
        {/* Vertical gradient for area fill */}
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.42" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
        
        {/* Horizontal flowing gradient for line */}
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
        
        {/* Blur filter for glow effect */}
        <filter id={blurId} x="-20%" y="-50%" width="140%" height="200%">
          <feGaussianBlur stdDeviation="3" />
        </filter>
      </defs>

      {/* Soft neon bloom under the line */}
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

      {/* Gradient area fill with subtle pulse */}
      <motion.path
        ref={areaRef}
        d=""
        fill={`url(#${gradId})`}
        initial={{ opacity: 0 }}
        animate={{ opacity: active ? [0.7, 1, 0.7] : 0 }}
        transition={{ duration: 3.2, repeat: Infinity, ease: "easeInOut" }}
      />

      {/* Main animated line with flowing gradient */}
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
