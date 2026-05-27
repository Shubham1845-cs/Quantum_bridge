import { motion } from "framer-motion";
import type { Product } from "../data/products";

interface Props {
  product: Product;
}

export default function HeroSection({ product }: Props) {
  return (
    <section
      className="relative h-screen flex items-center justify-center overflow-hidden"
      id="hero"
    >
      {/* Background effects */}
      <div className="absolute inset-0">
        {/* Central gradient orb */}
        <div
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] rounded-full opacity-[0.07] blur-[120px]"
          style={{ background: product.gradient }}
        />
        {/* Top glow */}
        <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(ellipse_80%_60%_at_50%_0%,rgba(0,255,255,0.04),transparent_70%)]" />
      </div>

      {/* Subtle grid pattern */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `linear-gradient(rgba(0,255,255,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,255,0.3) 1px, transparent 1px)`,
          backgroundSize: "60px 60px",
        }}
      />

      <div className="relative z-10 text-center px-6 max-w-5xl mx-auto">
        {/* Status badge */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, duration: 0.8 }}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-cyber-cyan/30 bg-cyber-cyan/5 mb-8"
          id="hero-status-badge"
        >
          <span className="w-2 h-2 rounded-full bg-cyber-cyan animate-pulse" />
          <span className="text-cyber-cyan text-[10px] font-bold tracking-[0.3em] uppercase">
            System Online — v4.0
          </span>
        </motion.div>

        {/* Main title */}
        <motion.h1
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4, duration: 1, ease: [0.22, 1, 0.36, 1] }}
          className="text-6xl md:text-8xl lg:text-9xl font-bold leading-[0.9] tracking-tighter mb-6"
          id="hero-title"
        >
          <span className="text-gradient-cyan">{product.name}</span>
        </motion.h1>

        {/* Subtitle */}
        <motion.p
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6, duration: 0.8 }}
          className="text-xl md:text-2xl text-white/50 font-light tracking-wide mb-12"
          id="hero-subtitle"
        >
          {product.subName}
        </motion.p>

        {/* Feature pills */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8, duration: 0.8 }}
          className="flex flex-wrap justify-center gap-3 mb-14"
        >
          {product.features.map((feature, i) => (
            <motion.span
              key={feature}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 1 + i * 0.15, duration: 0.5 }}
              className="px-5 py-2 rounded-full text-xs font-semibold border border-cyber-cyan/25 text-cyber-cyan bg-cyber-cyan/5 backdrop-blur-sm tracking-wider uppercase"
            >
              {feature}
            </motion.span>
          ))}
        </motion.div>

        {/* Stats row */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.2, duration: 0.8 }}
          className="flex justify-center gap-12 md:gap-20"
        >
          {product.stats.map((stat, i) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1.4 + i * 0.12, duration: 0.6 }}
              className="text-center"
            >
              <div className="text-3xl md:text-4xl font-bold text-gradient-cyan tracking-tight">
                {stat.val}
              </div>
              <div className="text-[10px] text-white/30 uppercase tracking-[0.3em] mt-2 font-medium">
                {stat.label}
              </div>
            </motion.div>
          ))}
        </motion.div>
      </div>

      {/* Scroll indicator */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 2, duration: 1 }}
        className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-3"
        id="scroll-indicator"
      >
        <span className="text-white/25 text-[10px] tracking-[0.4em] uppercase font-medium">
          Scroll to Explore
        </span>
        <motion.div
          animate={{ y: [0, 8, 0] }}
          transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
          className="w-5 h-8 rounded-full border-2 border-white/15 flex items-start justify-center p-1.5"
        >
          <motion.div className="w-1 h-1.5 rounded-full bg-cyber-cyan" />
        </motion.div>
      </motion.div>

      {/* Bottom fade into canvas */}
      <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-black/50 to-transparent pointer-events-none" />
    </section>
  );
}
