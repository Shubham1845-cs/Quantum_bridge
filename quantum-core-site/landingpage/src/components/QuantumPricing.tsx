import { useRef, useState } from "react";
import { motion, AnimatePresence, useInView } from "framer-motion";
import { Check, Sparkles, Zap, Shield, Cpu, Database, Server, Lock, Globe, FileText, HardDrive, Key } from "lucide-react";

type Plan = {
  name: string;
  label: string;
  description: string;
  price: number;
  yearlyPrice: number;
  isCustom?: boolean;
  popular?: boolean;
  features: string[];
  buttonText: string;
  buttonSecondary?: string;
  accent: string;
  accent2: string;
  icon: React.ReactNode;
};

const plans: Plan[] = [
  {
    name: "Free",
    label: "FREE",
    description: "Try QuantumBridge risk-free",
    price: 0,
    yearlyPrice: 0,
    features: [
      "1 endpoint",
      "10,000 requests/month",
      "ECDSA + ML-DSA-65 signing",
      "Basic dashboard",
    ],
    buttonText: "START FREE",
    accent: "#67e8f9",
    accent2: "#818cf8",
    icon: <Shield size={16} />,
  },
  {
    name: "Pro",
    label: "PRO",
    description: "For production workloads",
    price: 49,
    yearlyPrice: 470,
    popular: true,
    features: [
      "10 endpoints",
      "1,000,000 requests/month",
      "Custom domain support",
      "Priority email support",
      "CSV/JSON export",
    ],
    buttonText: "GET PRO",
    accent: "#c084fc",
    accent2: "#67e8f9",
    icon: <Sparkles size={16} />,
  },
  {
    name: "Enterprise",
    label: "ENTERPRISE",
    description: "For large-scale deployments",
    price: 0,
    yearlyPrice: 0,
    isCustom: true,
    features: [
      "Unlimited endpoints",
      "Unlimited requests",
      "SLA guarantee",
      "On-premise option",
      "Custom key management",
    ],
    buttonText: "CONTACT SALES",
    buttonSecondary: "Talk to an Expert",
    accent: "#67e8f9",
    accent2: "#c084fc",
    icon: <Cpu size={16} />,
  },
];

const featureIcons: Record<string, React.ReactNode> = {
  "1 endpoint": <Server size={14} />,
  "10 endpoints": <Server size={14} />,
  "Unlimited endpoints": <Server size={14} />,
  "10,000 requests/month": <Database size={14} />,
  "1,000,000 requests/month": <Database size={14} />,
  "Unlimited requests": <Database size={14} />,
  "ECDSA + ML-DSA-65 signing": <Lock size={14} />,
  "Basic dashboard": <FileText size={14} />,
  "Custom domain support": <Globe size={14} />,
  "Priority email support": <Zap size={14} />,
  "CSV/JSON export": <FileText size={14} />,
  "SLA guarantee": <Shield size={14} />,
  "On-premise option": <HardDrive size={14} />,
  "Custom key management": <Key size={14} />,
};

function BillingToggle({ isYearly, onChange }: { isYearly: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="relative inline-flex items-center rounded-full p-1.5 border border-cyan-400/20"
      style={{
        background: "linear-gradient(135deg, rgba(15,18,30,0.9), rgba(20,15,35,0.9))",
        backdropFilter: "blur(20px)",
        boxShadow: "0 8px 32px rgba(0,0,0,0.4), inset 0 1px 1px rgba(255,255,255,0.05), 0 0 24px rgba(103,232,249,0.08)",
      }}
    >
      <motion.div
        layout
        transition={{ type: "spring", stiffness: 350, damping: 30 }}
        className="absolute top-1.5 bottom-1.5 rounded-full"
        style={{
          left: isYearly ? "calc(50% + 2px)" : "6px",
          width: "calc(50% - 8px)",
          background: "linear-gradient(135deg, rgba(103,232,249,0.25), rgba(192,132,252,0.35))",
          boxShadow: "0 0 24px rgba(103,232,249,0.5), inset 0 1px 1px rgba(255,255,255,0.2)",
          border: "1px solid rgba(103,232,249,0.4)",
        }}
      />
      {["Monthly", "Yearly"].map((label, i) => {
        const active = (i === 1) === isYearly;
        return (
          <button
            key={label}
            onClick={() => onChange(i === 1)}
            className="relative z-10 px-6 py-2.5 text-sm font-medium tracking-wide transition-colors flex items-center gap-2"
            style={{ color: active ? "#fff" : "rgba(255,255,255,0.55)" }}
          >
            {label}
            {i === 1 && (
              <span className="text-[10px] px-2 py-0.5 rounded-full font-semibold tracking-wider"
                style={{
                  background: "linear-gradient(135deg, rgba(192,132,252,0.25), rgba(103,232,249,0.25))",
                  color: "#67e8f9",
                  border: "1px solid rgba(103,232,249,0.3)",
                }}
              >
                -20%
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

function PricingCard({ plan, isYearly, index }: { plan: Plan; isYearly: boolean; index: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });
  const [tilt, setTilt] = useState({ x: 0, y: 0 });

  const onMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - 0.5;
    const y = (e.clientY - r.top) / r.height - 0.5;
    setTilt({ x: y * -8, y: x * 8 });
  };
  const onLeave = () => setTilt({ x: 0, y: 0 });

  const accent = plan.popular ? "#c084fc" : "#67e8f9";
  const accent2 = plan.popular ? "#67e8f9" : "#818cf8";
  const price = isYearly ? plan.yearlyPrice : plan.price;

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 60 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.7, delay: index * 0.12, ease: [0.22, 1, 0.36, 1] }}
      onMouseMove={onMove}
      onMouseLeave={onLeave}
      style={{ perspective: 1200 }}
      className="relative"
    >
      <motion.div
        animate={{ rotateX: tilt.x, rotateY: tilt.y, translateY: plan.popular ? -8 : 0 }}
        transition={{ type: "spring", stiffness: 200, damping: 25 }}
        className="relative rounded-2xl overflow-hidden"
        style={{
          transformStyle: "preserve-3d",
          background: plan.popular
            ? "linear-gradient(160deg, rgba(28,18,48,0.85) 0%, rgba(12,16,28,0.92) 60%, rgba(8,10,20,0.95) 100%)"
            : "linear-gradient(160deg, rgba(14,18,28,0.85) 0%, rgba(10,12,20,0.92) 100%)",
          backdropFilter: "blur(24px)",
          border: `1px solid ${plan.popular ? "rgba(192,132,252,0.3)" : "rgba(103,232,249,0.15)"}`,
          boxShadow: plan.popular
            ? "0 24px 80px rgba(192,132,252,0.25), 0 0 60px rgba(103,232,249,0.15), inset 0 1px 1px rgba(255,255,255,0.06)"
            : "0 16px 50px rgba(0,0,0,0.5), inset 0 1px 1px rgba(255,255,255,0.04)",
        }}
      >
        {/* Animated holographic border */}
        <motion.div
          aria-hidden
          className="absolute inset-0 rounded-2xl pointer-events-none"
          style={{
            padding: 1,
            background: `conic-gradient(from 0deg, ${accent}40, ${accent2}40, transparent 30%, ${accent}40)`,
            WebkitMask: "linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0)",
            WebkitMaskComposite: "xor",
            maskComposite: "exclude",
            opacity: plan.popular ? 0.9 : 0.4,
          }}
          animate={{ rotate: 360 }}
          transition={{ duration: 14, repeat: Infinity, ease: "linear" }}
        />

        {/* Ambient glow blob */}
        <motion.div
          aria-hidden
          className="absolute -top-20 -right-20 w-64 h-64 rounded-full pointer-events-none"
          style={{
            background: `radial-gradient(circle, ${accent}33, transparent 70%)`,
            filter: "blur(40px)",
          }}
          animate={{ opacity: [0.4, 0.8, 0.4], scale: [1, 1.15, 1] }}
          transition={{ duration: 5, repeat: Infinity, ease: "easeInOut" }}
        />

        {/* Spotlight effect for PRO */}
        {plan.popular && (
          <motion.div
            aria-hidden
            className="absolute -top-32 left-1/2 -translate-x-1/2 w-96 h-64 rounded-full pointer-events-none"
            style={{
              background: "radial-gradient(ellipse, rgba(192,132,252,0.15), transparent 70%)",
              filter: "blur(60px)",
            }}
            animate={{ opacity: [0.3, 0.6, 0.3] }}
            transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
          />
        )}

        {/* Grid pattern */}
        <div
          aria-hidden
          className="absolute inset-0 pointer-events-none opacity-[0.06]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(255,255,255,0.4) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.4) 1px, transparent 1px)",
            backgroundSize: "32px 32px",
            maskImage: "radial-gradient(ellipse at top, #000 0%, transparent 70%)",
          }}
        />

        <div className="relative p-7 sm:p-8">
          {/* Header */}
          <div className="flex items-start justify-between mb-1">
            <div className="flex items-center gap-2">
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center"
                style={{
                  background: `linear-gradient(135deg, ${accent}33, ${accent2}1a)`,
                  border: `1px solid ${accent}44`,
                  boxShadow: `0 0 16px ${accent}40`,
                }}
              >
                {plan.icon}
              </div>
              <span className="text-[10px] tracking-[0.2em] font-mono uppercase" style={{ color: accent }}>
                {plan.label}
              </span>
            </div>
            {plan.popular && (
              <motion.div
                animate={{ boxShadow: ["0 0 12px rgba(192,132,252,0.4)", "0 0 24px rgba(192,132,252,0.7)", "0 0 12px rgba(192,132,252,0.4)"] }}
                transition={{ duration: 2.4, repeat: Infinity }}
                className="text-[10px] tracking-[0.18em] font-bold px-2.5 py-1 rounded-full uppercase"
                style={{
                  background: "linear-gradient(135deg, #c084fc, #67e8f9)",
                  color: "#0a0a1a",
                }}
              >
                MOST POPULAR
              </motion.div>
            )}
          </div>

          <h3 className="text-2xl font-semibold text-white mt-3 tracking-tight">
            {plan.name}
          </h3>
          <p className="text-sm text-white/55 mt-2 leading-relaxed min-h-[44px]">{plan.description}</p>

          {/* Price */}
          <div className="mt-6 flex items-end gap-1.5 min-h-[64px]">
            {plan.isCustom ? (
              <motion.span
                initial={{ opacity: 0, y: 10, filter: "blur(6px)" }}
                animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
                transition={{ duration: 0.35 }}
                className="text-5xl font-bold tracking-tight"
                style={{
                  background: `linear-gradient(135deg, #fff, ${accent})`,
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                }}
              >
                Custom
              </motion.span>
            ) : (
              <>
                <span className="text-xs text-white/40 mb-2">$</span>
                <AnimatePresence mode="wait">
                  <motion.span
                    key={price}
                    initial={{ opacity: 0, y: 10, filter: "blur(6px)" }}
                    animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
                    exit={{ opacity: 0, y: -10, filter: "blur(6px)" }}
                    transition={{ duration: 0.35 }}
                    className="text-5xl font-bold tracking-tight"
                    style={{
                      background: `linear-gradient(135deg, #fff, ${accent})`,
                      WebkitBackgroundClip: "text",
                      WebkitTextFillColor: "transparent",
                    }}
                  >
                    {price}
                  </motion.span>
                </AnimatePresence>
                <span className="text-sm text-white/45 mb-2">/{isYearly ? "year" : "month"}</span>
              </>
            )}
          </div>

          {/* Divider */}
          <div className="my-6 h-px" style={{ background: `linear-gradient(90deg, transparent, ${accent}55, transparent)` }} />

          {/* CTA */}
          <button
            className="relative w-full group/btn rounded-xl py-3 text-sm font-semibold overflow-hidden transition-transform active:scale-[0.98]"
            style={{
              background: plan.popular
                ? `linear-gradient(135deg, ${accent}, ${accent2})`
                : "rgba(255,255,255,0.04)",
              border: `1px solid ${plan.popular ? "transparent" : accent + "33"}`,
              color: plan.popular ? "#0a0a1a" : "#fff",
              boxShadow: plan.popular ? `0 8px 24px ${accent}55, inset 0 1px 1px rgba(255,255,255,0.3)` : `inset 0 1px 1px rgba(255,255,255,0.05)`,
            }}
          >
            <span className="relative z-10 flex items-center justify-center gap-2">
              <Zap size={14} /> {plan.buttonText}
            </span>
            <motion.span
              className="absolute inset-0 -translate-x-full group-hover/btn:translate-x-full transition-transform duration-700"
              style={{ background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.25), transparent)" }}
            />
          </button>

          {plan.buttonSecondary && (
            <button
              className="mt-3 w-full rounded-xl py-2.5 text-xs font-medium uppercase tracking-[0.2em] transition-colors"
              style={{
                background: "transparent",
                border: "1px solid rgba(255,255,255,0.08)",
                color: "rgba(255,255,255,0.5)",
              }}
            >
              {plan.buttonSecondary}
            </button>
          )}

          {/* Features */}
          <div className="mt-7">
            <div className="flex items-center gap-2 mb-3">
              <Lock size={11} color={accent} />
              <span className="text-[10px] tracking-[0.25em] font-mono uppercase" style={{ color: "rgba(255,255,255,0.4)" }}>
                Capabilities
              </span>
              <div className="flex-1 h-px" style={{ background: "rgba(255,255,255,0.06)" }} />
            </div>
            <ul className="space-y-2.5">
              {plan.features.map((feature, i) => (
                <motion.li
                  key={feature}
                  initial={{ opacity: 0, x: -8 }}
                  animate={inView ? { opacity: 1, x: 0 } : {}}
                  transition={{ delay: index * 0.12 + 0.4 + i * 0.06, duration: 0.4 }}
                  className="flex items-center gap-2.5 text-sm text-white/75"
                >
                  <span
                    className="flex items-center justify-center w-4 h-4 rounded-full shrink-0"
                    style={{
                      background: `${accent}22`,
                      border: `1px solid ${accent}55`,
                      boxShadow: `0 0 8px ${accent}33`,
                    }}
                  >
                    <Check size={9} color={accent} strokeWidth={3} />
                  </span>
                  {feature}
                </motion.li>
              ))}
            </ul>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}

export default function QuantumPricing() {
  const [isYearly, setIsYearly] = useState(false);
  const ref = useRef<HTMLElement>(null);
  const headInView = useInView(ref, { once: true, margin: "-100px" });

  return (
    <section
      ref={ref}
      className="relative w-full overflow-hidden py-24 sm:py-32"
      style={{
        background:
          "radial-gradient(ellipse 90% 60% at 50% 0%, rgba(103,232,249,0.10), transparent 60%), radial-gradient(ellipse 70% 50% at 50% 100%, rgba(192,132,252,0.10), transparent 60%)",
      }}
    >
      {/* Animated grid bg */}
      <div
        aria-hidden
        className="absolute inset-0 pointer-events-none opacity-[0.5]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(103,232,249,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(192,132,252,0.05) 1px, transparent 1px)",
          backgroundSize: "80px 80px",
          maskImage: "radial-gradient(ellipse 80% 60% at 50% 40%, #000 30%, transparent 85%)",
        }}
      />

      {/* Floating particles */}
      {Array.from({ length: 18 }).map((_, i) => (
        <motion.div
          key={i}
          aria-hidden
          className="absolute rounded-full pointer-events-none"
          style={{
            width: 2 + (i % 3),
            height: 2 + (i % 3),
            left: `${(i * 53) % 100}%`,
            top: `${(i * 37) % 100}%`,
            background: i % 2 === 0 ? "#67e8f9" : "#c084fc",
            boxShadow: `0 0 8px ${i % 2 === 0 ? "#67e8f9" : "#c084fc"}`,
            opacity: 0.5,
          }}
          animate={{ y: [0, -30, 0], opacity: [0.2, 0.8, 0.2] }}
          transition={{ duration: 4 + (i % 5), repeat: Infinity, delay: i * 0.3, ease: "easeInOut" }}
        />
      ))}

      {/* Light streaks */}
      <motion.div
        aria-hidden
        className="absolute top-0 left-1/4 w-px h-full pointer-events-none"
        style={{ background: "linear-gradient(180deg, transparent, rgba(103,232,249,0.4), transparent)" }}
        animate={{ opacity: [0, 1, 0] }}
        transition={{ duration: 5, repeat: Infinity, delay: 1 }}
      />
      <motion.div
        aria-hidden
        className="absolute top-0 right-1/4 w-px h-full pointer-events-none"
        style={{ background: "linear-gradient(180deg, transparent, rgba(192,132,252,0.4), transparent)" }}
        animate={{ opacity: [0, 1, 0] }}
        transition={{ duration: 6, repeat: Infinity, delay: 2.5 }}
      />

      <div className="relative max-w-7xl mx-auto px-6">
        {/* Header */}
        <div className="text-center max-w-3xl mx-auto mb-16">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={headInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.6 }}
            className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full mb-6"
            style={{
              background: "rgba(103,232,249,0.06)",
              border: "1px solid rgba(103,232,249,0.2)",
              backdropFilter: "blur(10px)",
            }}
          >
            <motion.span
              className="w-1.5 h-1.5 rounded-full bg-cyan-400"
              animate={{ opacity: [0.4, 1, 0.4], boxShadow: ["0 0 4px #67e8f9", "0 0 12px #67e8f9", "0 0 4px #67e8f9"] }}
              transition={{ duration: 2, repeat: Infinity }}
            />
            <span className="text-[11px] tracking-[0.25em] uppercase font-mono text-cyan-300/90">
              Pricing Matrix / v2.4
            </span>
          </motion.div>

          <motion.h2
            initial={{ opacity: 0, y: 20, filter: "blur(8px)" }}
            animate={headInView ? { opacity: 1, y: 0, filter: "blur(0)" } : {}}
            transition={{ duration: 0.8, delay: 0.1 }}
            className="text-4xl sm:text-5xl md:text-6xl font-bold tracking-tight"
            style={{
              background: "linear-gradient(180deg, #fff 0%, rgba(255,255,255,0.6) 100%)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
            }}
          >
            Quantum-Grade <br />
            <span style={{
              background: "linear-gradient(135deg, #67e8f9, #c084fc)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
            }}>Infrastructure Pricing</span>
          </motion.h2>

          <motion.p
            initial={{ opacity: 0 }}
            animate={headInView ? { opacity: 1 } : {}}
            transition={{ duration: 0.6, delay: 0.3 }}
            className="mt-5 text-white/55 text-base sm:text-lg leading-relaxed"
          >
            Post-quantum cryptography at every tier. No hidden fees. No compromises.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={headInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.6, delay: 0.45 }}
            className="mt-8 flex justify-center"
          >
            <BillingToggle isYearly={isYearly} onChange={setIsYearly} />
          </motion.div>
        </div>

        {/* Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 lg:gap-8">
          {plans.map((plan, i) => (
            <PricingCard key={plan.name} plan={plan} isYearly={isYearly} index={i} />
          ))}
        </div>
      </div>
    </section>
  );
}
