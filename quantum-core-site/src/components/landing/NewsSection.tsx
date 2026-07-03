import { motion } from "framer-motion";
import { Calendar, ArrowRight, Shield, Zap, Lock } from "lucide-react";
import { Link } from "react-router-dom";

interface NewsItem {
  date: string;
  title: string;
  excerpt: string;
  icon: React.ComponentType<{ size: number; className?: string }>;
  href: string;
  category: string;
}

const newsItems: NewsItem[] = [
  {
    date: "March 2025",
    title: "NIST FIPS 204 ML-DSA-65 Integration Complete",
    excerpt: "QuantumBridge now supports dual-signature verification with ECDSA P-256 and ML-DSA-65, providing quantum-safe protection today.",
    icon: Shield,
    href: "/blog/nist-fips-204-integration",
    category: "Product Update"
  },
  {
    date: "February 2025",
    title: "Sub-50ms Proxy Latency Achievement",
    excerpt: "Our edge infrastructure now processes and verifies dual signatures in under 50ms, maintaining performance while adding quantum protection.",
    icon: Zap,
    href: "/blog/sub-50ms-latency",
    category: "Performance"
  },
  {
    date: "January 2025",
    title: "Protecting Against Harvest-Now-Decrypt-Later Attacks",
    excerpt: "Learn why post-quantum cryptography is critical today, even before quantum computers become widely available.",
    icon: Lock,
    href: "/blog/harvest-now-decrypt-later",
    category: "Security"
  }
];

const fadeUp = {
  hidden: { opacity: 0, y: 28 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.15, duration: 0.6, ease: [0.22, 1, 0.36, 1] as const },
  }),
};

export default function NewsSection() {
  return (
    <section
      id="news"
      className="relative py-24 sm:py-32 overflow-hidden"
      style={{
        background: "linear-gradient(180deg, rgba(5,2,15,0.95) 0%, rgba(10,5,20,0.98) 100%)",
      }}
    >
      {/* Background Effects */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        {/* Ambient glow */}
        <div
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] rounded-full opacity-[0.04] blur-[120px]"
          style={{
            background: "radial-gradient(circle, #67e8f9 0%, #c084fc 50%, transparent 70%)",
          }}
        />

        {/* Floating particles */}
        {Array.from({ length: 12 }).map((_, i) => (
          <motion.span
            key={i}
            className="absolute rounded-full"
            style={{
              left: `${(i * 67) % 100}%`,
              top: `${(i * 43) % 100}%`,
              width: i % 3 === 0 ? 3 : 2,
              height: i % 3 === 0 ? 3 : 2,
              background: i % 2 === 0 ? "#c084fc" : "#67e8f9",
              boxShadow: `0 0 12px ${i % 2 === 0 ? "#c084fc" : "#67e8f9"}`,
              opacity: 0.4,
            }}
            animate={{ y: [0, -30, 0], opacity: [0.2, 0.6, 0.2] }}
            transition={{ duration: 8 + (i % 4), repeat: Infinity, delay: i * 0.4, ease: "easeInOut" }}
          />
        ))}
      </div>

      <div className="relative z-10 mx-auto max-w-[1280px] px-5 sm:px-8">
        {/* Section Header */}
        <div className="text-center mb-16">
          <motion.span
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            transition={{ delay: 0.1, duration: 0.6 }}
            className="inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium tracking-wider uppercase mb-6"
            style={{
              borderColor: "rgba(192,132,252,0.35)",
              color: "#c084fc",
              background: "rgba(192,132,252,0.06)",
            }}
          >
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: "#c084fc", boxShadow: "0 0 10px #c084fc" }} />
            Latest Updates
          </motion.span>

          <motion.h2
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
            custom={0}
            variants={fadeUp}
            style={{
              fontFamily: "var(--font-heading)",
              fontSize: "clamp(1.8rem, 4.5vw, 3rem)",
              lineHeight: 1.05,
              letterSpacing: "-0.01em",
              color: "#FFFFFF",
              marginBottom: 20,
            }}
          >
            News & Updates
          </motion.h2>

          <motion.p
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
            custom={1}
            variants={fadeUp}
            style={{
              color: "rgba(255,255,255,0.7)",
              fontSize: "clamp(0.95rem, 1.6vw, 1.05rem)",
              lineHeight: 1.7,
              maxWidth: 720,
              margin: "0 auto",
            }}
          >
            Stay informed about the latest developments in post-quantum cryptography
            and QuantumBridge product updates.
          </motion.p>
        </div>

        {/* News Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-6xl mx-auto">
          {newsItems.map((item, i) => {
            const Icon = item.icon;
            return (
              <motion.article
                key={item.title}
                initial="hidden"
                whileInView="visible"
                viewport={{ once: true, margin: "-50px" }}
                custom={i}
                variants={fadeUp}
                whileHover={{ y: -6, scale: 1.02 }}
                className="relative group cursor-pointer rounded-2xl overflow-hidden"
                style={{
                  background: "linear-gradient(155deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.02) 60%, rgba(255,255,255,0.01) 100%)",
                  border: "1px solid rgba(255,255,255,0.09)",
                  backdropFilter: "blur(20px)",
                  boxShadow: "0 1px 0 rgba(255,255,255,0.06) inset, 0 20px 60px -30px rgba(192,132,252,0.3), 0 0 0 1px rgba(255,255,255,0.02)",
                }}
              >
                <Link to={item.href} className="block p-6">
                  {/* Category Badge */}
                  <div className="flex items-center gap-2 mb-4">
                    <span
                      className="text-xs font-medium tracking-wider uppercase px-2 py-1 rounded"
                      style={{
                        color: "#67e8f9",
                        background: "rgba(103,232,249,0.1)",
                      }}
                    >
                      {item.category}
                    </span>
                    <Icon size={16} style={{ color: "#67e8f9" }} />
                  </div>

                  {/* Date */}
                  <div className="flex items-center gap-2 mb-3 text-sm text-white/50">
                    <Calendar size={14} />
                    <time>{item.date}</time>
                  </div>

                  {/* Title */}
                  <h3
                    className="text-lg font-semibold mb-3 group-hover:text-cyan-400 transition-colors"
                    style={{
                      fontFamily: "var(--font-heading)",
                      color: "#FFFFFF",
                      lineHeight: 1.3,
                    }}
                  >
                    {item.title}
                  </h3>

                  {/* Excerpt */}
                  <p
                    className="text-sm mb-4"
                    style={{
                      color: "rgba(255,255,255,0.65)",
                      lineHeight: 1.6,
                    }}
                  >
                    {item.excerpt}
                  </p>

                  {/* Read More Link */}
                  <div className="flex items-center gap-2 text-sm font-medium text-cyan-400 group-hover:gap-3 transition-all">
                    Read more
                    <ArrowRight size={16} />
                  </div>
                </Link>

                {/* Hover glow effect */}
                <div
                  className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
                  style={{
                    background: "radial-gradient(circle at center, rgba(103,232,249,0.08) 0%, transparent 70%)",
                  }}
                />
              </motion.article>
            );
          })}
        </div>

        {/* View All Link */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ delay: 0.6, duration: 0.6 }}
          className="text-center mt-12"
        >
          <Link
            to="/blog"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-full text-sm font-semibold transition-all"
            style={{
              color: "#67e8f9",
              border: "1px solid rgba(103,232,249,0.3)",
              background: "rgba(103,232,249,0.05)",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "rgba(103,232,249,0.15)";
              e.currentTarget.style.borderColor = "rgba(103,232,249,0.5)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "rgba(103,232,249,0.05)";
              e.currentTarget.style.borderColor = "rgba(103,232,249,0.3)";
            }}
          >
            View All News
            <ArrowRight size={16} />
          </Link>
        </motion.div>
      </div>
    </section>
  );
}
