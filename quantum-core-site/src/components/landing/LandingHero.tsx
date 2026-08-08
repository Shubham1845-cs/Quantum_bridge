import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import { Sparkles, Shield, Zap } from "lucide-react";

export default function LandingHero() {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden bg-gradient-to-b from-slate-950 via-purple-950/20 to-slate-950">
      {/* Animated background gradient orbs */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <motion.div
          className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/20 rounded-full blur-3xl"
          animate={{
            scale: [1, 1.2, 1],
            opacity: [0.3, 0.5, 0.3],
          }}
          transition={{
            duration: 8,
            repeat: Infinity,
            ease: "easeInOut",
          }}
        />
        <motion.div
          className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl"
          animate={{
            scale: [1.2, 1, 1.2],
            opacity: [0.5, 0.3, 0.5],
          }}
          transition={{
            duration: 8,
            repeat: Infinity,
            ease: "easeInOut",
          }}
        />
      </div>

      {/* Main content */}
      <div className="relative z-10 max-w-7xl mx-auto px-6 py-24 text-center">
        {/* Badge */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-full mb-8"
          style={{
            background: "rgba(103, 232, 249, 0.1)",
            border: "1px solid rgba(103, 232, 249, 0.3)",
            backdropFilter: "blur(10px)",
          }}
        >
          <motion.span
            className="w-2 h-2 rounded-full bg-cyan-400"
            animate={{
              opacity: [1, 0.5, 1],
              scale: [1, 1.2, 1],
            }}
            transition={{
              duration: 2,
              repeat: Infinity,
              ease: "easeInOut",
            }}
          />
          <span className="text-cyan-300 text-sm font-medium tracking-wide">
            Post-Quantum Security Platform
          </span>
        </motion.div>

        {/* Main heading */}
        <motion.h1
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="text-5xl md:text-7xl lg:text-8xl font-bold mb-6 leading-tight"
        >
          <span
            className="bg-gradient-to-r from-cyan-400 via-purple-400 to-cyan-400 bg-clip-text text-transparent"
            style={{
              backgroundSize: "200% auto",
            }}
          >
            Quantum-Safe
          </span>
          <br />
          <span className="text-white">API Gateway</span>
        </motion.h1>

        {/* Subtitle */}
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.4 }}
          className="text-lg md:text-xl text-slate-300 max-w-3xl mx-auto mb-12 leading-relaxed"
        >
          Protect your APIs with{" "}
          <span className="text-cyan-400 font-semibold">ML-DSA-65</span> and{" "}
          <span className="text-purple-400 font-semibold">ML-KEM-768</span>{" "}
          post-quantum cryptography. NIST-approved algorithms securing your data
          against quantum threats.
        </motion.p>

        {/* CTA Buttons */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.6 }}
          className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16"
        >
          {/* Primary CTA */}
          <Link to="/register">
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="group relative px-8 py-4 rounded-lg font-semibold text-lg overflow-hidden"
              style={{
                background: "linear-gradient(135deg, #67e8f9, #c084fc)",
                boxShadow: "0 0 30px rgba(103, 232, 249, 0.3)",
              }}
            >
              <span className="relative z-10 text-slate-950">
                Start Free Trial
              </span>
              <motion.div
                className="absolute inset-0 bg-white"
                initial={{ opacity: 0 }}
                whileHover={{ opacity: 0.2 }}
                transition={{ duration: 0.3 }}
              />
            </motion.button>
          </Link>

          {/* Secondary CTA */}
          <Link to="/login">
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="px-8 py-4 rounded-lg font-semibold text-lg text-cyan-300"
              style={{
                background: "rgba(103, 232, 249, 0.1)",
                border: "2px solid rgba(103, 232, 249, 0.3)",
                backdropFilter: "blur(10px)",
              }}
            >
              View Dashboard
            </motion.button>
          </Link>
        </motion.div>

        {/* Feature pills */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.8 }}
          className="flex flex-wrap items-center justify-center gap-6"
        >
          {/* Feature 1 */}
          <motion.div
            whileHover={{ scale: 1.05 }}
            className="flex items-center gap-3 px-6 py-3 rounded-full"
            style={{
              background: "rgba(103, 232, 249, 0.05)",
              border: "1px solid rgba(103, 232, 249, 0.2)",
              backdropFilter: "blur(10px)",
            }}
          >
            <div className="p-2 rounded-full bg-cyan-500/20">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <span className="text-slate-300 font-medium">
              NIST PQC Compliant
            </span>
          </motion.div>

          {/* Feature 2 */}
          <motion.div
            whileHover={{ scale: 1.05 }}
            className="flex items-center gap-3 px-6 py-3 rounded-full"
            style={{
              background: "rgba(192, 132, 252, 0.05)",
              border: "1px solid rgba(192, 132, 252, 0.2)",
              backdropFilter: "blur(10px)",
            }}
          >
            <div className="p-2 rounded-full bg-purple-500/20">
              <Zap className="w-5 h-5 text-purple-400" />
            </div>
            <span className="text-slate-300 font-medium">
              Zero-Trust Architecture
            </span>
          </motion.div>

          {/* Feature 3 */}
          <motion.div
            whileHover={{ scale: 1.05 }}
            className="flex items-center gap-3 px-6 py-3 rounded-full"
            style={{
              background: "rgba(103, 232, 249, 0.05)",
              border: "1px solid rgba(103, 232, 249, 0.2)",
              backdropFilter: "blur(10px)",
            }}
          >
            <div className="p-2 rounded-full bg-cyan-500/20">
              <Sparkles className="w-5 h-5 text-cyan-400" />
            </div>
            <span className="text-slate-300 font-medium">
              Real-Time Analytics
            </span>
          </motion.div>
        </motion.div>
      </div>

      {/* Bottom gradient fade */}
      <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-slate-950 to-transparent pointer-events-none" />
    </section>
  );
}
