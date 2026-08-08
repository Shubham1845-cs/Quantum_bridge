import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  ArrowRightCircle,
  Zap,
  LockKeyhole,
  Fingerprint,
  Menu,
  X,
  ChevronDown,
  Shield,
  Activity,
  Code,
  Eye,
  LogOut,
} from "lucide-react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { useAuth } from "../context/AuthContext";

// Landing components
import GlobalAtmosphere from "../components/landing/GlobalAtmosphere";
import QuantumAtmosphere from "../components/landing/QuantumAtmosphere";
import SeamlessVideoLoop from "../components/landing/SeamlessVideoLoop";
import MetricCard from "../components/landing/MetricCard";
import UICard3D from "../components/landing/UICard3D";
import QuantumDefenseConsole from "../components/landing/QuantumDefenseConsole";
import QuantumPricing from "../components/landing/QuantumPricing";
import RotaryTimeline from "../components/landing/RotaryTimeline";
import HelpContactSection from "../components/landing/HelpContactSection";
import NewsSection from "../components/landing/NewsSection";
import Footer from "../components/landing/Footer";
import { QUANTUM_METRICS } from "../components/landing/metricData";

const NAV_LINKS = ["Vault", "Plans", "Install", "News", "Help"];

const FEATURE_ITEMS = [
  { label: "Quantum Bridge", href: "#vault", icon: Shield },
  { label: "Defense Console", href: "#defense-console", icon: Activity },
  { label: "API Integration", href: "#install", icon: Code },
  { label: "Real-time Monitoring", href: "#vault", icon: Eye },
];

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

/**
 * HomePage - Lovable Landing Page Integration
 * 
 * Complete landing page with:
 * - GlobalAtmosphere (fixed background)
 * - QuantumAtmosphere (scroll-linked parallax)
 * - Hero section with video background
 * - Quantum Bridge metrics section
 * - Feature showcase sections
 * - Pricing
 * - Timeline
 */
const HomePage = () => {
  const [menuOpen, setMenuOpen] = useState(false);
  const [featuresOpen, setFeaturesOpen] = useState(false);
  const cinematicRef = useRef<HTMLDivElement | null>(null);
  const { isAuthenticated, logout } = useAuth();

  // Set document title
  useEffect(() => {
    document.title = "QuantumBridge — Post-Quantum Cryptography Proxy";
    console.log('[HomePage] Component mounted - should show landing page');
  }, []);

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
        src="https://res.cloudinary.com/dashtm8a6/video/upload/v1779628707/mp__qqmqfc.mp4"
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
        <Link to="/" aria-label="QuantumBridge home" className="flex items-center">
          <Logo />
        </Link>

        <nav className="hidden md:flex items-center gap-8">
          {/* Features Dropdown */}
          <DropdownMenu.Root open={featuresOpen} onOpenChange={setFeaturesOpen}>
            <DropdownMenu.Trigger asChild>
              <button
                className="text-sm font-medium transition-opacity hover:opacity-60 flex items-center gap-1 outline-none"
                style={{ color: "rgba(255,255,255,0.85)" }}
              >
                Features
                <ChevronDown 
                  size={16} 
                  className="transition-transform duration-200" 
                  style={{ transform: featuresOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}
                />
              </button>
            </DropdownMenu.Trigger>

            <DropdownMenu.Portal>
              <DropdownMenu.Content
                className="min-w-[220px] rounded-lg p-2 shadow-2xl animate-in fade-in-0 zoom-in-95 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95 z-50"
                style={{
                  backgroundColor: "rgba(10, 10, 15, 0.95)",
                  backdropFilter: "blur(20px)",
                  border: "1px solid rgba(255, 255, 255, 0.1)",
                  boxShadow: "0 8px 32px rgba(0, 0, 0, 0.5), inset 0 1px 1px rgba(255, 255, 255, 0.1)",
                  zIndex: 9999,
                }}
                sideOffset={8}
              >
                {FEATURE_ITEMS.map((item) => {
                  const Icon = item.icon;
                  return (
                    <DropdownMenu.Item
                      key={item.label}
                      asChild
                    >
                      <a
                        href={item.href}
                        className="flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-all outline-none cursor-pointer"
                        style={{
                          color: "rgba(255, 255, 255, 0.85)",
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.backgroundColor = "rgba(192, 132, 252, 0.15)";
                          e.currentTarget.style.color = "#c084fc";
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.backgroundColor = "transparent";
                          e.currentTarget.style.color = "rgba(255, 255, 255, 0.85)";
                        }}
                      >
                        <Icon size={16} style={{ color: "#67e8f9" }} />
                        {item.label}
                      </a>
                    </DropdownMenu.Item>
                  );
                })}
              </DropdownMenu.Content>
            </DropdownMenu.Portal>
          </DropdownMenu.Root>

          {/* Regular Nav Links */}
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
          {isAuthenticated ? (
            <>
              <Link
                to="/dashboard"
                className="relative group overflow-hidden rounded-full px-5 py-2.5 text-sm font-semibold text-white bg-white/[0.08] backdrop-blur-2xl border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.35),inset_0_1px_1px_rgba(255,255,255,0.2)] transition-transform hover:scale-[1.03]"
              >
                <span className="relative z-10">Dashboard</span>
                <div className="absolute inset-0 rounded-full bg-gradient-to-b from-white/40 via-white/10 to-transparent opacity-70" />
                <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition duration-500 bg-[#c084fc]/25" />
              </Link>
              <button
                onClick={logout}
                className="relative group overflow-hidden rounded-full px-5 py-2.5 text-sm font-semibold text-white bg-white/[0.08] backdrop-blur-2xl border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.35),inset_0_1px_1px_rgba(255,255,255,0.2)] transition-transform hover:scale-[1.03] flex items-center gap-2"
              >
                <span className="relative z-10">Logout</span>
                <LogOut size={16} className="relative z-10" />
                <div className="absolute inset-0 rounded-full bg-gradient-to-b from-white/40 via-white/10 to-transparent opacity-70" />
                <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition duration-500 bg-red-500/25" />
              </button>
            </>
          ) : (
            <>
              <Link
                to="/register"
                className="relative group overflow-hidden rounded-full px-5 py-2.5 text-sm font-semibold text-white bg-white/[0.08] backdrop-blur-2xl border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.35),inset_0_1px_1px_rgba(255,255,255,0.2)] transition-transform hover:scale-[1.03]"
              >
                <span className="relative z-10">Start For Free</span>
                <div className="absolute inset-0 rounded-full bg-gradient-to-b from-white/40 via-white/10 to-transparent opacity-70" />
                <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition duration-500 bg-[#c084fc]/25" />
              </Link>
              <Link
                to="/login"
                className="relative group overflow-hidden rounded-full px-5 py-2.5 text-sm font-semibold text-white bg-white/[0.08] backdrop-blur-2xl border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.35),inset_0_1px_1px_rgba(255,255,255,0.2)] transition-transform hover:scale-[1.03]"
              >
                <span className="relative z-10">Sign In</span>
                <div className="absolute inset-0 rounded-full bg-gradient-to-b from-white/40 via-white/10 to-transparent opacity-70" />
                <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition duration-500 bg-[#c084fc]/25" />
              </Link>
            </>
          )}
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

      {/* Mobile Menu */}
      {menuOpen && (
        <div className="fixed inset-0 z-50 md:hidden">
          <div
            className="absolute inset-0 bg-black/80 backdrop-blur-sm"
            onClick={() => setMenuOpen(false)}
          />
          <div className="absolute right-0 top-0 bottom-0 w-64 bg-black/95 backdrop-blur-xl border-l border-white/10 p-6">
            <button
              onClick={() => setMenuOpen(false)}
              className="absolute top-4 right-4 p-2"
              aria-label="Close menu"
            >
              <X size={24} color="white" />
            </button>
            <nav className="mt-12 flex flex-col gap-4">
              {/* Features Section */}
              <div className="mb-2">
                <div className="text-xs font-semibold uppercase tracking-wider text-white/40 mb-3 px-2">
                  Features
                </div>
                {FEATURE_ITEMS.map((item) => {
                  const Icon = item.icon;
                  return (
                    <a
                      key={item.label}
                      href={item.href}
                      onClick={() => setMenuOpen(false)}
                      className="flex items-center gap-3 px-2 py-2 text-base font-medium text-white/85 hover:text-white transition-colors rounded-md hover:bg-white/5"
                    >
                      <Icon size={16} style={{ color: "#67e8f9" }} />
                      {item.label}
                    </a>
                  );
                })}
              </div>

              {/* Divider */}
              <div className="h-px bg-white/10 my-2" />

              {/* Regular Nav Links */}
              {NAV_LINKS.map((l) => (
                <a
                  key={l}
                  href={`#${l.toLowerCase()}`}
                  onClick={() => setMenuOpen(false)}
                  className="text-lg font-medium text-white/85 hover:text-white transition-colors px-2"
                >
                  {l}
                </a>
              ))}
              <div className="mt-6 flex flex-col gap-3">
                {isAuthenticated ? (
                  <>
                    <Link
                      to="/dashboard"
                      className="text-center rounded-full px-5 py-2.5 text-sm font-semibold text-white bg-white/[0.08] border border-white/20"
                    >
                      Dashboard
                    </Link>
                    <button
                      onClick={logout}
                      className="text-center rounded-full px-5 py-2.5 text-sm font-semibold text-white bg-white/[0.08] border border-white/20 flex items-center justify-center gap-2"
                    >
                      Logout
                      <LogOut size={16} />
                    </button>
                  </>
                ) : (
                  <>
                    <Link
                      to="/register"
                      className="text-center rounded-full px-5 py-2.5 text-sm font-semibold text-white bg-white/[0.08] border border-white/20"
                    >
                      Start For Free
                    </Link>
                    <Link
                      to="/login"
                      className="text-center rounded-full px-5 py-2.5 text-sm font-semibold text-white bg-white/[0.08] border border-white/20"
                    >
                      Sign In
                    </Link>
                  </>
                )}
              </div>
            </nav>
          </div>
        </div>
      )}

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
            Quantum-Safe API Proxy{" "}
            <LockKeyhole
              size={24}
              color="#67e8f9"
              style={{ display: "inline", verticalAlign: "middle", position: "relative", top: -2, margin: "0 6px" }}
            />{" "}
            for Legacy Systems
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
            Dual-signature verification with ECDSA P-256 and ML-DSA-65 (NIST FIPS 204).
            Protect your APIs from harvest-now-decrypt-later attacks without touching legacy code.
          </motion.p>

          <motion.button
            initial="hidden"
            animate="visible"
            custom={2}
            variants={fadeUp}
            whileHover={{ scale: 1.04 }}
            whileTap={{ scale: 0.96 }}
            onClick={() => window.location.href = "/register"}
            className="relative group overflow-hidden rounded-full px-7 py-4 text-white font-semibold bg-white/[0.08] backdrop-blur-2xl border border-white/20 shadow-[0_8px_32px_rgba(0,0,0,0.35),inset_0_1px_1px_rgba(255,255,255,0.2)] inline-flex items-center justify-between cursor-pointer"
            style={{
              fontFamily: "var(--font-body)",
              fontSize: "clamp(0.9rem, 2vw, 1rem)",
              minWidth: 210,
              gap: 32,
            }}
          >
            <span className="relative z-10 flex items-center gap-2">Get Started</span>
            <ArrowRightCircle size={20} className="relative z-10" />
            <div className="absolute inset-0 rounded-full bg-gradient-to-b from-white/40 via-white/10 to-transparent opacity-70" />
            <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition duration-500 bg-[#c084fc]/25" />
          </motion.button>
        </div>
      </section>
      </div>
      {/* END HERO BLOCK */}

      {/* Quantum Bridge Proxy Engine — continuation section */}
      <section id="vault" className="relative z-10 mx-auto max-w-[1280px] px-5 sm:px-8 pt-24 sm:pt-32 pb-32">
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
          className="relative"
        >
          {/* Section header */}
          <div className="text-center mb-12">
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
                maxWidth: 720,
                margin: "0 auto",
              }}
            >
              Every request is dual-signed with ECDSA P-256 and ML-DSA-65 (NIST FIPS 204).
              Verified at the edge, forwarded in under 50ms — quantum-safe, today.
            </p>
          </div>

          {/* Two-column layout: UICard3D (left) + Metrics Grid (right) */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 max-w-6xl mx-auto items-center">
            {/* LEFT: UICard3D */}
            <div className="flex justify-center lg:justify-start">
              <UICard3D />
            </div>

            {/* RIGHT: 2x2 Metrics Grid */}
            <div
              className="grid grid-cols-1 sm:grid-cols-2 gap-4"
              style={{ perspective: 1200 }}
            >
              {QUANTUM_METRICS.map((m, i) => (
                <MetricCard key={m.label} m={m} index={i} />
              ))}
            </div>
          </div>
        </motion.div>
      </section>

      </div>
      {/* END CINEMATIC SECTION */}

      {/* How It Works - Rotary Timeline */}
      <div id="install">
        <RotaryTimeline />
      </div>

      {/* Quantum Defense Console */}
      <div id="defense-console">
        <QuantumDefenseConsole />
      </div>

      {/* Pricing */}
      <div id="plans">
        <QuantumPricing />
      </div>

      {/* News Section */}
      <NewsSection />

      {/* Help & Contact Section */}
      <HelpContactSection />

      {/* Footer */}
      <Footer />

      </div>
    </div>
  );
};

export default HomePage;
