import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const { isAuthenticated } = useAuth();

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 50);
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 px-6 py-4" id="navbar">
      {/* Glass backdrop */}
      <div
        className={`absolute inset-0 backdrop-blur-xl transition-all duration-500 ${
          scrolled
            ? "bg-black/60 border-b border-cyan-400/20"
            : "bg-black/20 border-b border-white/5"
        }`}
      />

      <div className="relative flex items-center justify-between max-w-7xl mx-auto">
        {/* Logo — NEXUS with glowing cyan dot */}
        <Link to="/" className="flex items-center gap-1 group" id="logo-link">
          <span className="text-2xl font-bold tracking-tighter text-white transition-colors duration-300">
            NEX
            <span className="text-cyber-cyan group-hover:drop-shadow-[0_0_8px_#00FFFF]  transition-all duration-300">
              U
            </span>
            S
          </span>
          <span className="relative flex h-2 w-2 ml-0.5 -mt-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-cyan opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-cyber-cyan shadow-neon-cyan" />
          </span>
        </Link>

        {/* Desktop Nav Links */}
        <div className="hidden md:flex items-center gap-8">
          {[
            { label: "Features", href: "#features" },
            { label: "Security", href: "#security" },
            { label: "Pricing", href: "#pricing" },
            { label: "How It Works", href: "#how-it-works" },
          ].map((item) => (
            <a
              key={item.label}
              href={item.href}
              className="text-white/40 hover:text-cyber-cyan text-xs font-medium transition-colors duration-300 tracking-[0.2em] uppercase"
              id={`nav-link-${item.label.toLowerCase().replace(/\s+/g, '-')}`}
            >
              {item.label}
            </a>
          ))}
        </div>

        {/* CTA area */}
        <div className="flex items-center gap-3">
          {isAuthenticated ? (
            <>
              <Link
                to="/dashboard"
                className="px-5 py-2 rounded-full text-xs font-bold text-white/50 hover:text-cyber-cyan border border-white/10 hover:border-cyber-cyan/30 transition-all duration-300 tracking-wider uppercase"
                id="nav-dashboard-link"
              >
                Dashboard
              </Link>
            </>
          ) : (
            <>
              <Link
                to="/login"
                className="hidden sm:block px-5 py-2 rounded-full text-xs font-bold text-white/50 hover:text-cyber-cyan border border-white/10 hover:border-cyber-cyan/30 transition-all duration-300 tracking-wider uppercase"
                id="nav-signin-link"
              >
                Sign In
              </Link>
              <Link to="/register">
                <motion.div
                  whileHover={{
                    scale: 1.05,
                    boxShadow:
                      "0 0 25px rgba(0,255,255,0.3), 0 0 50px rgba(138,43,226,0.15)",
                  }}
                  whileTap={{ scale: 0.97 }}
                  className="relative px-6 py-2.5 rounded-full text-sm font-bold text-black overflow-hidden group border border-cyber-cyan/50"
                  style={{
                    background:
                      "linear-gradient(135deg, #00FFFF 0%, #8A2BE2 100%)",
                  }}
                  id="deploy-node-btn"
                >
                  <span className="relative z-10 tracking-wider text-xs uppercase">
                    Deploy Node
                  </span>
                  <motion.div
                    className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                    style={{
                      background:
                        "radial-gradient(circle at center, rgba(0,255,255,0.5), transparent 70%)",
                    }}
                  />
                </motion.div>
              </Link>
            </>
          )}

          {/* Mobile menu toggle */}
          <button
            className="md:hidden text-white/60 hover:text-cyber-cyan transition-colors duration-300"
            onClick={() => setMenuOpen(!menuOpen)}
            aria-label="Toggle menu"
            id="mobile-menu-toggle"
          >
            <svg
              className="w-6 h-6"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              {menuOpen ? (
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              ) : (
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4 6h16M4 12h16M4 18h16"
                />
              )}
            </svg>
          </button>
        </div>
      </div>

      {/* Mobile Menu */}
      <AnimatePresence>
        {menuOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="relative md:hidden mt-4 pb-4 border-t border-cyber-cyan/20"
            id="mobile-menu"
          >
            <div className="flex flex-col gap-4 pt-4">
              {[
                { label: "Features", href: "#features" },
                { label: "Security", href: "#security" },
                { label: "Pricing", href: "#pricing" },
                { label: "How It Works", href: "#how-it-works" },
              ].map((item) => (
                <a
                  key={item.label}
                  href={item.href}
                  className="text-white/50 hover:text-cyber-cyan text-sm font-medium transition-colors tracking-[0.15em] uppercase px-2"
                  onClick={() => setMenuOpen(false)}
                >
                  {item.label}
                </a>
              ))}
              <div className="border-t border-white/5 pt-4 mt-2 flex flex-col gap-3 px-2">
                {isAuthenticated ? (
                  <Link
                    to="/dashboard"
                    className="text-cyber-cyan text-sm font-bold tracking-wider uppercase"
                    onClick={() => setMenuOpen(false)}
                  >
                    Dashboard →
                  </Link>
                ) : (
                  <>
                    <Link
                      to="/login"
                      className="text-white/50 hover:text-cyber-cyan text-sm font-medium tracking-wider uppercase"
                      onClick={() => setMenuOpen(false)}
                    >
                      Sign In
                    </Link>
                    <Link
                      to="/register"
                      className="text-cyber-cyan text-sm font-bold tracking-wider uppercase"
                      onClick={() => setMenuOpen(false)}
                    >
                      Create Account
                    </Link>
                  </>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </nav>
  );
}
