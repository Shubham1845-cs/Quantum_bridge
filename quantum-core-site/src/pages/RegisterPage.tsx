import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { useAuth } from "../context/AuthContext";
import SeamlessVideoLoop from "../components/landing/SeamlessVideoLoop";

export default function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");

    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }

    setLoading(true);
    try {
      await register(email, password);
      navigate("/dashboard", { replace: true });
    } catch (err: any) {
      setError(err.message || "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-black relative overflow-hidden px-4">
      {/* Background video */}
      <SeamlessVideoLoop
        src="https://res.cloudinary.com/dashtm8a6/video/upload/v1780173523/no_htxeus.mp4"
        crossfade={1.4}
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          objectFit: 'cover',
          opacity: 0.8,
        }}
      />

      {/* Very light overlay for slight contrast */}
      <div className="absolute inset-0 bg-black/10" />

      {/* Background effects */}
      <div className="absolute inset-0">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] rounded-full opacity-[0.06] blur-[150px] bg-gradient-to-br from-neon-purple to-cyber-cyan" />
        <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(ellipse_80%_60%_at_50%_100%,rgba(138,43,226,0.04),transparent_70%)]" />
        <div
          className="absolute inset-0 opacity-[0.02]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(138,43,226,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(138,43,226,0.3) 1px, transparent 1px)",
            backgroundSize: "60px 60px",
          }}
        />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
        className="relative z-10 w-full max-w-md"
      >
        {/* Logo */}
        <Link to="/" className="flex items-center justify-center mb-10">
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
        </Link>

        {/* Card */}
        <div className="rounded-3xl border border-white/[0.2] bg-black/[0.3] backdrop-blur-sm p-8">
          <h1 className="text-2xl font-bold text-white tracking-tight mb-2">
            Deploy your first node
          </h1>
          <p className="text-white/35 text-sm font-light mb-8">
            Create an account to start building on the quantum network
          </p>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Email */}
            <div>
              <label className="block text-white/40 text-[10px] font-bold tracking-[0.3em] uppercase mb-2">
                Email
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-3 rounded-xl bg-white/[0.04] border border-white/[0.08] text-white text-sm placeholder-white/20 focus:outline-none focus:border-neon-purple/50 focus:ring-1 focus:ring-neon-purple/25 transition-all duration-300"
                placeholder="you@company.com"
                id="register-email"
              />
            </div>

            {/* Password */}
            <div>
              <label className="block text-white/40 text-[10px] font-bold tracking-[0.3em] uppercase mb-2">
                Password
              </label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 rounded-xl bg-white/[0.04] border border-white/[0.08] text-white text-sm placeholder-white/20 focus:outline-none focus:border-neon-purple/50 focus:ring-1 focus:ring-neon-purple/25 transition-all duration-300"
                placeholder="Min. 8 characters"
                id="register-password"
              />
            </div>

            {/* Confirm Password */}
            <div>
              <label className="block text-white/40 text-[10px] font-bold tracking-[0.3em] uppercase mb-2">
                Confirm Password
              </label>
              <input
                type="password"
                required
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                className="w-full px-4 py-3 rounded-xl bg-white/[0.04] border border-white/[0.08] text-white text-sm placeholder-white/20 focus:outline-none focus:border-neon-purple/50 focus:ring-1 focus:ring-neon-purple/25 transition-all duration-300"
                placeholder="••••••••"
                id="register-confirm"
              />
            </div>

            {/* Error */}
            {error && (
              <motion.div
                initial={{ opacity: 0, y: -5 }}
                animate={{ opacity: 1, y: 0 }}
                className="px-4 py-3 rounded-xl border border-red-500/20 bg-red-500/5 text-red-400 text-sm"
              >
                {error}
              </motion.div>
            )}

            {/* Submit */}
            <motion.button
              type="submit"
              disabled={loading}
              whileHover={{
                scale: 1.01,
                boxShadow:
                  "0 0 30px rgba(138,43,226,0.25), 0 0 60px rgba(0,255,255,0.1)",
              }}
              whileTap={{ scale: 0.98 }}
              className="w-full py-3.5 rounded-xl font-bold text-white text-sm relative overflow-hidden tracking-wider uppercase disabled:opacity-50 disabled:cursor-not-allowed"
              style={{
                background: "linear-gradient(135deg, #8A2BE2 0%, #00FFFF 100%)",
              }}
              id="register-submit"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Creating account…
                </span>
              ) : (
                "Create Account"
              )}
            </motion.button>
          </form>

          {/* Login link */}
          <p className="text-center text-white/25 text-sm mt-6 font-light">
            Already have an account?{" "}
            <Link
              to="/login"
              className="text-cyber-cyan hover:text-cyber-cyan/80 font-medium transition-colors"
              id="goto-login"
            >
              Sign in
            </Link>
          </p>
        </div>
      </motion.div>
    </div>
  );
}
