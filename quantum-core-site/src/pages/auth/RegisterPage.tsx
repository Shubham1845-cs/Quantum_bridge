import { useState, FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../../hooks/useToast';

export default function RegisterPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  
  const { register } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();

  const validatePassword = (pwd: string): string | null => {
    if (pwd.length < 8) {
      return 'Password must be at least 8 characters';
    }
    return null;
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');

    // Validate password
    const passwordError = validatePassword(password);
    if (passwordError) {
      setError(passwordError);
      return;
    }

    // Check password match
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setIsLoading(true);

    try {
      await register(email, password);
      toast.success('Registration successful! Please check your email to verify your account.');
      navigate('/dashboard');
    } catch (err: any) {
      const status = err.response?.status;
      const message = err.response?.data?.error;

      if (status === 409) {
        setError('An account with this email already exists.');
      } else {
        setError(message || 'Registration failed. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const passwordStrength = (pwd: string): { strength: number; label: string; color: string } => {
    if (pwd.length === 0) return { strength: 0, label: '', color: '' };
    if (pwd.length < 8) return { strength: 25, label: 'Weak', color: 'bg-red-500' };
    
    let strength = 25;
    if (pwd.length >= 12) strength += 25;
    if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) strength += 25;
    if (/[0-9]/.test(pwd)) strength += 12.5;
    if (/[^a-zA-Z0-9]/.test(pwd)) strength += 12.5;

    if (strength <= 25) return { strength, label: 'Weak', color: 'bg-red-500' };
    if (strength <= 50) return { strength, label: 'Fair', color: 'bg-yellow-500' };
    if (strength <= 75) return { strength, label: 'Good', color: 'bg-green-500' };
    return { strength, label: 'Strong', color: 'bg-cyber-cyan' };
  };

  const strength = passwordStrength(password);

  return (
    <div className="min-h-screen flex items-center justify-center bg-black relative overflow-hidden px-4">
      {/* Background effects */}
      <div className="absolute inset-0">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] rounded-full opacity-[0.06] blur-[150px] bg-gradient-to-br from-neon-purple to-cyber-cyan" />
        <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(ellipse_80%_60%_at_50%_100%,rgba(138,43,226,0.04),transparent_70%)]" />
        <div
          className="absolute inset-0 opacity-[0.02]"
          style={{
            backgroundImage:
              'linear-gradient(rgba(138,43,226,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(138,43,226,0.3) 1px, transparent 1px)',
            backgroundSize: '60px 60px',
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
        <Link to="/" className="flex items-center justify-center gap-1 mb-10 group">
          <span className="text-3xl font-bold tracking-tighter text-white">
            Quantum
            <span className="text-cyber-cyan group-hover:drop-shadow-[0_0_8px_#00FFFF] transition-all duration-300">
              Bridge
            </span>
          </span>
        </Link>

        {/* Card */}
        <div className="rounded-3xl border border-white/[0.08] bg-white/[0.02] backdrop-blur-xl p-8">
          <h1 className="text-2xl font-bold text-white tracking-tight mb-2">
            Create your account
          </h1>
          <p className="text-white/35 text-sm font-light mb-8">
            Start securing your APIs with quantum-safe cryptography
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
                autoComplete="email"
                autoFocus
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
                autoComplete="new-password"
              />
              
              {password && (
                <div className="mt-2">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs text-white/40">Password strength:</span>
                    <span className={`text-xs font-medium ${strength.color.replace('bg-', 'text-')}`}>
                      {strength.label}
                    </span>
                  </div>
                  <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${strength.color} transition-all duration-300`}
                      style={{ width: `${strength.strength}%` }}
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Confirm Password */}
            <div>
              <label className="block text-white/40 text-[10px] font-bold tracking-[0.3em] uppercase mb-2">
                Confirm Password
              </label>
              <input
                type="password"
                required
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full px-4 py-3 rounded-xl bg-white/[0.04] border border-white/[0.08] text-white text-sm placeholder-white/20 focus:outline-none focus:border-neon-purple/50 focus:ring-1 focus:ring-neon-purple/25 transition-all duration-300"
                placeholder="••••••••"
                autoComplete="new-password"
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
              disabled={isLoading || !email || !password || !confirmPassword}
              whileHover={{
                scale: 1.01,
                boxShadow:
                  '0 0 30px rgba(138,43,226,0.25), 0 0 60px rgba(0,255,255,0.1)',
              }}
              whileTap={{ scale: 0.98 }}
              className="w-full py-3.5 rounded-xl font-bold text-white text-sm relative overflow-hidden tracking-wider uppercase disabled:opacity-50 disabled:cursor-not-allowed"
              style={{
                background: 'linear-gradient(135deg, #8A2BE2 0%, #00FFFF 100%)',
              }}
            >
              {isLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Creating account…
                </span>
              ) : (
                'Create Account'
              )}
            </motion.button>
          </form>

          {/* Login link */}
          <p className="text-center text-white/25 text-sm mt-6 font-light">
            Already have an account?{' '}
            <Link
              to="/login"
              className="text-cyber-cyan hover:text-cyber-cyan/80 font-medium transition-colors"
            >
              Sign in
            </Link>
          </p>
        </div>
      </motion.div>
    </div>
  );
}
