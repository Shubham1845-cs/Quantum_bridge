import { useEffect, useState } from 'react';
import { Link, useSearchParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { verifyEmail, resendVerification } from '../../api/auth';
import { useToast } from '../../hooks/useToast';

export default function VerifyEmailPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const toast = useToast();
  
  const [status, setStatus] = useState<'loading' | 'pending' | 'success' | 'error' | 'expired'>('loading');
  const [error, setError] = useState('');
  const [email, setEmail] = useState('');
  const [isResending, setIsResending] = useState(false);

  const token = searchParams.get('token');
  const emailParam = searchParams.get('email');

  useEffect(() => {
    // Arrived from registration with no token → show the "check your email"
    // interstitial. Seed the email field from the query string so resend works
    // without the user retyping it.
    if (!token) {
      if (emailParam) setEmail(emailParam);
      setStatus('pending');
      return;
    }

    verifyEmail(token)
      .then(() => {
        setStatus('success');
      })
      .catch((err: any) => {
        const status = err.response?.status;
        const message = err.response?.data?.error;

        if (status === 410) {
          setStatus('expired');
          setError('Verification link has expired');
        } else {
          setStatus('error');
          setError(message || 'Verification failed');
        }
      });
  }, [token, emailParam]);

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;

    setIsResending(true);
    try {
      await resendVerification(email);
      toast.success('Verification email sent! Please check your inbox.');
      setEmail('');
    } catch (err: any) {
      toast.error(err.response?.data?.error || 'Failed to resend verification email');
    } finally {
      setIsResending(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-black relative overflow-hidden px-4">
      {/* Background effects */}
      <div className="absolute inset-0">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] rounded-full opacity-[0.06] blur-[150px] bg-gradient-to-br from-cyber-cyan to-neon-purple" />
        <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(ellipse_80%_60%_at_50%_0%,rgba(0,255,255,0.03),transparent_70%)]" />
        <div
          className="absolute inset-0 opacity-[0.02]"
          style={{
            backgroundImage:
              'linear-gradient(rgba(0,255,255,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,255,0.3) 1px, transparent 1px)',
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
          {status === 'loading' && (
            <div className="text-center py-8">
              <div className="w-12 h-12 border-2 border-cyber-cyan/30 border-t-cyber-cyan rounded-full animate-spin mx-auto mb-4" />
              <h1 className="text-xl font-bold text-white mb-2">Verifying your email...</h1>
              <p className="text-white/40 text-sm">Please wait a moment</p>
            </div>
          )}

          {status === 'pending' && (
            <div className="text-center py-8">
              <div className="w-16 h-16 rounded-full bg-cyber-cyan/10 border border-cyber-cyan/20 flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-cyber-cyan" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
              </div>
              <h1 className="text-2xl font-bold text-white mb-2">Check your email</h1>
              <p className="text-white/40 text-sm mb-6">
                We sent a verification link{emailParam ? <> to <span className="text-white/70 font-medium">{emailParam}</span></> : null}. Click it to activate your account, then sign in.
              </p>

              <form onSubmit={handleResend} className="space-y-4">
                <div>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full px-4 py-3 rounded-xl bg-white/[0.04] border border-white/[0.08] text-white text-sm placeholder-white/20 focus:outline-none focus:border-cyber-cyan/50 focus:ring-1 focus:ring-cyber-cyan/25 transition-all duration-300"
                    placeholder="you@company.com"
                  />
                </div>
                <button
                  type="submit"
                  disabled={isResending || !email}
                  className="w-full px-6 py-3 rounded-xl font-bold text-black text-sm tracking-wider uppercase disabled:opacity-50"
                  style={{
                    background: 'linear-gradient(135deg, #00FFFF 0%, #8A2BE2 100%)',
                  }}
                >
                  {isResending ? 'Sending...' : 'Resend verification email'}
                </button>
              </form>

              <Link
                to="/login"
                className="inline-block mt-4 text-white/40 text-xs hover:text-white/60 transition-colors"
              >
                Already verified? Sign in
              </Link>
            </div>
          )}

          {status === 'success' && (
            <div className="text-center py-8">
              <div className="w-16 h-16 rounded-full bg-green-500/10 border border-green-500/20 flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h1 className="text-2xl font-bold text-white mb-2">Email verified!</h1>
              <p className="text-white/40 text-sm mb-6">
                Your account has been successfully verified. You can now sign in.
              </p>
              <Link
                to="/login"
                className="inline-block px-6 py-3 rounded-xl font-bold text-black text-sm tracking-wider uppercase"
                style={{
                  background: 'linear-gradient(135deg, #00FFFF 0%, #8A2BE2 100%)',
                }}
              >
                Go to Login
              </Link>
            </div>
          )}

          {status === 'expired' && (
            <div className="text-center py-8">
              <div className="w-16 h-16 rounded-full bg-yellow-500/10 border border-yellow-500/20 flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <h1 className="text-2xl font-bold text-white mb-2">Link expired</h1>
              <p className="text-white/40 text-sm mb-6">
                This verification link has expired. Enter your email below to receive a new one.
              </p>

              <form onSubmit={handleResend} className="space-y-4">
                <div>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full px-4 py-3 rounded-xl bg-white/[0.04] border border-white/[0.08] text-white text-sm placeholder-white/20 focus:outline-none focus:border-cyber-cyan/50 focus:ring-1 focus:ring-cyber-cyan/25 transition-all duration-300"
                    placeholder="you@company.com"
                    autoFocus
                  />
                </div>
                <button
                  type="submit"
                  disabled={isResending || !email}
                  className="w-full px-6 py-3 rounded-xl font-bold text-black text-sm tracking-wider uppercase disabled:opacity-50"
                  style={{
                    background: 'linear-gradient(135deg, #00FFFF 0%, #8A2BE2 100%)',
                  }}
                >
                  {isResending ? 'Sending...' : 'Resend Verification Email'}
                </button>
              </form>
            </div>
          )}

          {status === 'error' && (
            <div className="text-center py-8">
              <div className="w-16 h-16 rounded-full bg-red-500/10 border border-red-500/20 flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
              <h1 className="text-2xl font-bold text-white mb-2">Verification failed</h1>
              <p className="text-red-400 text-sm mb-6">{error}</p>
              <Link
                to="/login"
                className="inline-block px-6 py-3 rounded-xl font-bold text-white text-sm tracking-wider uppercase border border-white/10 hover:bg-white/5 transition-colors"
              >
                Back to Login
              </Link>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
