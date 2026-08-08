import { useState, FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import Input from '../ui/Input';
import Button from '../ui/Button';
import { useToast } from '../../hooks/useToast';

export default function RegisterForm() {
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
    <form onSubmit={handleSubmit} className="space-y-6">
      <Input
        label="Email"
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="you@example.com"
        required
        autoComplete="email"
        autoFocus
      />

      <div>
        <Input
          label="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="••••••••"
          required
          autoComplete="new-password"
          helperText="At least 8 characters"
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

      <Input
        label="Confirm Password"
        type="password"
        value={confirmPassword}
        onChange={(e) => setConfirmPassword(e.target.value)}
        placeholder="••••••••"
        required
        autoComplete="new-password"
      />

      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
          {error}
        </div>
      )}

      <Button
        type="submit"
        variant="primary"
        size="lg"
        isLoading={isLoading}
        disabled={!email || !password || !confirmPassword || isLoading}
        className="w-full"
      >
        Create Account
      </Button>
    </form>
  );
}
