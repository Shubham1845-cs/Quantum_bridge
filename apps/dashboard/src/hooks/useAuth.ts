/**
 * useAuth — convenience hook that exposes auth state and actions (Req 12.3–12.5)
 *
 * Wraps useAuthStore so components don't need to import the store directly.
 */
import { useAuthStore } from '../store/authStore';

export function useAuth() {
  const user        = useAuthStore((s) => s.user);
  const accessToken = useAuthStore((s) => s.accessToken);
  const isLoading   = useAuthStore((s) => s.isLoading);
  const login       = useAuthStore((s) => s.login);
  const logout      = useAuthStore((s) => s.logout);

  return {
    user,
    accessToken,
    isLoading,
    isAuthenticated: accessToken !== null,
    login,
    logout,
  };
}
