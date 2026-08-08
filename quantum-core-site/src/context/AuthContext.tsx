import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import * as authApi from "../api/auth";
import { getToken } from "../api/client";

interface AuthContextValue {
  /** true while we are checking the refresh-token on mount */
  loading: boolean;
  /** true if the user has a valid access token */
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // On mount, try to silently refresh using the httpOnly cookie
  useEffect(() => {
    let isMounted = true;
    
    console.log('[AuthContext] Attempting token refresh on mount...');
    
    authApi
      .refresh()
      .then(() => {
        if (isMounted) {
          console.log('[AuthContext] Token refresh successful');
          setIsAuthenticated(true);
        }
      })
      .catch((error) => {
        if (isMounted) {
          console.log('[AuthContext] Token refresh failed:', error.message);
          setIsAuthenticated(false);
        }
      })
      .finally(() => {
        if (isMounted) {
          console.log('[AuthContext] Auth check complete');
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    await authApi.login(email, password);
    setIsAuthenticated(true);
  }, []);

  const register = useCallback(async (email: string, password: string) => {
    await authApi.register({ email, password });
    // Email verification is required before login — do NOT auto-login here.
    // RegisterPage navigates to the /verify-email interstitial so the user can
    // confirm their inbox before signing in.
  }, []);

  const logout = useCallback(async () => {
    await authApi.logout();
    setIsAuthenticated(false);
  }, []);

  return (
    <AuthContext.Provider
      value={{ loading, isAuthenticated, login, register, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
