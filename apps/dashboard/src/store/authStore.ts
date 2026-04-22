/**
 * Zustand auth store (Req 12.3, 12.4, 12.5)
 *
 * State: user, accessToken, isLoading
 * Actions: login, logout, setAccessToken
 *
 * Wires up the token getter for apiClient on store creation to avoid
 * a circular import (apiClient ← authStore ← apiClient).
 */
import { create } from 'zustand';
import { setTokenGetter } from '../lib/apiClient';

export interface AuthUser {
  id: string;
  email: string;
}

interface AuthState {
  user: AuthUser | null;
  accessToken: string | null;
  isLoading: boolean;
  // Actions
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  setAccessToken: (token: string | null) => void;
}

export const useAuthStore = create<AuthState>((set, get) => {
  // Wire the token getter into apiClient immediately — no circular dep
  setTokenGetter(() => get().accessToken);

  return {
    user: null,
    accessToken: null,
    isLoading: false,

    // -----------------------------------------------------------------------
    // login — POST /auth/login, store access token + user (Req 12.3)
    // -----------------------------------------------------------------------
    login: async (email, password) => {
      set({ isLoading: true });
      try {
        // Lazy import to avoid loading apiClient before the store is ready
        const { apiClient } = await import('../lib/apiClient');
        const { data } = await apiClient.post<{
          accessToken: string;
          user: AuthUser;
        }>('/auth/login', { email, password });

        set({ accessToken: data.accessToken, user: data.user, isLoading: false });
      } catch (err) {
        set({ isLoading: false });
        throw err;
      }
    },

    // -----------------------------------------------------------------------
    // logout — POST /auth/logout, clear local state (Req 2.4)
    // -----------------------------------------------------------------------
    logout: async () => {
      try {
        const { apiClient } = await import('../lib/apiClient');
        await apiClient.post('/auth/logout');
      } catch {
        // Ignore network errors on logout — clear state regardless
      } finally {
        set({ user: null, accessToken: null });
      }
    },

    // -----------------------------------------------------------------------
    // setAccessToken — called by apiClient after a successful token refresh
    // -----------------------------------------------------------------------
    setAccessToken: (token) => set({ accessToken: token }),
  };
});
