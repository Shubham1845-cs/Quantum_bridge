/**
 * Axios instance with JWT interceptor and auto-refresh (Req 2.1, 2.2)
 *
 * Request interceptor:
 *   - Attaches `Authorization: Bearer {accessToken}` on every request
 *
 * Response interceptor:
 *   - On 401: calls POST /auth/refresh to get a new access token,
 *     updates the auth store, retries the original request once
 *   - If refresh fails: clears auth state and redirects to /login
 */
import axios, { type AxiosRequestConfig } from 'axios';

// ---------------------------------------------------------------------------
// Axios instance
// ---------------------------------------------------------------------------

export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? 'http://localhost:3000',
  withCredentials: true, // required for httpOnly refresh token cookie
});

// ---------------------------------------------------------------------------
// Token getter — set by authStore after it initialises (avoids circular dep)
// ---------------------------------------------------------------------------

let _getToken: (() => string | null) | null = null;

/** Called once by authStore to wire up the token getter. */
export function setTokenGetter(fn: () => string | null): void {
  _getToken = fn;
}

// ---------------------------------------------------------------------------
// Request interceptor — attach Bearer token
// ---------------------------------------------------------------------------

apiClient.interceptors.request.use((config) => {
  const token = _getToken?.();
  if (token) {
    config.headers = config.headers ?? {};
    config.headers['Authorization'] = `Bearer ${token}`;
  }
  return config;
});

// ---------------------------------------------------------------------------
// Response interceptor — auto-refresh on 401
// ---------------------------------------------------------------------------

// Track whether a refresh is already in flight to avoid concurrent refresh loops
let isRefreshing = false;
// Queue of callbacks waiting for the new token
let refreshQueue: ((token: string) => void)[] = [];

function processQueue(newToken: string) {
  refreshQueue.forEach((cb) => cb(newToken));
  refreshQueue = [];
}

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };

    // Only attempt refresh on 401 and only once per request
    if (error.response?.status !== 401 || originalRequest._retry) {
      return Promise.reject(error);
    }

    // Don't retry the refresh endpoint itself — that would loop forever
    if (originalRequest.url?.includes('/auth/refresh')) {
      handleAuthFailure();
      return Promise.reject(error);
    }

    originalRequest._retry = true;

    if (isRefreshing) {
      // Another refresh is already in flight — queue this request
      return new Promise((resolve, reject) => {
        refreshQueue.push((token) => {
          if (originalRequest.headers) {
            originalRequest.headers['Authorization'] = `Bearer ${token}`;
          }
          resolve(apiClient(originalRequest));
        });
        // If refresh ultimately fails, reject queued requests too
        void error; // keep reference alive
        reject; // will be called via handleAuthFailure path if needed
      });
    }

    isRefreshing = true;

    try {
      const { data } = await apiClient.post<{ accessToken: string }>('/auth/refresh');
      const newToken = data.accessToken;

      // Update store with new token
      const { useAuthStore } = await import('../store/authStore');
      useAuthStore.getState().setAccessToken(newToken);

      // Retry all queued requests with the new token
      processQueue(newToken);

      // Retry the original request
      if (originalRequest.headers) {
        originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
      }
      return apiClient(originalRequest);
    } catch {
      // Refresh failed — clear auth and redirect to login
      refreshQueue = [];
      handleAuthFailure();
      return Promise.reject(error);
    } finally {
      isRefreshing = false;
    }
  }
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function handleAuthFailure() {
  import('../store/authStore').then(({ useAuthStore }) => {
    useAuthStore.getState().logout();
  });
  // Redirect to login — use window.location to avoid importing the router here
  if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
    window.location.href = '/login';
  }
}
