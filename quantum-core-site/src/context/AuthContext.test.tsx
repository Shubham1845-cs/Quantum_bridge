import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider, useAuth } from './AuthContext';
import * as authApi from '../api/auth';

vi.mock('../api/auth');

describe('AuthContext', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    localStorage.clear();
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
      },
    });
  });

  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>{children}</AuthProvider>
    </QueryClientProvider>
  );

  it('should throw error when used outside AuthProvider', () => {
    // Suppress console.error for this test
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => {
      renderHook(() => useAuth());
    }).toThrow('useAuth must be used inside AuthProvider');

    consoleSpy.mockRestore();
  });

  it('should start with loading state and not authenticated', () => {
    const { result } = renderHook(() => useAuth(), { wrapper });

    // Initially should be loading (before auth check completes)
    expect(result.current.loading).toBe(true);
    expect(result.current.isAuthenticated).toBe(false);
  });

  it('should handle successful login', async () => {
    vi.mocked(authApi.login).mockResolvedValue(undefined);

    const { result } = renderHook(() => useAuth(), { wrapper });

    // Wait for initial auth check to complete
    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    // Perform login
    await result.current.login('test@example.com', 'password123');

    // Verify login was called
    expect(authApi.login).toHaveBeenCalledWith('test@example.com', 'password123');
    expect(result.current.isAuthenticated).toBe(true);
  });

  it('should handle login failure', async () => {
    vi.mocked(authApi.login).mockRejectedValue(new Error('Invalid credentials'));

    const { result } = renderHook(() => useAuth(), { wrapper });

    // Wait for initial auth check to complete
    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    // Attempt login and expect it to throw
    await expect(
      result.current.login('test@example.com', 'wrongpassword')
    ).rejects.toThrow('Invalid credentials');

    // Should still be not authenticated after failed login
    expect(result.current.isAuthenticated).toBe(false);
  });

  it('should handle successful registration without auto-login', async () => {
    // Registration creates the account but must NOT authenticate — email
    // verification is required first (RegisterPage routes to /verify-email).
    vi.mocked(authApi.register).mockResolvedValue(undefined);
    vi.mocked(authApi.login).mockResolvedValue(undefined);

    const { result } = renderHook(() => useAuth(), { wrapper });

    // Wait for initial auth check to complete
    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    // Perform registration
    await result.current.register('newuser@example.com', 'password123');

    // register was called, but login must NOT be (verification still pending)
    expect(authApi.register).toHaveBeenCalledWith({
      email: 'newuser@example.com',
      password: 'password123',
    });
    expect(authApi.login).not.toHaveBeenCalled();
    expect(result.current.isAuthenticated).toBe(false);
  });

  it('should handle logout', async () => {
    vi.mocked(authApi.logout).mockResolvedValue(undefined);

    const { result } = renderHook(() => useAuth(), { wrapper });

    // Wait for initial auth check to complete and simulate being authenticated
    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });
    // Manually set to authenticated state for this test
    result.current.setIsAuthenticated(true);

    // Perform logout
    await result.current.logout();

    // Verify logout was called
    expect(authApi.logout).toHaveBeenCalled();
    expect(result.current.isAuthenticated).toBe(false);
  });

  it('should handle token refresh on mount', async () => {
    vi.mocked(authApi.refresh).mockResolvedValue(undefined);

    const { result } = renderHook(() => useAuth(), { wrapper });

    // Wait for auth check to complete
    await waitFor(() => {
      expect(result.current.loading).toBe(false);
      expect(result.current.isAuthenticated).toBe(true);
    });

    // Verify refresh was called
    expect(authApi.refresh).toHaveBeenCalled();
  });

  it('should handle failed token refresh on mount', async () => {
    vi.mocked(authApi.refresh).mockRejectedValue(new Error('Token expired'));

    const { result } = renderHook(() => useAuth(), { wrapper });

    // Wait for auth check to complete
    await waitFor(() => {
      expect(result.current.loading).toBe(false);
      expect(result.current.isAuthenticated).toBe(false);
    });

    // Verify refresh was called
    expect(authApi.refresh).toHaveBeenCalled();
  });
});