import { describe, it, expect, beforeEach, vi } from 'vitest';
import { login, register, logout, refresh } from './auth';
import apiClient, { setToken } from './client';

vi.mock('./client', () => ({
  default: {
    post: vi.fn(),
    get: vi.fn(),
  },
  setToken: vi.fn(),
  getToken: vi.fn(),
}));

describe('Auth API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('login', () => {
    it('should call POST /auth/login and store token', async () => {
      const mockResponse = {
        data: {
          accessToken: 'test-token-123',
        },
      };
      
      vi.mocked(apiClient.post).mockResolvedValue(mockResponse);

      await login('test@example.com', 'password123');

      expect(apiClient.post).toHaveBeenCalledWith('/auth/login', {
        email: 'test@example.com',
        password: 'password123',
      });
      expect(setToken).toHaveBeenCalledWith('test-token-123');
    });

    it('should throw error on failed login', async () => {
      vi.mocked(apiClient.post).mockRejectedValue(new Error('Invalid credentials'));

      await expect(login('test@example.com', 'wrong')).rejects.toThrow('Invalid credentials');
    });
  });

  describe('register', () => {
    it('should call POST /auth/register with data object', async () => {
      const mockResponse = {
        data: {
          userId: 'user-123',
        },
      };
      
      vi.mocked(apiClient.post).mockResolvedValue(mockResponse);

      const result = await register({ email: 'test@example.com', password: 'password123' });

      expect(apiClient.post).toHaveBeenCalledWith('/auth/register', {
        email: 'test@example.com',
        password: 'password123',
      });
      expect(result).toEqual({ userId: 'user-123' });
    });
  });

  describe('logout', () => {
    it('should call POST /auth/logout and clear token', async () => {
      const mockResponse = { data: {} };
      vi.mocked(apiClient.post).mockResolvedValue(mockResponse);

      await logout();

      expect(apiClient.post).toHaveBeenCalledWith('/auth/logout');
      expect(setToken).toHaveBeenCalledWith(null);
    });
  });

  describe('refresh', () => {
    it('should call POST /auth/refresh and store new token', async () => {
      const mockResponse = {
        data: { accessToken: 'new-token-456' },
      };
      vi.mocked(apiClient.post).mockResolvedValue(mockResponse);

      await refresh();

      expect(apiClient.post).toHaveBeenCalledWith('/auth/refresh');
      expect(setToken).toHaveBeenCalledWith('new-token-456');
    });
  });
});
