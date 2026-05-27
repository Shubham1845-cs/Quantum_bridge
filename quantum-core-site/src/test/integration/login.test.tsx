import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../test-utils';
import userEvent from '@testing-library/user-event';
import LoginPage from '../../pages/LoginPage';
import * as authApi from '../../api/auth';
import * as client from '../../api/client';

vi.mock('../../api/auth');
vi.mock('../../api/client');

describe('Login Flow Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Mock setToken and getToken
    vi.mocked(client.setToken).mockImplementation(() => {});
    vi.mocked(client.getToken).mockReturnValue(null);
    // Mock refresh to resolve immediately so AuthProvider doesn't error
    vi.mocked(authApi.refresh).mockResolvedValue(undefined);
  });

  it('should successfully login with valid credentials', async () => {
    const user = userEvent.setup();
    
    vi.mocked(authApi.login).mockResolvedValue(undefined);

    render(<LoginPage />);

    // Fill in the form - use actual placeholder text
    const emailInput = screen.getByPlaceholderText('you@company.com');
    const passwordInput = screen.getByPlaceholderText('••••••••');
    const submitButton = screen.getByRole('button', { name: /sign in/i });

    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'password123');
    await user.click(submitButton);

    // Wait for the API call
    await waitFor(() => {
      expect(authApi.login).toHaveBeenCalledWith('test@example.com', 'password123');
    });
  });

  it('should show error message on failed login', async () => {
    const user = userEvent.setup();
    
    vi.mocked(authApi.login).mockRejectedValue(new Error('Invalid credentials'));

    render(<LoginPage />);

    const emailInput = screen.getByPlaceholderText('you@company.com');
    const passwordInput = screen.getByPlaceholderText('••••••••');
    const submitButton = screen.getByRole('button', { name: /sign in/i });

    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'wrongpassword');
    await user.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument();
    });
  });

  it('should disable submit button while loading', async () => {
    const user = userEvent.setup();
    
    vi.mocked(authApi.login).mockImplementation(
      () => new Promise((resolve) => setTimeout(resolve, 1000))
    );

    render(<LoginPage />);

    const emailInput = screen.getByPlaceholderText('you@company.com');
    const passwordInput = screen.getByPlaceholderText('••••••••');
    const submitButton = screen.getByRole('button', { name: /sign in/i });

    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'password123');
    await user.click(submitButton);

    expect(submitButton).toBeDisabled();
  });
});
