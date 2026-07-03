import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import RegisterForm from './RegisterForm';
import * as authApi from '../../api/auth';
import { useAuth } from '../../context/AuthContext';

// Mock the auth hook
vi.mock('../../context/AuthContext');
// Mock toast hook
vi.mock('../../hooks/useToast');
// Mock useNavigate
vi.mock('react-router-dom', () => ({
  ...vi.requireActual('react-router-dom'),
  useNavigate: vi.fn(),
}));

describe('RegisterForm', () => {
  const mockRegister = vi.fn();
  const mockNavigate = vi.fn();
  const mockToast = { success: vi.fn() };

  beforeEach(() => {
    vi.clearAllMocks();
    // Setup mocks
    (useAuth as any).mockReturnValue({ register: mockRegister });
    (useToast as any).mockReturnValue(mockToast);
    // @ts-ignore
    require('react-router-dom').useNavigate.mockReturnValue(mockNavigate);
  });

  afterEach(() => {
    cleanup();
  });

  it('should render correctly', () => {
    render(<RegisterForm />);

    // Check for form elements
    expect(screen.getByPlaceholderText(/you@example.com/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/••••••••/)).toBeInTheDocument(); // Password
    expect(screen.getByPlaceholderText(/••••••••/)).toBeInTheDocument(); // Confirm Password
    expect(screen.getByRole('button', { name: /create account/i })).toBeInTheDocument();
  });

  it('should show password strength indicator', () => {
    render(<RegisterForm />);

    const passwordInput = screen.getByPlaceholderText(/••••••••/).closest('div');
    expect(passwordInput).toContainHTML('Password strength:');
  });

  it('should handle successful registration', async () => {
    mockRegister.mockResolvedValue(undefined);

    render(<RegisterForm />);
    const user = userEvent.setup();

    const emailInput = screen.getByPlaceholderText(/you@example.com/i);
    const passwordInput = screen.getByPlaceholderText(/••••••••/); // First password field
    const confirmPasswordInput = screen.getByPlaceholderText(/••••••••/); // Second password field
    const submitButton = screen.getByRole('button', { name: /create account/i });

    // Fill out the form
    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'securepassword123');
    await user.type(confirmPasswordInput, 'securepassword123');

    // Verify button is enabled
    expect(submitButton).toBeEnabled();

    // Submit the form
    await user.click(submitButton);

    // Verify register was called with correct parameters
    expect(mockRegister).toHaveBeenCalledWith('test@example.com', 'securepassword123');

    // Verify success toast was shown
    expect(mockToast.success).toHaveBeenCalledWith(
      'Registration successful! Please check your email to verify your account.'
    );

    // Verify navigation to dashboard
    expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
  });

  it('should show error for weak password', async () => {
    render(<RegisterForm />);
    const user = userEvent.setup();

    const emailInput = screen.getByPlaceholderText(/you@example.com/i);
    const passwordInput = screen.getByPlaceholderText(/••••••••/);
    const confirmPasswordInput = screen.getByPlaceholderText(/••••••••/);
    const submitButton = screen.getByRole('button', { name: /create account/i });

    // Fill out the form with weak password
    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, '123'); // Too short
    await user.type(confirmPasswordInput, '123');

    // Submit the form
    await user.click(submitButton);

    // Should show password validation error
    expect(await screen.findByText(/password must be at least 8 characters/i)).toBeInTheDocument();

    // Register should not have been called
    expect(mockRegister).not.toHaveBeenCalled();
  });

  it('should show error for mismatched passwords', async () => {
    render(<RegisterForm />);
    const user = userEvent.setup();

    const emailInput = screen.getByPlaceholderText(/you@example.com/i);
    const passwordInput = screen.getByPlaceholderText(/••••••••/);
    const confirmPasswordInput = screen.getByPlaceholderText(/••••••••/);
    const submitButton = screen.getByRole('button', { name: /create account/i });

    // Fill out the form with mismatched passwords
    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'password123');
    await user.type(confirmPasswordInput, 'differentpassword');

    // Submit the form
    await user.click(submitButton);

    // Should show password mismatch error
    expect(await screen.findByText(/passwords do not match/i)).toBeInTheDocument();

    // Register should not have been called
    expect(mockRegister).not.toHaveBeenCalled();
  });

  it('should show error for existing email', async () => {
    // Mock registration failure due to existing email
    mockMockRejectedValueOnce(
      { response: { status: 409, data: { error: 'Conflict' } } }
    );

    render(<RegisterForm />);
    const user = userEvent.setup();

    const emailInput = screen.getByPlaceholderText(/you@example.com/i);
    const passwordInput = screen.getByPlaceholderText(/••••••••/);
    const confirmPasswordInput = screen.getByPlaceholderText(/••••••••/);
    const submitButton = screen.getByRole('button', { name: /create account/i });

    // Fill out the form
    await user.type(emailInput, 'existing@example.com');
    await user.type(passwordInput, 'password123');
    await user.type(confirmPasswordInput, 'password123');

    // Submit the form
    await user.click(submitButton);

    // Should show email exists error
    expect(await screen.findByText(/an account with this email already exists/i)).toBeInTheDocument();

    // Register should have been called
    expect(mockRegister).toHaveBeenCalledWith('existing@example.com', 'password123');
  });

  it('should show loading state during submission', async () => {
    // Make the request take time
    mockRegister.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 100)));

    render(<RegisterForm />);
    const user = userEvent.setup();

    const emailInput = screen.getByPlaceholderText(/you@example.com/i);
    const passwordInput = screen.getByPlaceholderText(/••••••••/);
    const confirmPasswordInput = screen.getByPlaceholderText(/••••••••/);
    const submitButton = screen.getByRole('button', { name: /create account/i });

    // Fill out the form
    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'password123');
    await user.type(confirmPasswordInput, 'password123');

    // Click submit and quickly check for loading state
    await user.click(submitButton);

    // Button should be disabled during loading
    expect(await screen.findByRole('button', { name: /creating account/i, disabled: true })).toBeInTheDocument();

    // Wait for completion
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
    });
  });
});