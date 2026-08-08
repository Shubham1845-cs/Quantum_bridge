import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '../../test/test-utils';
import ProtectedRoute from '../ProtectedRoute';
import * as authApi from '../../api/auth';

vi.mock('../../api/auth');

describe('ProtectedRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Mock refresh to resolve immediately so AuthProvider doesn't error
    vi.mocked(authApi.refresh).mockResolvedValue(undefined);
  });

  it('should render children when authenticated', async () => {
    // Mock successful authentication
    vi.mocked(authApi.refresh).mockResolvedValue(undefined);

    render(
      <ProtectedRoute>
        <div>Protected Content</div>
      </ProtectedRoute>
    );

    // Wait for the auth check to complete and content to render
    const content = await screen.findByText('Protected Content');
    expect(content).toBeInTheDocument();
  });

  it('should show loading spinner when loading', () => {
    // Mock refresh to never resolve (keeps loading state)
    vi.mocked(authApi.refresh).mockImplementation(
      () => new Promise(() => {}) // Never resolves
    );

    render(
      <ProtectedRoute>
        <div>Protected Content</div>
      </ProtectedRoute>
    );

    expect(screen.getByText(/authenticating/i)).toBeInTheDocument();
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
  });

  it('should redirect to login when not authenticated', async () => {
    // Mock failed authentication
    vi.mocked(authApi.refresh).mockRejectedValue(new Error('Unauthorized'));

    render(
      <ProtectedRoute>
        <div>Protected Content</div>
      </ProtectedRoute>
    );

    // Should not render protected content
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
  });
});
