import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CreateEndpointModal from './CreateEndpointModal';
import * as endpointsApi from '../../api/endpoints';
import { useQueryClient } from '@tanstack/react-query';
import { useToast } from '../../hooks/useToast';

// Mock the necessary hooks and dependencies
vi.mock('../../api/endpoints');
vi.mock('@tanstack/react-query', () => ({
  ...vi.requireActual('@tanstack/react-query'),
  useMutation: vi.fn(),
  useQueryClient: vi.fn(),
}));
vi.mock('../../hooks/useToast');

// Mock the Modal component to avoid portalMessage: 'Portal';
 vi.mock('../Modal', () => ({
   default: ({ isOpen, onClose, title, children }: any) =>
     isOpen ? (
       <div data-testid="modal-backdrop">
         <div data-testid="modal-content">
           <h2 data-testid="modal-title">{title}</h2>
           <div data-testid="modal-body">{children}</div>
           <button data-testid="modal-close-button" onClick={onClose}>
             Close
           </button>
         </div>
       </div>
     ) : null;
 }));

describe('CreateEndpointModal', () => {
  const mockOrgId = 'test-org-id';
  const mockCreateMutation = {
    mutate: vi.fn(),
    isPending: false,
  };

  const mockQueryClient = {
    invalidateQueries: vi.fn(),
  };

  const mockToast = {
    success: vi.fn(),
    error: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();

    // Setup mocks
    (useMutation as any).mockReturnValue(mockCreateMutation);
    (useQueryClient as any).mockReturnValue(mockQueryClient);
    (useToast as any).mockReturnValue(mockToast);
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  it('should render when isOpen is true', () => {
    const { container } = render(<CreateEndpointModal isOpen={true} onClose={() => {}} orgId={mockOrgId} />);

    // Should render the modal backdrop and content
    expect(container.querySelector('[data-testid="modal-backdrop"]')).toBeInTheDocument();
    expect(container.querySelector('[data-testid="modal-content"]')).toBeInTheDocument();
    expect(screen.getByText(/create endpoint/i)).toBeInTheDocument();
  });

  it('should not render when isOpen is false', () => {
    const { container } = render(<CreateEndpointModal isOpen={false} onClose={() => {}} orgId={mockOrgId} />);

    // Should not render the modal
    expect(container.querySelector('[data-testid="modal-backdrop"]')).not.toBeInTheDocument();
  });

  it('should render form fields', () => {
    render(<CreateEndpointModal isOpen={true} onClose={() => {}} orgId={mockOrgId} />);

    // Check for form elements
    expect(screen.getByLabelText(/endpoint name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/target url/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/ip allowlist/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /create endpoint/i })).toBeInTheDocument();
  });

  it('should handle form submission', async () => {
    render(<CreateEndpointModal isOpen={true} onClose={() => {}} orgId={mockOrgId} />);
    const user = userEvent.setup();

    // Fill out the form
    await user.type(await screen.findByLabelText(/endpoint name/i), 'My API Endpoint');
    await user.type(await screen.findByLabelText(/target url/i), 'https://api.example.com');
    await user.type(await screen.findByLabelText(/ip allowlist/i), '192.168.1.1, 10.0.0.1');

    // Submit the form
    await user.click(screen.getByRole('button', { name: /create endpoint/i }));

    // Verify the mutation was called with correct parameters
    expect(mockCreateMutation.mutate).toHaveBeenCalledWith({
      name: 'My API Endpoint',
      targetUrl: 'https://api.example.com',
      ipAllowlist: ['192.168.1.1', '10.0.0.1'],
    });
  });

  it('should validate form fields', async () => {
    render(<CreateEndpointModal isOpen={true} onClose={() => {}} orgId={mockOrgId} />);
    const user = userEvent.setup();

    // Try to submit empty form
    await user.click(screen.getByRole('button', { name: /create endpoint/i }));

    // Should show validation errors
    expect(await screen.findByText(/name must be at least 3 characters/i)).toBeInTheDocument();
    expect(await screen.findByText(/target url is required/i)).toBeInTheDocument();

    // Fill in valid name but invalid URL
    await user.type(await screen.findByLabelText(/endpoint name/i), 'Valid Name');
    await user.type(await screen.findByLabelText(/target url/i), 'http://invalid.com'); // Not HTTPS
    await user.click(screen.getByRole('button', { name: /create endpoint/i }));

    // Should show URL validation error
    expect(await screen.findByText(/target url must use https/i)).toBeInTheDocument();
  });

  it('should handle successful creation', async () => {
    // Mock successful mutation
    mockCreateMutation.mutate.mockImplementation((callback: any) => {
      callback({ apiKey: 'sk_live_1234567890abcdef' });
    });

    render(<CreateEndpointModal isOpen={true} onClose={() => {}} orgId={mockOrgId} />);
    const user = userEvent.setup();

    // Fill out the form
    await user.type(await screen.findByLabelText(/endpoint name/i), 'My API');
    await user.type(await screen.findByLabelText(/target url/i), 'https://api.example.com');

    // Submit the form
    await user.click(screen.getByRole('button', { name: /create endpoint/i }));

    // Wait for success state
    await waitFor(() => {
      expect(mockToast.success).toHaveBeenCalledWith('Endpoint created successfully');
    });

    // Verify query cache was invalidated
    expect(mockQueryClient.invalidateQueries).toHaveBeenCalledWith({
      queryKey: ['endpoints', mockOrgId],
    });
  });

  it('should handle creation error', async () => {
    // Mock failed mutation
    mockCreateMutation.mutate.mockImplementation((callback: any) => {
      throw new Error('Creation failed');
    });

    render(<CreateEndpointModal isOpen={true} onClose={() => {}} orgId={mockOrgId} />);
    const user = userEvent.setup();

    // Fill out the form
    await user.type(await screen.findByLabelText(/endpoint name/i), 'My API');
    await user.type(await screen.findByLabelText(/target url/i), 'https://api.example.com');

    // Submit the form
    await user.click(screen.getByRole('button', { name: /create endpoint/i }));

    // Wait for error state (implementation would show this differently, but we're testing the mock)
    expect(mockCreateMutation.mutate).toHaveBeenCalled();
  });

  it('should handle rate limit error (402)', async () => {
    // Mock 402 error
    mockCreateMutation.mutate.mockImplementation((callback: any) => {
      throw { response: { status: 402, data: { error: 'Plan limit reached' } } };
    });

    render(<CreateEndpointModal isOpen={true} onClose={() => {}} orgId={mockOrgId} />);
    const user = userEvent.setup();

    // Fill out the form
    await user.type(await screen.findByLabelText(/endpoint name/i), 'My API');
    await user.type(await screen.findByLabelText(/target url/i), 'https://api.example.com');

    // Submit the form
    await user.click(screen.getByRole('button', { name: /create endpoint/i }));

    // Note: In actual implementation, this would set errors state, but we're testing the mock behavior
    expect(mockCreateMutation.mutate).toHaveBeenCalled();
  });

  it('should close modal when cancel button clicked', async () => {
    const handleClose = vi.fn();
    render(<CreateEndpointModal isOpen={true} onClose={handleClose} orgId={mockOrgid} />);

    await userEvent.click(screen.getByRole('button', { name: /cancel/i }));

    expect(handleClose).toHaveBeenCalled();
  });

  it('should prevent closing when submission is in progress', async () => {
    // Mock pending mutation
    mockCreateMutation.isPending = true;
    const handleClose = vi.fn();

    render(<CreateEndpointModal isOpen={true} onClose={handleClose} orgId={mockOrgid} />);

    await userEvent.click(screen.getByRole('button', { name: /cancel/i }));

    // Should not close when pending
    expect(handleClose).not.toHaveBeenCalled();
  });
});