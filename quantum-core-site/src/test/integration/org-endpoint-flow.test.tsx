import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../test-utils';
import userEvent from '@testing-library/user-event';
import CreateOrgModal from '../../components/modals/CreateOrgModal';
import CreateEndpointModal from '../../components/modals/CreateEndpointModal';
import * as orgsApi from '../../api/orgs';
import * as endpointsApi from '../../api/endpoints';

vi.mock('../../api/orgs');
vi.mock('../../api/endpoints');

describe('Organization → Endpoint Creation Flow', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should create an organization then create an endpoint for it', async () => {
    const user = userEvent.setup();

    // Mock successful organization creation
    const mockOrg = { _id: 'org-123', name: 'Test Org', slug: 'test-org', plan: 'free', monthlyRequestCount: 0, createdAt: '' };
    vi.mocked(orgsApi.createOrg).mockResolvedValue(mockOrg);

    // Mock successful endpoint creation
    const mockEndpoint = {
      _id: 'ep-456',
      name: 'Test Endpoint',
      targetUrl: 'https://api.example.com',
      apiKey: 'sk_live_1234567890abcdef',
      orgId: 'org-123',
      createdAt: ''
    };
    vi.mocked(endpointsApi.createEndpoint).mockResolvedValue(mockEndpoint);

    // Step 1: Create organization
    render(<CreateOrgModal isOpen={true} onClose={vi.fn()} />);

    await user.type(await screen.findByLabelText(/organization name/i), 'Test Org');
    await user.click(screen.getByRole('button', { name: /create organization/i }));

    await waitFor(() => {
      expect(orgsApi.createOrg).toHaveBeenCalledWith({ name: 'Test Org' });
    });

    // Step 2: Create endpoint for the organization
    render(<CreateEndpointModal isOpen={true} onClose={vi.fn()} orgId="org-123" />);

    await user.type(await screen.findByLabelText(/endpoint name/i), 'Test Endpoint');
    await user.type(await screen.findByLabelText(/target url/i), 'https://api.example.com');
    await user.click(screen.getByRole('button', { name: /create endpoint/i }));

    await waitFor(() => {
      expect(endpointsApi.createEndpoint).toHaveBeenCalledWith('org-123', {
        name: 'Test Endpoint',
        targetUrl: 'https://api.example.com',
        ipAllowlist: undefined,
      });
    });
  });
});