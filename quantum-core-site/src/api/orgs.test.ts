import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as orgsApi from './orgs';
import apiClient from './client';

vi.mock('./client');

describe('Orgs API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('listOrgs', () => {
    it('should fetch organizations list', async () => {
      const mockResponse = [
        { _id: 'org1', name: 'Org One', slug: 'org-1', plan: 'free', monthlyRequestCount: 1000, createdAt: '2023-01-01T00:00:00Z' },
        { _id: 'org2', name: 'Org Two', slug: 'org-2', plan: 'pro', monthlyRequestCount: 5000, createdAt: '2023-01-02T00:00:00Z' },
      ];
      vi.mocked(apiClient.get).mockResolvedValue({ data: mockResponse });

      const result = await orgsApi.listOrgs();

      expect(apiClient.get).toHaveBeenCalledWith('/orgs');
      expect(result).toEqual(mockResponse);
    });
  });

  describe('getOrg', () => {
    it('should fetch a single organization', async () => {
      const mockOrgId = 'test-org-id';
      const mockResponse = { _id: mockOrgId, name: 'Test Org', slug: 'test-org', plan: 'pro', monthlyRequestCount: 2500, createdAt: '2023-01-01T00:00:00Z' };
      vi.mocked(apiClient.get).mockResolvedValue({ data: mockResponse });

      const result = await orgsApi.getOrg(mockOrgId);

      expect(apiClient.get).toHaveBeenCalledWith(`/orgs/${mockOrgId}`);
      expect(result).toEqual(mockResponse);
    });
  });

  describe('createOrg', () => {
    it('should create a new organization', async () => {
      const mockResponse = { _id: 'new-org', name: 'New Org', slug: 'new-org', plan: 'free', monthlyRequestCount: 0, createdAt: '2023-01-01T00:00:00Z' };
      vi.mocked(apiClient.post).mockResolvedValue({ data: mockResponse });

      const result = await orgsApi.createOrg('New Org');

      expect(apiClient.post).toHaveBeenCalledWith('/orgs', { name: 'New Org' });
      expect(result).toEqual(mockResponse);
    });
  });

  describe('updateOrg', () => {
    it('should update an organization', async () => {
      const mockOrgId = 'test-org-id';
      const mockUpdates = { name: 'Updated Org Name' };
      const mockResponse = { _id: mockOrgId, name: 'Updated Org Name', slug: 'updated-org', plan: 'pro', monthlyRequestCount: 3000, createdAt: '2023-01-01T00:00:00Z' };
      vi.mocked(apiClient.patch).mockResolvedValue({ data: mockResponse });

      const result = await orgsApi.updateOrg(mockOrgId, mockUpdates);

      expect(apiClient.patch).toHaveBeenCalledWith(`/orgs/${mockOrgId}`, mockUpdates);
      expect(result).toEqual(mockResponse);
    });
  });

  describe('deleteOrg', () => {
    it('should delete an organization', async () => {
      const mockOrgId = 'test-org-id';
      vi.mocked(apiClient.delete).mockResolvedValue(undefined);

      await orgsApi.deleteOrg(mockOrgId);

      expect(apiClient.delete).toHaveBeenCalledWith(`/orgs/${mockOrgId}`);
    });
  });
});