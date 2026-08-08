import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { OrgProvider, useOrg } from './OrgContext';
import * as orgsApi from '../api/orgs';

vi.mock('../api/orgs');

describe('OrgContext', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
      },
    });
  });

  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <OrgProvider>{children}</OrgProvider>
    </QueryClientProvider>
  );

  it('should throw error when used outside OrgProvider', () => {
    // Suppress console.error for this test
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => {
      renderHook(() => useOrg());
    }).toThrow('useOrg must be used inside OrgProvider');

    consoleSpy.mockRestore();
  });

  it('should provide empty orgs array initially', () => {
    vi.mocked(orgsApi.listOrgs).mockResolvedValue([]);

    const { result } = renderHook(() => useOrg(), { wrapper });

    expect(result.current.orgs).toEqual([]);
    expect(result.current.currentOrg).toBeNull();
  });

  it('should load orgs from API', async () => {
    const mockOrgs = [
      { _id: 'org1', name: 'Org 1', slug: 'org-1', plan: 'free' as const, createdAt: '' },
      { _id: 'org2', name: 'Org 2', slug: 'org-2', plan: 'pro' as const, createdAt: '' },
    ];
    vi.mocked(orgsApi.listOrgs).mockResolvedValue(mockOrgs);

    const { result } = renderHook(() => useOrg(), { wrapper });

    await waitFor(() => {
      expect(result.current.orgs).toEqual(mockOrgs);
    });
  });

  it('should auto-select first org when none selected', async () => {
    const mockOrgs = [
      { _id: 'org1', name: 'Org 1', slug: 'org-1', plan: 'free' as const, createdAt: '' },
      { _id: 'org2', name: 'Org 2', slug: 'org-2', plan: 'pro' as const, createdAt: '' },
    ];
    vi.mocked(orgsApi.listOrgs).mockResolvedValue(mockOrgs);

    const { result } = renderHook(() => useOrg(), { wrapper });

    await waitFor(() => {
      expect(result.current.currentOrg).toEqual(mockOrgs[0]);
    });
  });

  it('should allow setting current org', async () => {
    const mockOrgs = [
      { _id: 'org1', name: 'Org 1', slug: 'org-1', plan: 'free' as const, createdAt: '' },
      { _id: 'org2', name: 'Org 2', slug: 'org-2', plan: 'pro' as const, createdAt: '' },
    ];
    vi.mocked(orgsApi.listOrgs).mockResolvedValue(mockOrgs);

    const { result } = renderHook(() => useOrg(), { wrapper });

    await waitFor(() => {
      expect(result.current.currentOrg).toEqual(mockOrgs[0]);
    });

    // Change to second org
    result.current.setCurrentOrg(mockOrgs[1]);

    await waitFor(() => {
      expect(result.current.currentOrg).toEqual(mockOrgs[1]);
    });
  });

  it('should persist current org to sessionStorage', async () => {
    const mockOrgs = [
      { _id: 'org1', name: 'Org 1', slug: 'org-1', plan: 'free' as const, createdAt: '' },
    ];
    vi.mocked(orgsApi.listOrgs).mockResolvedValue(mockOrgs);

    const { result } = renderHook(() => useOrg(), { wrapper });

    await waitFor(() => {
      expect(result.current.currentOrg).toEqual(mockOrgs[0]);
    });

    await waitFor(() => {
      expect(sessionStorage.getItem('currentOrgId')).toBe('org1');
    });
  });

  it('should restore org from sessionStorage', async () => {
    const mockOrgs = [
      { _id: 'org1', name: 'Org 1', slug: 'org-1', plan: 'free' as const, createdAt: '' },
      { _id: 'org2', name: 'Org 2', slug: 'org-2', plan: 'pro' as const, createdAt: '' },
    ];
    vi.mocked(orgsApi.listOrgs).mockResolvedValue(mockOrgs);

    // Pre-set sessionStorage
    sessionStorage.setItem('currentOrgId', 'org2');

    const { result } = renderHook(() => useOrg(), { wrapper });

    await waitFor(() => {
      expect(result.current.currentOrg).toEqual(mockOrgs[1]);
    });
  });
});
