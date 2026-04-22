/**
 * useOrg — resolves the active organization ID.
 * Fetches the user's orgs on first call and stores the first one.
 */
import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../lib/apiClient';
import { useOrgStore } from '../store/orgStore';

interface OrgSummary {
  _id: string;
  name: string;
  slug: string;
  plan: string;
}

export function useOrg() {
  const { orgId, setOrgId } = useOrgStore();

  const { data: orgs } = useQuery<OrgSummary[]>({
    queryKey: ['orgs'],
    queryFn: () => apiClient.get('/orgs').then((r) => r.data),
    enabled: !orgId,
    staleTime: 5 * 60 * 1000,
  });

  useEffect(() => {
    if (!orgId && orgs && orgs.length > 0) {
      setOrgId(orgs[0]._id);
    }
  }, [orgs, orgId, setOrgId]);

  return { orgId };
}
