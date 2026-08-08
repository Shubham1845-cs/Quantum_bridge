import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { listOrgs, Organization } from '../api/orgs';

interface OrgContextValue {
  currentOrg: Organization | null;
  orgs: Organization[];
  setCurrentOrg: (org: Organization) => void;
  loading: boolean;
}

const OrgContext = createContext<OrgContextValue | null>(null);

export function OrgProvider({ children }: { children: ReactNode }) {
  const [currentOrg, setCurrentOrg] = useState<Organization | null>(null);
  
  const { data: orgs = [], isLoading } = useQuery({
    queryKey: ['orgs'],
    queryFn: listOrgs,
  });

  // Auto-select first org if none selected
  useEffect(() => {
    if (!currentOrg && orgs.length > 0 && !isLoading) {
      console.log('[OrgContext] Auto-selecting organization...');
      const savedOrgId = sessionStorage.getItem('currentOrgId');
      const org = savedOrgId 
        ? orgs.find(o => o._id === savedOrgId) || orgs[0]
        : orgs[0];
      console.log('[OrgContext] Selected org:', org.name);
      setCurrentOrg(org);
    }
  }, [orgs, currentOrg, isLoading]);

  // Persist selection
  useEffect(() => {
    if (currentOrg) {
      sessionStorage.setItem('currentOrgId', currentOrg._id);
    }
  }, [currentOrg]);

  return (
    <OrgContext.Provider value={{ currentOrg, orgs, setCurrentOrg, loading: isLoading }}>
      {children}
    </OrgContext.Provider>
  );
}

export function useOrg(): OrgContextValue {
  const ctx = useContext(OrgContext);
  if (!ctx) throw new Error('useOrg must be used inside OrgProvider');
  return ctx;
}
