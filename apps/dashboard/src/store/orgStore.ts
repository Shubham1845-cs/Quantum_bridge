/**
 * Minimal org store — holds the currently selected organization ID.
 * The first org returned from GET /orgs is used as the active org.
 */
import { create } from 'zustand';

interface OrgState {
  orgId: string | null;
  setOrgId: (id: string) => void;
}

export const useOrgStore = create<OrgState>((set) => ({
  orgId: null,
  setOrgId: (id) => set({ orgId: id }),
}));
