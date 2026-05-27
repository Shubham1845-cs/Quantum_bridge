import apiClient from './client';

export interface Organization {
  _id: string;
  name: string;
  slug: string;
  plan: 'free' | 'pro' | 'enterprise';
  monthlyRequestCount: number;
  createdAt: string;
}

/** GET /orgs — list all organizations the user belongs to */
export async function listOrgs(): Promise<Organization[]> {
  const { data } = await apiClient.get<Organization[]>('/orgs');
  return data;
}

/** GET /orgs/:orgId — get a single organization */
export async function getOrg(orgId: string): Promise<Organization> {
  const { data } = await apiClient.get<Organization>(`/orgs/${orgId}`);
  return data;
}

/** POST /orgs — create a new organization */
export async function createOrg(name: string): Promise<Organization> {
  const { data } = await apiClient.post<Organization>('/orgs', { name });
  return data;
}

/** PATCH /orgs/:orgId — update an organization */
export async function updateOrg(orgId: string, updates: Partial<Organization>): Promise<Organization> {
  const { data } = await apiClient.patch<Organization>(`/orgs/${orgId}`, updates);
  return data;
}

/** DELETE /orgs/:orgId — delete an organization */
export async function deleteOrg(orgId: string): Promise<void> {
  await apiClient.delete(`/orgs/${orgId}`);
}
