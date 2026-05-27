import apiClient from './client';

export interface OrgMember {
  _id: string;
  userId: { _id: string; email: string; name?: string };
  role: 'owner' | 'admin' | 'viewer';
  status: 'active' | 'pending';
  inviteEmail?: string;
  createdAt: string;
}

/** GET /orgs/:orgId/members — get all members of an organization */
export async function listMembers(orgId: string): Promise<OrgMember[]> {
  const { data } = await apiClient.get<OrgMember[]>(`/orgs/${orgId}/members`);
  return data;
}

/** POST /orgs/:orgId/members/invite — invite a new member */
export async function inviteMember(
  orgId: string,
  inviteData: { email: string; role: 'admin' | 'viewer' }
): Promise<void> {
  await apiClient.post(`/orgs/${orgId}/members/invite`, inviteData);
}

/** DELETE /orgs/:orgId/members/:userId — remove a member */
export async function removeMember(orgId: string, userId: string): Promise<void> {
  await apiClient.delete(`/orgs/${orgId}/members/${userId}`);
}

/** PATCH /orgs/:orgId/members/:userId/role — update member role */
export async function updateMemberRole(
  orgId: string,
  userId: string,
  role: 'admin' | 'viewer'
): Promise<void> {
  await apiClient.patch(`/orgs/${orgId}/members/${userId}/role`, { role });
}
