import apiClient from './client';

export interface Endpoint {
  _id: string;
  name: string;
  targetUrl: string;
  proxySlug: string;
  isActive: boolean;
  requestCount: number;
  ipAllowlist: string[];
  createdAt: string;
}

export interface CreateEndpointRequest {
  name: string;
  targetUrl: string;
  ipAllowlist?: string[];
}

export interface CreateEndpointResponse extends Endpoint {
  apiKey: string;
  proxyUrl: string;
}

/** GET /orgs/:orgId/endpoints — list all endpoints for an organization */
export async function listEndpoints(orgId: string): Promise<Endpoint[]> {
  const { data } = await apiClient.get<Endpoint[]>(`/orgs/${orgId}/endpoints`);
  return data;
}

/** GET /orgs/:orgId/endpoints/:endpointId — get a single endpoint */
export async function getEndpoint(orgId: string, endpointId: string): Promise<Endpoint> {
  const { data } = await apiClient.get<Endpoint>(`/orgs/${orgId}/endpoints/${endpointId}`);
  return data;
}

/** POST /orgs/:orgId/endpoints — create a new endpoint */
export async function createEndpoint(
  orgId: string,
  endpointData: CreateEndpointRequest
): Promise<CreateEndpointResponse> {
  const { data } = await apiClient.post<CreateEndpointResponse>(
    `/orgs/${orgId}/endpoints`,
    endpointData
  );
  return data;
}

/** PATCH /orgs/:orgId/endpoints/:endpointId — update an endpoint */
export async function updateEndpoint(
  orgId: string,
  endpointId: string,
  updates: Partial<Endpoint>
): Promise<Endpoint> {
  const { data } = await apiClient.patch<Endpoint>(
    `/orgs/${orgId}/endpoints/${endpointId}`,
    updates
  );
  return data;
}

/** DELETE /orgs/:orgId/endpoints/:endpointId — delete an endpoint */
export async function deleteEndpoint(orgId: string, endpointId: string): Promise<void> {
  await apiClient.delete(`/orgs/${orgId}/endpoints/${endpointId}`);
}

/** POST /orgs/:orgId/endpoints/:endpointId/regenerate-key — regenerate API key */
export async function regenerateApiKey(
  orgId: string,
  endpointId: string
): Promise<{ apiKey: string }> {
  const { data } = await apiClient.post<{ apiKey: string }>(
    `/orgs/${orgId}/endpoints/${endpointId}/regenerate-key`
  );
  return data;
}
