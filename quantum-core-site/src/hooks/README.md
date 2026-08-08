# Custom React Query Hooks

This directory contains custom React Query hooks that wrap the API client functions for better state management and caching.

## Available Hooks

### useEndpoints.ts
Hooks for managing endpoints:
- `useEndpoints(orgId)` - Fetch all endpoints for an organization
- `useEndpoint(orgId, endpointId)` - Fetch a single endpoint
- `useCreateEndpoint(orgId)` - Create a new endpoint
- `useUpdateEndpoint(orgId, endpointId)` - Update an endpoint
- `useDeleteEndpoint(orgId)` - Delete an endpoint
- `useRegenerateApiKey(orgId, endpointId)` - Regenerate API key

**Example Usage:**
```typescript
import { useEndpoints, useCreateEndpoint } from '@/hooks';

function EndpointsPage() {
  const { data: endpoints, isLoading } = useEndpoints(orgId);
  const createMutation = useCreateEndpoint(orgId);

  const handleCreate = async (data) => {
    await createMutation.mutateAsync(data);
  };

  return (
    <div>
      {endpoints?.map(endpoint => (
        <div key={endpoint._id}>{endpoint.name}</div>
      ))}
    </div>
  );
}
```

### useAnalytics.ts
Hooks for analytics and logging:
- `useAnalyticsSummary(orgId, options?)` - Fetch summary metrics
- `useTimeseries(orgId, params)` - Fetch timeseries data for charts
- `useProxyLogs(orgId, params?)` - Fetch proxy logs with pagination
- `exportLogsAsCSV(orgId)` - Export logs as CSV (utility function)

**Example Usage:**
```typescript
import { useAnalyticsSummary, useProxyLogs } from '@/hooks';

function AnalyticsPage() {
  // Auto-refresh every 30 seconds
  const { data: summary } = useAnalyticsSummary(orgId, { refetchInterval: 30000 });
  
  const { data: logs } = useProxyLogs(orgId, { 
    page: 1, 
    threatFlag: true 
  });

  return (
    <div>
      <p>Requests Today: {summary?.requestsToday}</p>
      <p>Threats: {summary?.threatsToday}</p>
    </div>
  );
}
```

### useKeys.ts
Hooks for key management:
- `useKeys(orgId)` - Fetch all key versions
- `useRotateKeys(orgId)` - Manually rotate keys

**Example Usage:**
```typescript
import { useKeys, useRotateKeys } from '@/hooks';

function KeysPage() {
  const { data: keys } = useKeys(orgId);
  const rotateMutation = useRotateKeys(orgId);

  const handleRotate = async () => {
    await rotateMutation.mutateAsync();
  };

  return (
    <div>
      {keys?.map(key => (
        <div key={key.version}>Version {key.version}</div>
      ))}
      <button onClick={handleRotate}>Rotate Keys</button>
    </div>
  );
}
```

### useWebhooks.ts
Hooks for webhook management:
- `useWebhooks(orgId)` - Fetch all webhooks
- `useWebhookDeliveries(orgId, webhookId)` - Fetch delivery log
- `useCreateWebhook(orgId)` - Create a new webhook
- `useDeleteWebhook(orgId)` - Delete a webhook

**Example Usage:**
```typescript
import { useWebhooks, useCreateWebhook } from '@/hooks';

function WebhooksPage() {
  const { data: webhooks } = useWebhooks(orgId);
  const createMutation = useCreateWebhook(orgId);

  const handleCreate = async (url: string) => {
    await createMutation.mutateAsync(url);
  };

  return (
    <div>
      {webhooks?.map(webhook => (
        <div key={webhook._id}>{webhook.url}</div>
      ))}
    </div>
  );
}
```

### useTeam.ts
Hooks for team management:
- `useTeamMembers(orgId)` - Fetch all team members
- `useInviteMember(orgId)` - Invite a new member
- `useRemoveMember(orgId)` - Remove a member
- `useUpdateMemberRole(orgId)` - Update member role

**Example Usage:**
```typescript
import { useTeamMembers, useInviteMember } from '@/hooks';

function TeamPage() {
  const { data: members } = useTeamMembers(orgId);
  const inviteMutation = useInviteMember(orgId);

  const handleInvite = async (email: string, role: 'admin' | 'viewer') => {
    await inviteMutation.mutateAsync({ email, role });
  };

  return (
    <div>
      {members?.map(member => (
        <div key={member._id}>{member.userId.email}</div>
      ))}
    </div>
  );
}
```

## Query Key Management

Each hook module exports a query key factory for consistent cache management:

- `endpointKeys` - Keys for endpoint queries
- `analyticsKeys` - Keys for analytics queries
- `keyKeys` - Keys for key management queries
- `webhookKeys` - Keys for webhook queries
- `teamKeys` - Keys for team queries

These can be used for manual cache invalidation or prefetching:

```typescript
import { endpointKeys } from '@/hooks';
import { useQueryClient } from '@tanstack/react-query';

function MyComponent() {
  const queryClient = useQueryClient();

  // Manually invalidate endpoint list
  queryClient.invalidateQueries({ queryKey: endpointKeys.list(orgId) });

  // Prefetch endpoint detail
  queryClient.prefetchQuery({
    queryKey: endpointKeys.detail(orgId, endpointId),
    queryFn: () => getEndpoint(orgId, endpointId),
  });
}
```

## Best Practices

1. **Always provide orgId**: Most hooks require an orgId parameter. Ensure it's available before using the hook.

2. **Handle loading states**: All query hooks return `isLoading` and `error` states. Always handle these in your UI.

3. **Use mutation callbacks**: Mutation hooks support `onSuccess`, `onError`, and `onSettled` callbacks for side effects.

4. **Optimistic updates**: For better UX, consider implementing optimistic updates using `onMutate`:

```typescript
const updateMutation = useUpdateEndpoint(orgId, endpointId);

updateMutation.mutate(updates, {
  onMutate: async (newData) => {
    // Cancel outgoing refetches
    await queryClient.cancelQueries({ queryKey: endpointKeys.detail(orgId, endpointId) });
    
    // Snapshot previous value
    const previous = queryClient.getQueryData(endpointKeys.detail(orgId, endpointId));
    
    // Optimistically update
    queryClient.setQueryData(endpointKeys.detail(orgId, endpointId), newData);
    
    return { previous };
  },
  onError: (err, newData, context) => {
    // Rollback on error
    queryClient.setQueryData(endpointKeys.detail(orgId, endpointId), context.previous);
  },
});
```

5. **Cache invalidation**: The hooks automatically invalidate related queries on mutations. No manual invalidation needed in most cases.
