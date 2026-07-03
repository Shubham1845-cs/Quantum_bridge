import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import MemberTable from './MemberTable';
import type { OrgMember } from '../../api/team';

// Mock window.confirm
const originalConfirm = window.confirm;

beforeAll(() => {
  window.confirm = vi.fn(() => true); // Default to confirming
});

afterAll(() => {
  window.confirm = originalConfirm;
});

describe('MemberTable', () => {
  const mockOrgMembers: Omit<OrgMember, 'userId'> & { userId: { _id: string; email: string } }[] = [
    {
      _id: 'member1',
      inviteEmail: undefined,
      userId: { _id: 'user1', email: 'owner@example.com' },
      role: 'owner',
      status: 'active',
      createdAt: '2023-01-01T00:00:00Z',
    },
    {
      _id: 'member2',
      inviteEmail: 'pending@example.com',
      userId: { _id: 'user2', email: 'user2@example.com' },
      role: 'admin',
      status: 'pending',
      createdAt: '2023-01-02T00:00:00Z',
    },
    {
      _id: 'member3',
      inviteEmail: undefined,
      userId: { _id: 'user3', email: 'viewer@example.com' },
      role: 'viewer',
      status: 'active',
      createdAt: '2023-01-03T00:00:00Z',
    },
  ];

  const mockCurrentUserId = 'user1';

  it('should render table headers', () => {
    render(<MemberTable members={mockOrgMembers} orgId="test-org" currentUserId={mockCurrentUserId} />);

    expect(screen.getByRole('columnheader', { name: /email/i })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: /role/i })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: /status/i })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: /joined/i })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: /actions/i })).toBeInTheDocument();
  });

  it('should display member data correctly', () => {
    render(<MemberTable members={mockOrgMembers} orgId="test-org" currentUserId={mockCurrentUserId} />);

    // Check owner (current user)
    expect(screen.getByText('owner@example.com')).toBeInTheDocument();
    expect(screen.getByText('(You)')).toBeInTheDocument();
    expect(screen.getByText(/owner/i)).toBeInTheDocument();
    expect(screen.getByText(/active/i)).toBeInTheDocument();

    // Check pending member
    expect(screen.getByText('pending@example.com')).toBeInTheDocument();
    expect(screen.getByText(/admin/i)).toBeInTheDocument();
    expect(screen.getByText(/pending/i)).toBeInTheDocument();

    // Check viewer
    expect(screen.getByText('viewer@example.com')).toBeInTheDocument();
    expect(screen.getByText(/viewer/i)).toBeInTheDocument();
    expect(screen.getByText(/active/i)).toBeInTheDocument();
  });

  it('should show empty state when no members', () => {
    render(<MemberTable members={[]} orgId="test-org" currentUserId={mockCurrentUserId} />);

    expect(screen.getByText(/no members found/i)).toBeInTheDocument();
    // Should not render table rows for members
    expect(screen.getAllByRole('row')).toHaveLength(1); // Only header row
  });

  it('should show loading state', () => {
    render(<MemberTable members={[]} orgId="test-org" currentUserId={mockCurrentUserId} isLoading />);

    expect(screen.getByDisplayValue(/loading spinner/i)).toBeInTheDocument();
    // Should show loading spinner instead of table
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('should handle remove member button visibility based on permissions', () => {
    render(<MemberTable members={mockOrgMembers} orgId="test-org" currentUserId={mockCurrentUserId} />);

    // Owner (current user) should NOT see remove button for themselves
    const ownerRow = screen.getByText('owner@example.com').closest('tr');
    expect(ownerRow.querySelector('button')).not.toBeInTheDocument(); // No remove button for self

    // Admin should see remove button for viewer (but not for owner)
    const viewerRow = Array.from(
      document.querySelectorAll('tr')
    ).find(row => row.textContent?.includes('viewer@example.com'));
    expect(viewerRow?.querySelector('button')).toBeInTheDocument(); // Can remove viewer

    // Admin should NOT see remove button for owner
    const ownerRow2 = Array.from(
      document.querySelectorAll('tr')
    ).find(row => row.textContent?.includes('owner@example.com'));
    expect(ownerRow2?.querySelector('button')).not.toBeInTheDocument(); // Cannot remove owner

    // Test with admin current user
    render(<MemberTable members={mockOrgMembers} orgId="test-org" currentUserId="user2" currentUserRole="admin" />);

    // Admin should be able to remove owner
    const ownerRow3 = screen.getByText('owner@example.com').closest('tr');
    expect(ownerRow3.querySelector('button')).toBeInTheDocument(); // Can remove owner as admin

    // Admin should NOT be able to remove another admin
    const adminRow = screen.getByText('user2@example.com').closest('tr'); // This is the current user
    expect(adminRow.querySelector('button')).not.toBeInTheDocument(); // Can't remove self
  });

  it('should call removeMember when remove button clicked', async () => {
    const mockRemoveMember = vi.fn().mockResolvedValue(undefined);
    vi.mock('../../api/team', () => ({
      ...vi.importActual('../../api/team'),
      removeMember: mockRemoveMember,
    }));

    // Mock window.confirm to return true
    vi.stubGlobal('confirm', vi.fn(() => true));

    render(<MemberTable members={mockOrgMembers} orgId="test-org" currentUserId={mockCurrentUserId} currentUserRole="admin" />);
    const user = userEvent.setup();

    // Click remove button for the viewer (index 2 in array)
    const removeButtons = screen.getAllByRole('button', { name: /remove/i });
    expect(removeButtons).toHaveLength(2); // Can remove viewer and pending admin (but not owner or self)

    // Click the first remove button (should be for pending member)
    await user.click(removeButtons[0]);

    // Verify confirm was called
    expect(window.confirm).toHaveBeenCalledWith(
      'Are you sure you want to remove pending@example.com from this organization?'
    );

    // Verify removeMember was called
    expect(mockRemoveMember).toHaveBeenCalledWith('test-org', 'user2');
  });

  it('should not call removeMember when user cancels confirmation', async () => {
    const mockRemoveMember = vi.fn();

    vi.mock('../../api/team', () => ({
      ...vi.importActual('../../api/team'),
      removeMember: mockRemoveMember,
    }));

    // Mock window.confirm to return false (cancel)
    vi.stubGlobal('confirm', vi.fn(() => false));

    render(<MemberTable members={mockOrgMembers} orgId="test-org" currentUserId={mockCurrentUserId} currentUserRole="admin" />);
    const user = userEvent.setup();

    // Click remove button
    const removeButton = screen.getAllByRole('button', { name: /remove/i })[0];
    await user.click(removeButton);

    // Verify confirm was called
    expect(window.confirm).toHaveBeenCalled();

    // Verify removeMember was NOT called
    expect(mockRemoveMember).not.toHaveBeenCalled();
  });

  it('should handle remove member with invite email (pending user)', async () => {
    const mockRemoveMember = vi.fn().mockResolvedValue(undefined);
    vi.mock('../../api/team', () => ({
      ...vi.importActual('../../api/team'),
      removeMember: mockRemoveFriend,
    }));

    vi.stubGlobal('confirm', vi.fn(() => true));

    render(<MemberTable members={mockOrgMembers} orgId="test-org" currentUserId={mockCurrentUserId} currentUserRole="admin" />);
    const user = userEvent.setup();

    // Find the pending member (has inviteEmail but no userId yet in mock data)
    // Actually, looking at the mock data, the pending member does have a userId
    // Let's adjust the test to use a member without user info
    const membersWithInviteOnly = [
      {
        _id: 'member1',
        inviteEmail: 'pending@example.com',
        userId: { _id: 'temp', email: 'temp@temp.com' }, // We'll override this in test
        role: 'admin',
        status: 'pending',
        createdAt: '2023-01-01T00:00:00Z',
      },
    ];

    // Override to simulate invite-only member
    const modifiedMember = {...membersWithInviteOnly[0]};
    delete (modifiedMember as any).userId; // Remove userId to simulate invite-only

    render(<MemberTable members={[modifiedMember as any]} orgId="test-org" currentUserId={mockCurrentUserId} currentUserRole="admin" />);
    const user = userEvent.setup();

    // Click remove button
    await user.click(screen.getByRole('button', { name: /remove/i }));

    // Should show confirmation with invite email
    expect(window.confirm).toHaveBeenCalledWith(
      'Are you sure you want to remove pending@example.com from this organization?'
    );

    // Verify removeMember was called with the member ID
    expect(mockRemoveMember).toHaveBeenCalledWith('test-org', 'member1');
  });
});