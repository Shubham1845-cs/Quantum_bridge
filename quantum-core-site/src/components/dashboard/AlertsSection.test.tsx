/**
 * AlertsSection Component Tests
 * 
 * Tests for the AlertsSection component including:
 * - Rendering with mock data
 * - Filtering by priority and status
 * - Debounced search functionality
 * - Alert detail modal display
 * - Status update actions
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import AlertsSection from './AlertsSection';
import { mockAlerts } from '@/mocks/alerts';

// Mock react-hot-toast
vi.mock('react-hot-toast', () => ({
  default: {
    success: vi.fn(),
    error: vi.fn(),
  },
}));

// Helper function to render with QueryClient
function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      {ui}
    </QueryClientProvider>
  );
}

describe('AlertsSection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render the alerts section with header', () => {
    renderWithClient(<AlertsSection />);
    
    expect(screen.getByText('Security Alerts')).toBeInTheDocument();
    expect(screen.getByText(/Monitor and manage security alerts/i)).toBeInTheDocument();
  });

  it('should display active alerts count badge', async () => {
    renderWithClient(<AlertsSection />);
    
    await waitFor(() => {
      const activeCount = mockAlerts.filter(a => a.status === 'active').length;
      expect(screen.getByText(`${activeCount} Active`)).toBeInTheDocument();
    });
  });

  it('should render filter controls', () => {
    renderWithClient(<AlertsSection />);
    
    expect(screen.getByLabelText(/Priority/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Status/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Alert ID, title, or endpoint/i)).toBeInTheDocument();
  });

  it('should display alerts in a table', async () => {
    renderWithClient(<AlertsSection />);
    
    await waitFor(() => {
      // Check for table headers
      expect(screen.getByText('Alert ID')).toBeInTheDocument();
      expect(screen.getByText('Priority')).toBeInTheDocument();
      expect(screen.getByText('Title')).toBeInTheDocument();
      expect(screen.getByText('Affected Endpoint')).toBeInTheDocument();
      expect(screen.getByText('Status')).toBeInTheDocument();
      expect(screen.getByText('Time')).toBeInTheDocument();
      
      // Check that at least one alert is rendered
      expect(screen.getByText(mockAlerts[0].alertId)).toBeInTheDocument();
    });
  });

  it('should filter alerts by priority', async () => {
    const user = userEvent.setup();
    renderWithClient(<AlertsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockAlerts[0].alertId)).toBeInTheDocument();
    });
    
    const prioritySelect = screen.getByLabelText(/Priority/i);
    await user.selectOptions(prioritySelect, 'critical');
    
    await waitFor(() => {
      const criticalAlerts = mockAlerts.filter(a => a.priority === 'critical');
      const nonCriticalAlerts = mockAlerts.filter(a => a.priority !== 'critical');
      
      // Critical alerts should be visible
      criticalAlerts.forEach(alert => {
        expect(screen.getByText(alert.alertId)).toBeInTheDocument();
      });
      
      // Non-critical alerts should not be visible
      nonCriticalAlerts.forEach(alert => {
        expect(screen.queryByText(alert.alertId)).not.toBeInTheDocument();
      });
    });
  });

  it('should filter alerts by status', async () => {
    const user = userEvent.setup();
    renderWithClient(<AlertsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockAlerts[0].alertId)).toBeInTheDocument();
    });
    
    const statusSelect = screen.getByLabelText(/Status/i);
    await user.selectOptions(statusSelect, 'active');
    
    await waitFor(() => {
      const activeAlerts = mockAlerts.filter(a => a.status === 'active');
      const inactiveAlerts = mockAlerts.filter(a => a.status !== 'active');
      
      // Active alerts should be visible
      activeAlerts.forEach(alert => {
        expect(screen.getByText(alert.alertId)).toBeInTheDocument();
      });
      
      // Inactive alerts should not be visible
      inactiveAlerts.slice(0, 3).forEach(alert => {
        expect(screen.queryByText(alert.alertId)).not.toBeInTheDocument();
      });
    });
  });

  it('should search alerts with debounce', async () => {
    const user = userEvent.setup();
    renderWithClient(<AlertsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockAlerts[0].alertId)).toBeInTheDocument();
    });
    
    const searchInput = screen.getByPlaceholderText(/Alert ID, title, or endpoint/i);
    
    // Type search query
    await user.type(searchInput, mockAlerts[0].alertId);
    
    // Wait for debounce (300ms)
    await waitFor(() => {
      expect(screen.getByText(mockAlerts[0].alertId)).toBeInTheDocument();
    }, { timeout: 500 });
  });

  it('should open alert detail modal on row click', async () => {
    const user = userEvent.setup();
    renderWithClient(<AlertsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockAlerts[0].alertId)).toBeInTheDocument();
    });
    
    // Click on first alert row
    const alertRow = screen.getByText(mockAlerts[0].alertId).closest('tr');
    if (alertRow) {
      await user.click(alertRow);
    }
    
    // Modal should open with alert details
    await waitFor(() => {
      expect(screen.getByText('Alert Details and Actions')).toBeInTheDocument();
      expect(screen.getByText(mockAlerts[0].title)).toBeInTheDocument();
      expect(screen.getByText(mockAlerts[0].description)).toBeInTheDocument();
    });
  });

  it('should display action buttons in modal for active alerts', async () => {
    const user = userEvent.setup();
    renderWithClient(<AlertsSection />);
    
    // Find an active alert
    const activeAlert = mockAlerts.find(a => a.status === 'active');
    if (!activeAlert) throw new Error('No active alert in mock data');
    
    await waitFor(() => {
      expect(screen.getByText(activeAlert.alertId)).toBeInTheDocument();
    });
    
    // Click on active alert
    const alertRow = screen.getByText(activeAlert.alertId).closest('tr');
    if (alertRow) {
      await user.click(alertRow);
    }
    
    // Check for action buttons
    await waitFor(() => {
      expect(screen.getByText('Mark as Resolved')).toBeInTheDocument();
      expect(screen.getByText('Dismiss')).toBeInTheDocument();
    });
  });

  it('should not display action buttons for resolved alerts', async () => {
    const user = userEvent.setup();
    renderWithClient(<AlertsSection />);
    
    // Find a resolved alert
    const resolvedAlert = mockAlerts.find(a => a.status === 'resolved');
    if (!resolvedAlert) throw new Error('No resolved alert in mock data');
    
    await waitFor(() => {
      expect(screen.getByText(resolvedAlert.alertId)).toBeInTheDocument();
    });
    
    // Click on resolved alert
    const alertRow = screen.getByText(resolvedAlert.alertId).closest('tr');
    if (alertRow) {
      await user.click(alertRow);
    }
    
    // Action buttons should not be present
    await waitFor(() => {
      expect(screen.queryByText('Mark as Resolved')).not.toBeInTheDocument();
      expect(screen.queryByText('Dismiss')).not.toBeInTheDocument();
    });
  });

  it('should display "No alerts found" when filters return no results', async () => {
    const user = userEvent.setup();
    renderWithClient(<AlertsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockAlerts[0].alertId)).toBeInTheDocument();
    });
    
    // Search for non-existent alert
    const searchInput = screen.getByPlaceholderText(/Alert ID, title, or endpoint/i);
    await user.type(searchInput, 'NONEXISTENT-ALERT-12345');
    
    await waitFor(() => {
      expect(screen.getByText('No alerts found')).toBeInTheDocument();
      expect(screen.getByText(/Try adjusting your filters or search query/i)).toBeInTheDocument();
    }, { timeout: 500 });
  });

  it('should display results count', async () => {
    renderWithClient(<AlertsSection />);
    
    await waitFor(() => {
      const countText = `Showing ${mockAlerts.length} of ${mockAlerts.length} alerts`;
      expect(screen.getByText(countText)).toBeInTheDocument();
    });
  });

  it('should apply correct priority badge styling', async () => {
    renderWithClient(<AlertsSection />);
    
    await waitFor(() => {
      // Find a critical alert badge
      const criticalAlert = mockAlerts.find(a => a.priority === 'critical');
      if (criticalAlert) {
        const criticalBadge = screen.getAllByText('CRITICAL')[0];
        expect(criticalBadge).toHaveClass('text-[#FF6B6B]');
      }
    });
  });

  it('should apply correct status badge styling', async () => {
    renderWithClient(<AlertsSection />);
    
    await waitFor(() => {
      // Check that status badges have appropriate classes
      const activeBadges = screen.getAllByText(/active/i).filter(el => 
        el.tagName === 'SPAN' && el.className.includes('text-[#FF6B6B]')
      );
      expect(activeBadges.length).toBeGreaterThan(0);
    });
  });
});
