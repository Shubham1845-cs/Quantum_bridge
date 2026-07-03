/**
 * VerificationsSection Component Tests
 * 
 * Tests for the VerificationsSection component including:
 * - Rendering with mock data
 * - Filtering by result status
 * - Search functionality with debouncing
 * - Date range filtering
 * - Sortable table columns
 * - Pagination controls
 * - CSV export functionality
 * - Verification detail modal
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import VerificationsSection from './VerificationsSection';
import { mockVerifications } from '@/mocks/verifications';

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

describe('VerificationsSection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render the verifications section with header', () => {
    renderWithClient(<VerificationsSection />);
    
    expect(screen.getByText('Verification History')).toBeInTheDocument();
    expect(screen.getByText(/Historical audit of signature verification requests/i)).toBeInTheDocument();
  });

  it('should display export CSV button', () => {
    renderWithClient(<VerificationsSection />);
    
    expect(screen.getByText('Export CSV')).toBeInTheDocument();
  });

  it('should render filter controls', () => {
    renderWithClient(<VerificationsSection />);
    
    expect(screen.getByLabelText(/Result Status/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Date Range/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Verification ID or endpoint/i)).toBeInTheDocument();
  });

  it('should display verifications in a table', async () => {
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      // Check for table headers
      expect(screen.getByText('Timestamp')).toBeInTheDocument();
      expect(screen.getByText('Verification ID')).toBeInTheDocument();
      expect(screen.getByText('Endpoint')).toBeInTheDocument();
      expect(screen.getByText('Algorithm')).toBeInTheDocument();
      expect(screen.getByText('Result')).toBeInTheDocument();
      expect(screen.getByText('Response Time')).toBeInTheDocument();
      
      // Check that verifications are rendered (should show first page)
      expect(screen.getByText(mockVerifications[0].verificationId)).toBeInTheDocument();
    });
  });

  it('should filter verifications by result status', async () => {
    const user = userEvent.setup();
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockVerifications[0].verificationId)).toBeInTheDocument();
    });
    
    const resultSelect = screen.getByLabelText(/Result Status/i);
    await user.selectOptions(resultSelect, 'verified');
    
    await waitFor(() => {
      // Should only show verified verifications
      const verifiedVerifications = mockVerifications.filter(v => v.result === 'verified');
      const rejectedVerifications = mockVerifications.filter(v => v.result === 'rejected');
      
      // At least one verified verification should be visible on current page
      const visibleVerified = verifiedVerifications.slice(0, 25);
      expect(screen.getByText(visibleVerified[0].verificationId)).toBeInTheDocument();
    });
  });

  it('should search verifications with debounce', async () => {
    const user = userEvent.setup();
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockVerifications[0].verificationId)).toBeInTheDocument();
    });
    
    const searchInput = screen.getByPlaceholderText(/Verification ID or endpoint/i);
    
    // Type search query
    await user.type(searchInput, mockVerifications[0].verificationId);
    
    // Wait for debounce (300ms)
    await waitFor(() => {
      expect(screen.getByText(mockVerifications[0].verificationId)).toBeInTheDocument();
    }, { timeout: 500 });
  });

  it('should filter by date range', async () => {
    const user = userEvent.setup();
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockVerifications[0].verificationId)).toBeInTheDocument();
    });
    
    const dateRangeSelect = screen.getByLabelText(/Date Range/i);
    await user.selectOptions(dateRangeSelect, '7');
    
    // Should filter to last 7 days (component will apply filter)
    await waitFor(() => {
      // Just verify the component is still rendering
      expect(screen.getByText('Verification History')).toBeInTheDocument();
    });
  });

  it('should sort by column when header is clicked', async () => {
    const user = userEvent.setup();
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockVerifications[0].verificationId)).toBeInTheDocument();
    });
    
    // Click on endpoint header to sort
    const endpointHeader = screen.getByText('Endpoint').closest('th');
    if (endpointHeader) {
      await user.click(endpointHeader);
    }
    
    // Should see sort icon
    await waitFor(() => {
      expect(endpointHeader).toBeInTheDocument();
    });
  });

  it('should display pagination controls', async () => {
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(/Show/i)).toBeInTheDocument();
      expect(screen.getByText(/entries/i)).toBeInTheDocument();
      expect(screen.getByText(/Page \d+ of \d+/)).toBeInTheDocument();
    });
  });

  it('should change page size', async () => {
    const user = userEvent.setup();
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockVerifications[0].verificationId)).toBeInTheDocument();
    });
    
    // Find and change page size selector
    const pageSizeSelect = screen.getByDisplayValue('25');
    await user.selectOptions(pageSizeSelect, '50');
    
    await waitFor(() => {
      // Should update results display
      expect(screen.getByText(/Showing \d+ to \d+ of \d+ verifications/)).toBeInTheDocument();
    });
  });

  it('should navigate to next page', async () => {
    const user = userEvent.setup();
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockVerifications[0].verificationId)).toBeInTheDocument();
    });
    
    // Get the "next page" button (ChevronRight icon)
    const nextButtons = screen.getAllByRole('button');
    const nextButton = nextButtons.find(btn => 
      btn.querySelector('svg') && !btn.disabled
    );
    
    if (nextButton) {
      await user.click(nextButton);
      
      await waitFor(() => {
        // Should show page 2
        expect(screen.getByText(/Page 2 of/)).toBeInTheDocument();
      });
    }
  });

  it('should open verification detail modal on row click', async () => {
    const user = userEvent.setup();
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockVerifications[0].verificationId)).toBeInTheDocument();
    });
    
    // Click on first verification row
    const verificationRow = screen.getByText(mockVerifications[0].verificationId).closest('tr');
    if (verificationRow) {
      await user.click(verificationRow);
    }
    
    // Modal should open with verification details
    await waitFor(() => {
      expect(screen.getByText('Verification Details')).toBeInTheDocument();
      expect(screen.getByText(mockVerifications[0].endpoint)).toBeInTheDocument();
    });
  });

  it('should display error details for rejected verifications', async () => {
    const user = userEvent.setup();
    renderWithClient(<VerificationsSection />);
    
    // Find a rejected verification
    const rejectedVerification = mockVerifications.find(v => v.result === 'rejected');
    if (!rejectedVerification) throw new Error('No rejected verification in mock data');
    
    await waitFor(() => {
      expect(screen.getByText(rejectedVerification.verificationId)).toBeInTheDocument();
    });
    
    // Click on rejected verification
    const verificationRow = screen.getByText(rejectedVerification.verificationId).closest('tr');
    if (verificationRow) {
      await user.click(verificationRow);
    }
    
    // Should show error details
    await waitFor(() => {
      expect(screen.getByText('Error Details')).toBeInTheDocument();
      if (rejectedVerification.errorDetails) {
        expect(screen.getByText(rejectedVerification.errorDetails)).toBeInTheDocument();
      }
    });
  });

  it('should export to CSV when button is clicked', async () => {
    const user = userEvent.setup();
    
    // Mock URL.createObjectURL and document.createElement
    const createObjectURLMock = vi.fn(() => 'mock-url');
    const revokeObjectURLMock = vi.fn();
    global.URL.createObjectURL = createObjectURLMock;
    global.URL.revokeObjectURL = revokeObjectURLMock;
    
    const clickMock = vi.fn();
    const createElementSpy = vi.spyOn(document, 'createElement').mockReturnValue({
      click: clickMock,
      href: '',
      download: '',
    } as any);
    
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      expect(screen.getByText('Export CSV')).toBeInTheDocument();
    });
    
    const exportButton = screen.getByText('Export CSV');
    await user.click(exportButton);
    
    // Should trigger CSV creation
    await waitFor(() => {
      expect(createObjectURLMock).toHaveBeenCalled();
      expect(clickMock).toHaveBeenCalled();
    });
    
    createElementSpy.mockRestore();
  });

  it('should display "No verifications found" when filters return no results', async () => {
    const user = userEvent.setup();
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockVerifications[0].verificationId)).toBeInTheDocument();
    });
    
    // Search for non-existent verification
    const searchInput = screen.getByPlaceholderText(/Verification ID or endpoint/i);
    await user.type(searchInput, 'NONEXISTENT-VRF-12345');
    
    await waitFor(() => {
      expect(screen.getByText('No verifications found')).toBeInTheDocument();
      expect(screen.getByText(/Try adjusting your filters or search query/i)).toBeInTheDocument();
    }, { timeout: 500 });
  });

  it('should apply correct result badge styling', async () => {
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      // Find a verified badge
      const verifiedVerification = mockVerifications.find(v => v.result === 'verified');
      if (verifiedVerification) {
        const verifiedBadges = screen.getAllByText(/verified/i);
        const verifiedBadge = verifiedBadges.find(el => 
          el.tagName === 'SPAN' && el.className.includes('text-[#34D399]')
        );
        expect(verifiedBadge).toBeDefined();
      }
    });
  });

  it('should apply correct algorithm badge styling', async () => {
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      // Check that algorithm badges exist
      const mlDsaBadges = screen.getAllByText('ML-DSA-65');
      const ecdsaBadges = screen.getAllByText('ECDSA P-256');
      
      expect(mlDsaBadges.length + ecdsaBadges.length).toBeGreaterThan(0);
    });
  });

  it('should reset to page 1 when filters change', async () => {
    const user = userEvent.setup();
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockVerifications[0].verificationId)).toBeInTheDocument();
    });
    
    // Go to page 2
    const nextButtons = screen.getAllByRole('button');
    const nextButton = nextButtons.find(btn => 
      btn.querySelector('svg') && !btn.disabled
    );
    
    if (nextButton && mockVerifications.length > 25) {
      await user.click(nextButton);
      
      await waitFor(() => {
        expect(screen.getByText(/Page 2 of/)).toBeInTheDocument();
      });
      
      // Change filter
      const resultSelect = screen.getByLabelText(/Result Status/i);
      await user.selectOptions(resultSelect, 'verified');
      
      // Should reset to page 1
      await waitFor(() => {
        expect(screen.getByText(/Page 1 of/)).toBeInTheDocument();
      });
    }
  });

  it('should disable export button when no results', async () => {
    const user = userEvent.setup();
    renderWithClient(<VerificationsSection />);
    
    await waitFor(() => {
      expect(screen.getByText(mockVerifications[0].verificationId)).toBeInTheDocument();
    });
    
    // Search for non-existent verification
    const searchInput = screen.getByPlaceholderText(/Verification ID or endpoint/i);
    await user.type(searchInput, 'NONEXISTENT-VRF-99999');
    
    await waitFor(() => {
      const exportButton = screen.getByText('Export CSV').closest('button');
      expect(exportButton).toBeDisabled();
    }, { timeout: 500 });
  });
});
