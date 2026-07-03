import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import VerificationRateChart from './VerificationRateChart';
import { TimeseriesDataPoint } from '../../api/analytics';

describe('VerificationRateChart', () => {
  const mockData: TimeseriesDataPoint[] = [
    {
      timestamp: '2023-01-01T00:00:00Z',
      requestCount: 100,
      ecdsaVerificationRate: 0.95,
      dilithiumVerificationRate: 0.88,
      threatFlagRate: 0.02,
    },
    {
      timestamp: '2023-01-01T01:00:00Z',
      requestCount: 120,
      ecdsaVerificationRate: 0.93,
      dilithiumVerificationRate: 0.90,
      threatFlagRate: 0.01,
    },
  ];

  it('should render chart title', () => {
    render(<VerificationRateChart data={mockData} />);

    expect(screen.getByText(/verification rate/i)).toBeInTheDocument();
  });

  it('should show "no data available" message when data is empty', () => {
    render(<VerificationRateChart data={[]} />);

    expect(screen.getByText(/no data available/i)).toBeInTheDocument();
    expect(screen.queryByRole('img')).not.toBeInTheDocument();
  });

  it('should render the chart when data is provided', () => {
    render(<VerificationRateChart data={mockData} />);

    const svgElement = screen.getByRole('img');
    expect(svgElement).toBeInTheDocument();
  });

  it('should handle single data point', () => {
    const singleDataPoint: TimeseriesDataPoint[] = [
      {
        timestamp: '2023-01-01T00:00:00Z',
        requestCount: 100,
        ecdsaVerificationRate: 0.95,
        dilithiumVerificationRate: 0.88,
        threatFlagRate: 0.02,
      },
    ];

    render(<VerificationRateChart data={singleDataPoint} />);

    expect(screen.getByText(/verification rate/i)).toBeInTheDocument();
    expect(screen.getByRole('img')).toBeInTheDocument();
  });
});