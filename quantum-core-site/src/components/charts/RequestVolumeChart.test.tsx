import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import RequestVolumeChart from './RequestVolumeChart';
import { TimeseriesDataPoint } from '../../api/analytics';

describe('RequestVolumeChart', () => {
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
    {
      timestamp: '2023-01-01T02:00:00Z',
      requestCount: 95,
      ecdsaVerificationRate: 0.96,
      dilithiumVerificationRate: 0.89,
      threatFlagRate: 0.03,
    },
  ];

  it('should render chart title', () => {
    render(<RequestVolumeChart data={mockData} />);

    expect(screen.getByText(/request volume/i)).toBeInTheDocument();
  });

  it('should show "no data available" message when data is empty', () => {
    render(<RequestVolumeChart data={[]} />);

    expect(screen.getByText(/no data available/i)).toBeInTheDocument();
    // Should not render the chart when there's no data
    expect(screen.queryByRole('img')).not.toBeInTheDocument(); // Recharts renders as SVG
  });

  it('should render the chart when data is provided', () => {
    render(<RequestVolumeChart data={mockData} />);

    // Recharts renders SVG elements, so we check for SVG presence
    const svgElement = screen.getByRole('img');
    expect(svgElement).toBeInTheDocument();
    // The SVG should have the chart elements
    expect(svgElement).toHaveAttribute('role', 'img');
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

    render(<RequestVolumeChart data={singleDataPoint} />);

    expect(screen.getByText(/request volume/i)).toBeInTheDocument();
    expect(screen.getByRole('img')).toBeInTheDocument();
    expect(screen.queryByText(/no data available/i)).not.toBeInTheDocument();
  });

  it('should handle zero request count', () => {
    const zeroData: TimeseriesDataPoint[] = [
      {
        timestamp: '2023-01-01T00:00:00Z',
        requestCount: 0,
        ecdsaVerificationRate: 0.0,
        dilithiumVerificationRate: 0.0,
        threatFlagRate: 0.0,
      },
    ];

    render(<RequestVolumeChart data={zeroData} />);

    expect(screen.getByText(/request volume/i)).toBeInTheDocument();
    expect(screen.getByRole('img')).toBeInTheDocument();
  });

  it('should handle large request counts', () => {
    const largeData: TimeseriesDataPoint[] = [
      {
        timestamp: '2023-01-01T00:00:00Z',
        requestCount: 1000000,
        ecdsaVerificationRate: 1.0,
        dilithiumVerificationRate: 1.0,
        threatFlagRate: 0.0,
      },
    ];

    render(<RequestVolumeChart data={largeData} />);

    expect(screen.getByText(/request volume/i)).toBeInTheDocument();
    expect(screen.getByRole('img')).toBeInTheDocument();
  });

  it('should handle various date formats in timestamp', () => {
    const variedData: TimeseriesDataPoint[] = [
      {
        timestamp: '2023-12-31T23:59:59Z',
        requestCount: 50,
        ecdsaVerificationRate: 0.5,
        dilithiumVerificationRate: 0.5,
        threatFlagRate: 0.5,
      },
      {
        timestamp: '2024-01-01T00:00:00Z',
        requestCount: 60,
        ecdsaVerificationRate: 0.6,
        dilithiumVerificationRate: 0.6,
        threatRate: 0.4,
      },
    ];

    render(<RequestVolumeChart data={variedData} />);

    expect(screen.getByText(/request volume/i)).toBeInTheDocument();
    expect(screen.getByRole('img')).toBeInTheDocument();
  });
});