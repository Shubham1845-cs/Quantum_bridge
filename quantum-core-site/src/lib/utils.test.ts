import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  formatDate,
  formatDateTime,
  truncate,
  formatBytes,
  debounce,
  getPlanDisplayName,
  getRoleDisplayName,
  getRoleColor,
} from './utils';

describe('Utility Functions', () => {
  describe('formatDate', () => {
    it('should format date string correctly', () => {
      const result = formatDate('2023-06-15T10:30:00Z');
      expect(result).toBe('Jun 15, 2023');
    });

    it('should format Date object correctly', () => {
      const date = new Date('2023-06-15T10:30:00Z');
      const result = formatDate(date);
      expect(result).toBe('Jun 15, 2023');
    });

    it('should handle invalid date gracefully', () => {
      // Invalid date returns "Invalid Date" string
      const result = formatDate('invalid-date');
      // Depending on browser, this might vary, but we're testing it doesn't crash
      expect(typeof result).toBe('string');
    });
  });

  describe('formatDateTime', () => {
    it('should format date and time correctly', () => {
      const result = formatDateTime('2023-06-15T10:30:00Z');
      expect(result).toMatch(/Jun 15, 2023, 10:30 AM/);
    });

    it('should format Date object correctly', () => {
      const date = new Date('2023-06-15T10:30:00Z');
      const result = formatDateTime(date);
      expect(result).toMatch(/Jun 15, 2023, 10:30 AM/);
    });
  });

  describe('truncate', () => {
    it('should return original string if shorter than maxLength', () => {
      const result = truncate('hello', 10);
      expect(result).toBe('hello');
    });

    it('should truncate string when longer than maxLength', () => {
      const result = truncate('hello world', 5);
      expect(result).toBe('hello...');
    });

    it('should handle exact length', () => {
      const result = truncate('hello', 5);
      expect(result).toBe('hello');
    });

    it('should handle empty string', () => {
      const result = truncate('', 5);
      expect(result).toBe('');
    });

    it('should handle zero maxLength', () => {
      const result = truncate('hello', 0);
      expect(result).toBe('...');
    });
  });

  describe('formatBytes', () => {
    it('should format bytes correctly', () => {
      expect(formatBytes(0)).toBe('0 Bytes');
      expect(formatBytes(1024)).toBe('1.00 KB');
      expect(formatBytes(1024 * 1024)).toBe('1.00 MB');
      expect(formatBytes(1024 * 1024 * 1024)).toBe('1.00 GB');
      expect(formatBytes(1024 * 1024 * 1024 * 1024)).toBe('1.00 TB');
    });

    it('should handle decimal places', () => {
      expect(formatBytes(1536, 0)).toBe('1 KB'); // 1.5KB rounded to 0 decimals
      expect(formatBytes(1536, 1)).toBe('1.5 KB');
      expect(formatBytes(1536, 2)).toBe('1.50 KB');
    });

    it('should handle very small numbers', () => {
      expect(formatBytes(1)).toBe('1.00 Bytes');
      expect(formatBytes(500)).toBe('500.00 Bytes');
    });
  });

  describe('debounce', () => {
    let mockFunc: any;
    let debouncedFn: any;

    beforeEach(() => {
      mockFunc = vi.fn();
      debouncedFn = debounce(mockFunc, 100);
      vi.clearAllMocks();
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should delay function execution', () => {
      debouncedFn('arg1', 'arg2');
      debouncedFn('arg3', 'arg4');

      // Should not have been called yet
      expect(mockFunc).not.toHaveBeenCalledTimes(0);

      // Fast-forward time
      vi.advanceTimersByTime(100);

      // Should have been called once with the last arguments
      expect(mockFunc).toHaveBeenCalledTimes(1);
      expect(mockFunc).toHaveBeenCalledWith('arg3', 'arg4');
    });

    it('should reset timer on each call', () => {
      debouncedFn('first');
      vi.advanceTimersByTime(50);
      debouncedFn('second');
      vi.advanceTimersByTime(50);
      debouncedFn('third');

      // Should not have been called yet (still waiting)
      expect(mockFunc).not.toHaveBeenCalled();

      // Advance past debounce time
      vi.advanceTimersByTime(100);

      // Should have been called once with the last argument
      expect(mockFunc).toHaveBeenCalledTimes(1);
      expect(mockFunc).toHaveBeenCalledWith('third');
    });

    it('should call immediately if wait is 0', () => {
      const instantFn = debounce(mockFunc, 0);
      instantFn('test');

      expect(mockFunc).toHaveBeenCalledTimes(1);
      expect(mockFunc).toHaveBeenCalledWith('test');
    });
  });

  describe('getPlanDisplayName', () => {
    it('should return correct display name for free plan', () => {
      expect(getPlanDisplayName('free')).toBe('Free');
    });

    it('should return correct display name for pro plan', () => {
      expect(getPlanDisplayName('pro')).toBe('Pro');
    });

    it('should return correct display name for enterprise plan', () => {
      expect(getPlanDisplayName('enterprise')).toBe('Enterprise');
    });
  });

  describe('getRoleDisplayName', () => {
    it('should return correct display name for owner role', () => {
      expect(getRoleDisplayName('owner')).toBe('Owner');
    });

    it('should return correct display name for admin role', () => {
      expect(getRoleDisplayName('admin')).toBe('Admin');
    });

    it('should return correct display name for viewer role', () => {
      expect(getRoleDisplayName('viewer')).toBe('Viewer');
    });
  });

  describe('getRoleColor', () => {
    it('should return correct color class for owner role', () => {
      expect(getRoleColor('owner')).toBe('bg-neon-purple/20 text-neon-purple');
    });

    it('should return correct color class for admin role', () => {
      expect(getRoleColor('admin')).toBe('bg-cyber-cyan/20 text-cyber-cyan');
    });

    it('should return correct color class for viewer role', () => {
      expect(getRoleColor('viewer')).toBe('bg-gray-500/20 text-gray-400');
    });
  });
});