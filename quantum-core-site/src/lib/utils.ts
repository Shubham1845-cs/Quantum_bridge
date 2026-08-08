import { type ClassValue, clsx } from 'clsx';

/**
 * Utility for merging Tailwind CSS classes
 */
export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

/**
 * Format a date string to a human-readable format
 */
export function formatDate(date: string | Date): string {
  return new Date(date).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/**
 * Format a date string to include time
 */
export function formatDateTime(date: string | Date): string {
  return new Date(date).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Truncate a string to a maximum length
 */
export function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength) + '...';
}

/**
 * Copy text to clipboard
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (err) {
    console.error('Failed to copy to clipboard:', err);
    return false;
  }
}

/**
 * Format bytes to human-readable size
 */
export function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Debounce a function
 */
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: ReturnType<typeof setTimeout> | null = null;

  return function executedFunction(...args: Parameters<T>) {
    const later = () => {
      timeout = null;
      func(...args);
    };

    if (timeout) {
      clearTimeout(timeout);
    }
    timeout = setTimeout(later, wait);
  };
}

/**
 * Get plan display name
 */
export function getPlanDisplayName(plan: 'free' | 'pro' | 'enterprise'): string {
  const names = {
    free: 'Free',
    pro: 'Pro',
    enterprise: 'Enterprise',
  };
  return names[plan];
}

/**
 * Get plan color for badges
 */
export function getPlanColor(plan: 'free' | 'pro' | 'enterprise'): string {
  const colors = {
    free: 'bg-gray-500/20 text-gray-400',
    pro: 'bg-cyber-cyan/20 text-cyber-cyan',
    enterprise: 'bg-neon-purple/20 text-neon-purple',
  };
  return colors[plan];
}

/**
 * Get role display name
 */
export function getRoleDisplayName(role: 'owner' | 'admin' | 'viewer'): string {
  const names = {
    owner: 'Owner',
    admin: 'Admin',
    viewer: 'Viewer',
  };
  return names[role];
}

/**
 * Get role color for badges
 */
export function getRoleColor(role: 'owner' | 'admin' | 'viewer'): string {
  const colors = {
    owner: 'bg-neon-purple/20 text-neon-purple',
    admin: 'bg-cyber-cyan/20 text-cyber-cyan',
    viewer: 'bg-gray-500/20 text-gray-400',
  };
  return colors[role];
}
