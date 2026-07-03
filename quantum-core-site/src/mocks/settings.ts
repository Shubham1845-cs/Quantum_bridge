/**
 * Mock data for system settings
 * Provides default configuration for all settings tabs
 */

export interface SettingsFormData {
  // System Configuration
  autoRefreshInterval: number; // milliseconds
  defaultTimeRange: string;
  dataRetentionDays: number;
  
  // User Preferences
  theme: 'dark' | 'light';
  language: string; // ISO 639-1 code
  timezone: string; // IANA timezone
  
  // Organization Settings
  organizationName: string;
  billingEmail: string;
  subscriptionPlan: 'free' | 'pro' | 'enterprise';
  
  // API Configuration
  apiBaseUrl: string;
  webhookUrl?: string;
  apiTimeout: number; // milliseconds
  
  // Notification Settings
  emailNotifications: boolean;
  smsNotifications: boolean;
  webhookNotifications: boolean;
  alertThresholds: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface Settings {
  _id: string;
  organizationId: string;
  
  // System Configuration
  systemConfig: {
    autoRefreshInterval: number;
    defaultTimeRange: string;
    dataRetentionDays: number;
  };
  
  // User Preferences
  userPreferences: {
    theme: 'dark' | 'light';
    language: string;
    timezone: string;
  };
  
  // Organization Settings
  organizationSettings: {
    name: string;
    billingEmail: string;
    subscriptionPlan: 'free' | 'pro' | 'enterprise';
  };
  
  // API Configuration
  apiConfig: {
    baseUrl: string;
    webhookUrl?: string;
    timeout: number;
  };
  
  // Notification Settings
  notificationSettings: {
    emailNotifications: boolean;
    smsNotifications: boolean;
    webhookNotifications: boolean;
    alertThresholds: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
  
  updatedAt: string;
  updatedBy: string; // User ID
}

export const mockSettings: Settings = {
  _id: 'settings-001',
  organizationId: 'org-001',
  
  systemConfig: {
    autoRefreshInterval: 10000, // 10 seconds
    defaultTimeRange: 'Last 24 Hours',
    dataRetentionDays: 90,
  },
  
  userPreferences: {
    theme: 'dark',
    language: 'en',
    timezone: 'America/New_York',
  },
  
  organizationSettings: {
    name: 'QuantumBridge Security',
    billingEmail: 'billing@quantumbridge.io',
    subscriptionPlan: 'pro',
  },
  
  apiConfig: {
    baseUrl: 'https://api.quantumbridge.io',
    webhookUrl: 'https://hooks.quantumbridge.io/events',
    timeout: 30000, // 30 seconds
  },
  
  notificationSettings: {
    emailNotifications: true,
    smsNotifications: false,
    webhookNotifications: true,
    alertThresholds: {
      critical: 1, // Notify immediately
      high: 3, // Notify after 3 occurrences
      medium: 5, // Notify after 5 occurrences
      low: 10, // Notify after 10 occurrences
    },
  },
  
  updatedAt: new Date().toISOString(),
  updatedBy: 'user-001',
};

export const mockSettingsFormData: SettingsFormData = {
  autoRefreshInterval: mockSettings.systemConfig.autoRefreshInterval,
  defaultTimeRange: mockSettings.systemConfig.defaultTimeRange,
  dataRetentionDays: mockSettings.systemConfig.dataRetentionDays,
  
  theme: mockSettings.userPreferences.theme,
  language: mockSettings.userPreferences.language,
  timezone: mockSettings.userPreferences.timezone,
  
  organizationName: mockSettings.organizationSettings.name,
  billingEmail: mockSettings.organizationSettings.billingEmail,
  subscriptionPlan: mockSettings.organizationSettings.subscriptionPlan,
  
  apiBaseUrl: mockSettings.apiConfig.baseUrl,
  webhookUrl: mockSettings.apiConfig.webhookUrl,
  apiTimeout: mockSettings.apiConfig.timeout,
  
  emailNotifications: mockSettings.notificationSettings.emailNotifications,
  smsNotifications: mockSettings.notificationSettings.smsNotifications,
  webhookNotifications: mockSettings.notificationSettings.webhookNotifications,
  alertThresholds: mockSettings.notificationSettings.alertThresholds,
};

// Available options for dropdowns
export const timeRangeOptions = [
  'Last 1 Hour',
  'Last 6 Hours',
  'Last 24 Hours',
  'Last 7 Days',
  'Last 30 Days',
  'Last 90 Days',
];

export const languageOptions = [
  { code: 'en', name: 'English' },
  { code: 'es', name: 'Spanish' },
  { code: 'fr', name: 'French' },
  { code: 'de', name: 'German' },
  { code: 'ja', name: 'Japanese' },
  { code: 'zh', name: 'Chinese' },
];

export const timezoneOptions = [
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'America/Anchorage',
  'Pacific/Honolulu',
  'Europe/London',
  'Europe/Paris',
  'Europe/Berlin',
  'Asia/Tokyo',
  'Asia/Shanghai',
  'Asia/Dubai',
  'Australia/Sydney',
  'UTC',
];
