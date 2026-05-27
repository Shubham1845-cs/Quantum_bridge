import { useState, FormEvent } from 'react';
import Input from '../ui/Input';
import Button from '../ui/Button';

interface EndpointFormData {
  name: string;
  targetUrl: string;
  ipAllowlist: string[];
}

interface EndpointFormProps {
  initialData?: Partial<EndpointFormData>;
  onSubmit: (data: EndpointFormData) => Promise<void>;
  onCancel?: () => void;
  submitLabel?: string;
  isLoading?: boolean;
}

export default function EndpointForm({
  initialData,
  onSubmit,
  onCancel,
  submitLabel = 'Create Endpoint',
  isLoading = false,
}: EndpointFormProps) {
  const [name, setName] = useState(initialData?.name || '');
  const [targetUrl, setTargetUrl] = useState(initialData?.targetUrl || '');
  const [ipAllowlistText, setIpAllowlistText] = useState(
    initialData?.ipAllowlist?.join(', ') || ''
  );
  const [errors, setErrors] = useState<Record<string, string>>({});

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!name.trim()) {
      newErrors.name = 'Name is required';
    }

    if (!targetUrl.trim()) {
      newErrors.targetUrl = 'Target URL is required';
    } else if (!targetUrl.startsWith('https://')) {
      newErrors.targetUrl = 'Target URL must be a valid HTTPS URL';
    }

    // Validate IP allowlist format (optional)
    if (ipAllowlistText.trim()) {
      const ips = ipAllowlistText.split(',').map((ip) => ip.trim());
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      
      for (const ip of ips) {
        if (!ipRegex.test(ip)) {
          newErrors.ipAllowlist = 'Invalid IP address format. Use comma-separated IPs (e.g., 192.168.1.1, 10.0.0.1)';
          break;
        }
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    const ipAllowlist = ipAllowlistText
      .split(',')
      .map((ip) => ip.trim())
      .filter((ip) => ip.length > 0);

    try {
      await onSubmit({
        name: name.trim(),
        targetUrl: targetUrl.trim(),
        ipAllowlist,
      });
    } catch (err) {
      // Error handling is done by parent component
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <Input
        label="Endpoint Name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder="My API Endpoint"
        error={errors.name}
        helperText="A friendly name for this endpoint"
        required
        autoFocus
      />

      <Input
        label="Target URL"
        type="url"
        value={targetUrl}
        onChange={(e) => setTargetUrl(e.target.value)}
        placeholder="https://api.example.com"
        error={errors.targetUrl}
        helperText="The HTTPS URL of your legacy API"
        required
      />

      <Input
        label="IP Allowlist (Optional)"
        value={ipAllowlistText}
        onChange={(e) => setIpAllowlistText(e.target.value)}
        placeholder="192.168.1.1, 10.0.0.1"
        error={errors.ipAllowlist}
        helperText="Comma-separated list of allowed IP addresses. Leave empty to allow all IPs."
      />

      <div className="flex gap-3 pt-4">
        {onCancel && (
          <Button
            type="button"
            variant="secondary"
            onClick={onCancel}
            disabled={isLoading}
            className="flex-1"
          >
            Cancel
          </Button>
        )}
        <Button
          type="submit"
          variant="primary"
          isLoading={isLoading}
          disabled={!name || !targetUrl || isLoading}
          className="flex-1"
        >
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}
