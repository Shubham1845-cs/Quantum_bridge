import { useState } from 'react';
import Modal from './Modal';
import Button from '../ui/Button';
import { copyToClipboard } from '../../lib/utils';
import { useToast } from '../../hooks/useToast';

interface ApiKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
  apiKey: string;
}

export default function ApiKeyModal({ isOpen, onClose, apiKey }: ApiKeyModalProps) {
  const [copied, setCopied] = useState(false);
  const toast = useToast();

  const handleCopy = async () => {
    const success = await copyToClipboard(apiKey);
    if (success) {
      setCopied(true);
      toast.success('API key copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    } else {
      toast.error('Failed to copy API key');
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="API Key Generated" maxWidth="lg">
      <div className="space-y-4">
        <div className="p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/30">
          <p className="text-yellow-400 text-sm font-medium">
            ⚠️ This key will only be shown once. Make sure to copy it now!
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-white/60 mb-2">
            Your API Key
          </label>
          <div className="flex gap-2">
            <div className="flex-1 p-3 rounded-lg bg-black/50 border border-white/10 font-mono text-sm text-white break-all">
              {apiKey}
            </div>
            <Button
              onClick={handleCopy}
              variant="secondary"
              className="shrink-0"
            >
              {copied ? (
                <>
                  <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  Copied
                </>
              ) : (
                <>
                  <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                  Copy
                </>
              )}
            </Button>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10">
          <h4 className="font-medium text-white mb-2">How to use this key:</h4>
          <ol className="text-sm text-white/60 space-y-1 list-decimal list-inside">
            <li>Include it as <code className="text-cyber-cyan">{'Authorization: Bearer <key>'}</code></li>
            <li>Send requests to your proxy URL</li>
            <li>Never commit this key to version control</li>
            <li>Rotate keys regularly for security</li>
          </ol>
        </div>

        <div className="flex justify-end pt-4">
          <Button onClick={onClose} variant="primary">
            I've Saved My Key
          </Button>
        </div>
      </div>
    </Modal>
  );
}
