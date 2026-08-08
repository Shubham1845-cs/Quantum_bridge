import { Toaster } from 'react-hot-toast';

export default function Toast() {
  return (
    <Toaster
      position="top-right"
      toastOptions={{
        duration: 3000,
        style: {
          background: '#0a0a0a',
          color: '#fff',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          borderRadius: '12px',
          padding: '12px 16px',
          fontSize: '14px',
        },
        success: {
          style: {
            border: '1px solid rgba(0, 255, 255, 0.2)',
          },
          iconTheme: {
            primary: '#00FFFF',
            secondary: '#0a0a0a',
          },
        },
        error: {
          style: {
            border: '1px solid rgba(239, 68, 68, 0.2)',
          },
          iconTheme: {
            primary: '#ef4444',
            secondary: '#0a0a0a',
          },
        },
        loading: {
          style: {
            border: '1px solid rgba(255, 255, 255, 0.1)',
          },
        },
      }}
    />
  );
}
