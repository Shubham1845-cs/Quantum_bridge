import toast from 'react-hot-toast';

export function useToast() {
  return {
    success: (message: string) => {
      toast.success(message, {
        duration: 3000,
        position: 'top-right',
        style: {
          background: '#0a0a0a',
          color: '#fff',
          border: '1px solid rgba(0, 255, 255, 0.2)',
        },
      });
    },
    error: (message: string) => {
      toast.error(message, {
        duration: 4000,
        position: 'top-right',
        style: {
          background: '#0a0a0a',
          color: '#fff',
          border: '1px solid rgba(239, 68, 68, 0.2)',
        },
      });
    },
    loading: (message: string) => {
      return toast.loading(message, {
        position: 'top-right',
        style: {
          background: '#0a0a0a',
          color: '#fff',
          border: '1px solid rgba(255, 255, 255, 0.1)',
        },
      });
    },
    dismiss: (toastId: string) => {
      toast.dismiss(toastId);
    },
  };
}
