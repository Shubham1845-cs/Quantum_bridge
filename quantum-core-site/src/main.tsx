import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClientProvider } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import { Toaster } from 'react-hot-toast'
import { Analytics } from '@vercel/analytics/react'
import { queryClient } from './lib/queryClient'
import { ErrorBoundary } from './components/ErrorBoundary'
import './index.css'
import App from './App'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <App />
        <Toaster />
        <ReactQueryDevtools initialIsOpen={false} />
        <Analytics />
      </QueryClientProvider>
    </ErrorBoundary>
  </StrictMode>,
)
