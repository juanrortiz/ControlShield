import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { Toaster } from 'sonner'
import './index.css'
import App from './App'
import { GuardianProvider } from './store'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <GuardianProvider>
      <App />
      <Toaster theme="dark" richColors position="bottom-right" />
    </GuardianProvider>
  </StrictMode>,
)
