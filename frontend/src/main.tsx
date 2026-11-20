
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import App from './App'
import { AuthProvider, useAuth } from './context/AuthContext'
import AuthPage from './pages/AuthPage'

import './index.css'

function AuthGate() {
  const { user, loading, logout } = useAuth()

  if (loading) {
    return (
      <main className="auth-loading-screen">
        <div className="auth-loading-indicator">
          <span className="auth-spinner" />
          Restoring your secure session...
        </div>
      </main>
    )
  }

  if (!user) {
    return <AuthPage />
  }

  return (
    <>
      <App />
      <button
        className="auth-signout"
        type="button"
        onClick={logout}
        title={`Signed in as ${user.email}`}
      >
        Sign out
      </button>
    </>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthProvider>
      <AuthGate />
    </AuthProvider>
  </StrictMode>,
)
