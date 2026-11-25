
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Route, Routes } from 'react-router-dom'

import App from './App'
import { AuthProvider, useAuth } from './context/AuthContext'
import AuthPage from './pages/AuthPage'
import ForgotPasswordPage from './pages/ForgotPasswordPage'
import ResetPasswordPage from './pages/ResetPasswordPage'

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
    return (
      <Routes>
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        <Route path="*" element={<AuthPage />} />
      </Routes>
    )
  }

  return (
    <>
      <App />
      <button
        className="auth-signout"
        type="button"
        onClick={() => {
          void logout()
        }}
        title={`Signed in as ${user.email}`}
      >
        Sign out
      </button>
    </>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <AuthGate />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
)
