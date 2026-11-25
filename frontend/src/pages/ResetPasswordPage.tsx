import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight,
  Eye,
  EyeOff,
  LockKeyhole,
  ShieldCheck,
} from 'lucide-react'

import { ApiError, resetPassword } from '../services/api'
import './Auth.css'

export default function ResetPasswordPage() {
  const [token] = useState<string>(() => {
    const params = new URLSearchParams(window.location.search)
    return params.get('token')?.trim() ?? ''
  })

  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    if (window.location.search) {
      window.history.replaceState({}, '', window.location.pathname)
    }
  }, [])

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setNotice('')

    if (!token) {
      setError(
        'Reset token is missing or invalid. Please request a new password reset link.',
      )
      return
    }

    if (newPassword.length < 12) {
      setError('Your password must contain at least 12 characters.')
      return
    }

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.')
      return
    }

    setLoading(true)
    try {
      const result = await resetPassword(token, newPassword)
      setNotice(
        result.message ||
          'Password reset successfully. You can now sign in with your new password.',
      )
      setNewPassword('')
      setConfirmPassword('')
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message)
      } else {
        setError('Unable to reset password. Please request a new link.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="auth-shell">
      <div className="auth-brand">
        <div className="auth-brand-mark">
          <ShieldCheck size={20} />
        </div>
        <span>CreatorXDR</span>
      </div>

      <section className="auth-card" aria-labelledby="reset-heading">
        <h1 id="reset-heading">Choose a new password</h1>
        <p className="auth-subtitle">
          Set a strong password of at least 12 characters. Resetting your
          password will sign out all active sessions.
        </p>

        {!token && !notice && (
          <div className="auth-message auth-error" role="alert">
            No reset token was found in this link. Request a new password reset
            link.
          </div>
        )}

        {error && (
          <div className="auth-message auth-error" role="alert">
            {error}
          </div>
        )}

        {notice && (
          <div className="auth-message auth-success" role="status">
            {notice}
          </div>
        )}

        {!notice && (
          <form className="auth-form" onSubmit={handleSubmit}>
            <label htmlFor="reset-password">New password</label>

            <div className="auth-input-wrap">
              <LockKeyhole size={17} />
              <input
                id="reset-password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="new-password"
                placeholder="At least 12 characters"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                disabled={loading || !token}
                minLength={12}
                required
              />
              <button
                className="auth-password-toggle"
                type="button"
                onClick={() => setShowPassword((current) => !current)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
              </button>
            </div>

            <label htmlFor="reset-password-confirm">Confirm new password</label>

            <div className="auth-input-wrap">
              <LockKeyhole size={17} />
              <input
                id="reset-password-confirm"
                type={showPassword ? 'text' : 'password'}
                autoComplete="new-password"
                placeholder="Re-enter your new password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                disabled={loading || !token}
                minLength={12}
                required
              />
            </div>

            <button
              className="auth-submit"
              type="submit"
              disabled={loading || !token}
            >
              {loading ? 'Updating password...' : 'Reset password'}
              {!loading && <ArrowRight size={17} />}
            </button>
          </form>
        )}

        <div className="auth-switch">
          {notice ? (
            <Link to="/">Continue to sign in</Link>
          ) : (
            <>
              Need a new link? <Link to="/forgot-password">Request reset</Link>
            </>
          )}
        </div>

        <div className="auth-security-note">
          <LockKeyhole size={13} />
          Protected access · All active sessions revoked on reset
        </div>
      </section>

      <footer className="auth-footer">
        CREATORXDR <span>•</span> IDENTITY AND SECURITY
      </footer>
    </main>
  )
}
