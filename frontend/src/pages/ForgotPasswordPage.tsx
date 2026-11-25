import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, LockKeyhole, Mail, ShieldCheck } from 'lucide-react'

import { ApiError, forgotPassword } from '../services/api'
import './Auth.css'

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setNotice('')

    const normalized = email.trim()
    if (!normalized) {
      setError('Enter your email address.')
      return
    }

    setLoading(true)
    try {
      const result = await forgotPassword(normalized)
      setNotice(
        result.message ||
          'If an account exists for that email, a password reset link has been sent.',
      )
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message)
      } else {
        setError('Unable to submit password reset request. Please try again.')
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

      <section className="auth-card" aria-labelledby="forgot-heading">
        <h1 id="forgot-heading">Reset your password</h1>
        <p className="auth-subtitle">
          Enter your email address and we will send you a single-use reset link
          valid for 15 minutes.
        </p>

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

        <form className="auth-form" onSubmit={handleSubmit}>
          <label htmlFor="forgot-email">Email</label>

          <div className="auth-input-wrap">
            <Mail size={17} />
            <input
              id="forgot-email"
              type="email"
              autoComplete="email"
              placeholder="name@company.com"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              disabled={loading}
              required
            />
          </div>

          <button className="auth-submit" type="submit" disabled={loading}>
            {loading ? 'Sending...' : 'Send reset link'}
            {!loading && <ArrowRight size={17} />}
          </button>
        </form>

        <div className="auth-switch">
          Remembered your password? <Link to="/">Back to sign in</Link>
        </div>

        <div className="auth-security-note">
          <LockKeyhole size={13} />
          Protected access · Single-use 15-minute reset links
        </div>
      </section>

      <footer className="auth-footer">
        CREATORXDR <span>•</span> IDENTITY AND SECURITY
      </footer>
    </main>
  )
}
