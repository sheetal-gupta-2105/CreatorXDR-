
import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { Link } from 'react-router-dom'

import {
  ArrowRight,
  Eye,
  EyeOff,
  Fingerprint,
  LockKeyhole,
  Mail,
  UserRound,
  ShieldCheck,
} from 'lucide-react'

import { ApiError, resendOtp } from '../services/api'
import { useAuth } from '../context/AuthContext'
import './Auth.css'

type AuthMode = 'login' | 'register' | 'verify'

export default function AuthPage() {
  const { login, register, verify } = useAuth()

  const [mode, setMode] = useState<AuthMode>('login')
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')

  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [resendLoading, setResendLoading] = useState(false)
  const [resendCooldown, setResendCooldown] = useState(0)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    if (resendCooldown <= 0) {
      return
    }
    const timer = window.setInterval(() => {
      setResendCooldown((prev) => (prev <= 1 ? 0 : prev - 1))
    }, 1000)
    return () => window.clearInterval(timer)
  }, [resendCooldown])

  function changeMode(nextMode: AuthMode) {
    setMode(nextMode)
    setError('')
    setNotice('')
    setPassword('')
    setCode('')
    setFullName('')
  }

  async function handleResendOtp() {
    if (resendCooldown > 0 || resendLoading || !email.trim()) {
      return
    }
    setError('')
    setNotice('')
    setResendLoading(true)
    try {
      const result = await resendOtp(email.trim())
      setNotice(
        result.message ||
          'If an unverified account exists for that email, a new verification code has been sent.',
      )
      setResendCooldown(60)
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message)
      } else {
        setError('Unable to resend verification code. Please try again.')
      }
    } finally {
      setResendLoading(false)
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    setError('')
    setNotice('')

    if (!email.trim()) {
      setError('Enter your email address.')
      return
    }

    if (mode === 'register') {
      const name = fullName.trim()

      if (!name) {
        setError('Enter your full name.')
        return
      }

      if (name.length > 120) {
        setError('Your name must be under 120 characters.')
        return
      }
    }

    if (mode !== 'verify' && password.length < 12) {
      setError('Your password must contain at least 12 characters.')
      return
    }

    if (mode === 'verify' && !/^\d{6}$/.test(code)) {
      setError('Enter the six-digit verification code.')
      return
    }

    setLoading(true)

    try {
      if (mode === 'register') {
        const message = await register(
          fullName.trim(),
          email.trim(),
          password,
        )

        setNotice(
          message ||
            'Your account was created. Check your email for the verification code.',
        )

        setMode('verify')
        setResendCooldown(60)
        setPassword('')
        setCode('')
      } else if (mode === 'verify') {
        const message = await verify(email.trim(), code)

        setNotice(message || 'Email verified. You can now sign in.')

        setCode('')
        setPassword('')
        setMode('login')
      } else {
        await login(email.trim(), password)
      }
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          if (err.message.toLowerCase().includes('verification')) {
            setError(
              'Email verification is required before signing in. Please verify your email.',
            )
          } else {
            setError(
              'Your account is suspended or locked. Please contact support.',
            )
          }
        } else {
          setError(err.message)
        }
      } else {
        setError('Something went wrong. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  const isVerifyMode = mode === 'verify'
  const isRegisterMode = mode === 'register'

  return (
    <main className="auth-screen">
      <div className="auth-background-glow auth-glow-one" />
      <div className="auth-background-glow auth-glow-two" />

      <section className="auth-card">
        <div className="auth-brand">
          <div className="auth-brand-mark">
            <ShieldCheck size={23} strokeWidth={2.1} />
          </div>

          <div>
            <div className="auth-brand-name">
              creator<span>xd</span>r
            </div>
            <div className="auth-brand-caption">
              CREATOR SECURITY PLATFORM
            </div>
          </div>
        </div>

        <div className="auth-divider" />

        <div className="auth-heading">
          <div className="auth-heading-icon">
            {isVerifyMode ? (
              <Mail size={20} />
            ) : isRegisterMode ? (
              <Fingerprint size={21} />
            ) : (
              <LockKeyhole size={20} />
            )}
          </div>

          <p className="auth-eyebrow">
            {isVerifyMode
              ? 'EMAIL VERIFICATION'
              : isRegisterMode
                ? 'CREATE YOUR ACCOUNT'
                : 'SECURE ACCESS'}
          </p>

          <h1>
            {isVerifyMode
              ? 'Verify your email.'
              : isRegisterMode
                ? 'Create your identity.'
                : 'Welcome back.'}
          </h1>

          <p className="auth-subtitle">
            {isVerifyMode
              ? `Enter the six-digit code sent to ${email}.`
              : isRegisterMode
                ? 'Start protecting your creator identity with CreatorXDR.'
                : 'Sign in to access your creator security workspace.'}
          </p>
        </div>

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
          {isRegisterMode && (
            <>
              <label htmlFor="auth-full-name">Full name</label>

              <div className="auth-input-wrap">
                <UserRound size={17} />

                <input
                  id="auth-full-name"
                  type="text"
                  autoComplete="name"
                  placeholder="Enter your full name"
                  value={fullName}
                  onChange={(event) => setFullName(event.target.value)}
                  disabled={loading}
                  maxLength={120}
                  required
                />
              </div>
            </>
          )}

          <label htmlFor="auth-email">Email address</label>

          <div className="auth-input-wrap">
            <Mail size={17} />

            <input
              id="auth-email"
              type="email"
              autoComplete="email"
              placeholder="you@example.com"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              disabled={loading || isVerifyMode}
              required
            />
          </div>

          {!isVerifyMode && (
            <>
              <label htmlFor="auth-password">Password</label>

              <div className="auth-input-wrap">
                <LockKeyhole size={17} />

                <input
                  id="auth-password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete={
                    isRegisterMode ? 'new-password' : 'current-password'
                  }
                  placeholder={
                    isRegisterMode
                      ? 'At least 12 characters'
                      : 'Enter your password'
                  }
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={loading}
                  minLength={12}
                  required
                />

                <button
                  className="auth-password-toggle"
                  type="button"
                  onClick={() => setShowPassword((current) => !current)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? (
                    <EyeOff size={17} />
                  ) : (
                    <Eye size={17} />
                  )}
                </button>
              </div>

              {isRegisterMode && (
                <p className="auth-field-hint">
                  Use at least 12 characters. A longer, unique passphrase is
                  better.
                </p>
              )}

              {!isRegisterMode && (
                <div className="auth-forgot-row">
                  <Link className="auth-forgot-link" to="/forgot-password">
                    Forgot password?
                  </Link>
                </div>
              )}
            </>
          )}

          {isVerifyMode && (
            <>
              <label htmlFor="auth-code">Verification code</label>

              <div className="auth-input-wrap auth-code-wrap">
                <Fingerprint size={17} />

                <input
                  id="auth-code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="000000"
                  maxLength={6}
                  value={code}
                  onChange={(event) =>
                    setCode(
                      event.target.value.replace(/\D/g, '').slice(0, 6),
                    )
                  }
                  disabled={loading}
                  required
                />
              </div>

              <div className="auth-resend-row">
                <p className="auth-field-hint">
                  Code expires in 10 minutes. Do not share it.
                </p>
                <button
                  type="button"
                  className="auth-resend-btn"
                  onClick={handleResendOtp}
                  disabled={loading || resendLoading || resendCooldown > 0}
                >
                  {resendLoading
                    ? 'Sending...'
                    : resendCooldown > 0
                      ? `Resend code in ${resendCooldown}s`
                      : 'Resend code'}
                </button>
              </div>
            </>
          )}

          <button className="auth-submit" type="submit" disabled={loading}>
            {loading
              ? 'Please wait...'
              : isVerifyMode
                ? 'Verify email'
                : isRegisterMode
                  ? 'Create account'
                  : 'Sign in'}

            {!loading && <ArrowRight size={17} />}
          </button>
        </form>

        <div className="auth-switch">
          {isVerifyMode ? (
            <>
              Used the wrong email?{' '}
              <button
                type="button"
                onClick={() => changeMode('register')}
                disabled={loading}
              >
                Go back
              </button>
            </>
          ) : isRegisterMode ? (
            <>
              Already have an account?{' '}
              <button
                type="button"
                onClick={() => changeMode('login')}
                disabled={loading}
              >
                Sign in
              </button>
            </>
          ) : (
            <>
              New to CreatorXDR?{' '}
              <button
                type="button"
                onClick={() => changeMode('register')}
                disabled={loading}
              >
                Create an account
              </button>
            </>
          )}
        </div>

        <div className="auth-security-note">
          <LockKeyhole size={13} />
          Protected access · Local development environment
        </div>
      </section>

      <footer className="auth-footer">
        CREATORXDR <span>•</span> IDENTITY AND SECURITY
      </footer>
    </main>
  )
}
