import ThreatMonitoringPage from './pages/ThreatMonitoringPage'
import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { ClipboardCheck } from 'lucide-react'
import AdminVerificationPage from './pages/AdminVerificationPage'
import AdminBlockchainPage from './pages/AdminBlockchainPage'
import { getThreatDetections } from './services/threatApi'
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Bell,
  Blocks,
  ChevronDown,
  CircleHelp,
  Fingerprint,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  Settings,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Users,
  X,
  FileClock,
  Link2,
  LogOut,
  ScanSearch,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import {
  NavLink,
  Route,
  Routes,
  useLocation,
} from 'react-router-dom'
import IdentityPage from './pages/IdentityPage'
import ForgotPasswordPage from './pages/ForgotPasswordPage'
import ResetPasswordPage from './pages/ResetPasswordPage'
import { useAuth } from './context/AuthContext'
import './App.css'

type NavigationItem = {
  label: string
  path: string
  icon: LucideIcon
  section: string
}

const navigation: NavigationItem[] = [
  {
    label: 'Overview',
    path: '/',
    icon: LayoutDashboard,
    section: 'WORKSPACE',
  },
  {
    label: 'Identity',
    path: '/identity',
    icon: Fingerprint,
    section: 'WORKSPACE',
  },
  {
    label: 'Connected accounts',
    path: '/accounts',
    icon: Link2,
    section: 'WORKSPACE',
  },
  {
    label: 'Threat monitoring',
    path: '/threats',
    icon: ScanSearch,
    section: 'SECURITY',
  },
  {
    label: 'Security reports',
    path: '/reports',
    icon: FileClock,
    section: 'SECURITY',
  },
  {
    label: 'Audit trail',
    path: '/audit',
    icon: Activity,
    section: 'SECURITY',
  },
  {
    label: 'Identity review',
    path: '/admin/verification',
    icon: ClipboardCheck,
    section: 'ADMIN',
  },
  {
    label: 'Blockchain audit',
    path: '/admin/blockchain',
    icon: Blocks,
    section: 'ADMIN',
  },
]

function getDisplayName(
  fullName?: string | null,
  email?: string | null,
): string {
  return (
    fullName?.trim() ||
    email?.split('@')[0] ||
    'Creator'
  )
}

function getInitials(name: string): string {
  return (
    name
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0].toUpperCase())
      .join('') || 'CR'
  )
}

function Sidebar({
  mobileOpen,
  onClose,
}: {
  mobileOpen: boolean
  onClose: () => void
}) {
  const { logout, user } = useAuth()

  const canPollThreats =
    user?.role?.toUpperCase() === 'CREATOR' && Boolean(user.email_verified)

  const [activeThreatCount, setActiveThreatCount] =
    useState<number | null>(null)

  useEffect(() => {
    if (!canPollThreats) {
      return
    }

    let isMounted = true

    const fetchThreatCount = async () => {
      try {
        const response = await getThreatDetections()

        const activeCount = response.detections.filter(
          (detection) =>
            !['SAFE', 'DISMISSED'].includes(
              detection.investigation_status.toUpperCase(),
            ),
        ).length

        if (isMounted) {
          setActiveThreatCount(activeCount)
        }
      } catch {
        // Keep navigation usable if threat data is unavailable.
      }
    }

    void fetchThreatCount()

    const intervalId = window.setInterval(
      fetchThreatCount,
      30_000,
    )

    return () => {
      isMounted = false
      window.clearInterval(intervalId)
    }
  }, [canPollThreats, user?.id])

  const visibleThreatCount = canPollThreats ? activeThreatCount : null

  const isAdmin = user?.role?.toUpperCase() === 'ADMIN'

  const displayName = getDisplayName(
    user?.full_name,
    user?.email,
  )

  const initials = getInitials(displayName)

  const accountLabel = isAdmin
    ? 'Admin account'
    : 'Creator account'

  const visibleSections = isAdmin
    ? ['WORKSPACE', 'SECURITY', 'ADMIN']
    : ['WORKSPACE', 'SECURITY']

  return (
    <>
      {mobileOpen && (
        <button
          className="sidebar-overlay"
          aria-label="Close navigation"
          onClick={onClose}
        />
      )}

      <aside className={`sidebar ${mobileOpen ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={21} strokeWidth={2.2} />
          </div>

          <div className="brand-copy">
            <span className="brand-name">
              creator<span>xd</span>r
            </span>
            <span className="brand-caption">
              CREATOR SECURITY
            </span>
          </div>

          <button
            className="icon-button sidebar-close"
            onClick={onClose}
            aria-label="Close navigation"
          >
            <X size={19} />
          </button>
        </div>

        <div className="workspace-switcher">
          <div className="workspace-avatar">
            {initials}
          </div>

          <div className="workspace-copy">
            <strong>
              {isAdmin ? 'Admin workspace' : 'Personal workspace'}
            </strong>
            <span>{accountLabel}</span>
          </div>

          <ChevronDown size={15} className="muted-icon" />
        </div>

        <nav
          className="side-navigation"
          aria-label="Main navigation"
        >
          {visibleSections.map((section) => (
            <div className="nav-section" key={section}>
              <p className="nav-section-title">
                {section}
              </p>

              {navigation
                .filter(
                  (item) =>
                    item.section === section &&
                    (item.path !== '/threats' || canPollThreats),
                )
                .map((item) => {
                  const Icon = item.icon

                  return (
                    <NavLink
                      key={item.path}
                      to={item.path}
                      end={item.path === '/'}
                      onClick={onClose}
                      className={(navState) =>
                        navState.isActive
                          ? 'nav-link nav-link-active'
                          : 'nav-link'
                      }
                    >
                      <Icon size={17} strokeWidth={1.8} />

                      <span>{item.label}</span>

                      {item.path === '/threats' &&
  visibleThreatCount !== null &&
  visibleThreatCount > 0 && (
    <span className="nav-count">
      {visibleThreatCount > 99
        ? '99+'
        : visibleThreatCount}
    </span>
  )}
                    </NavLink>
                  )
                })}
            </div>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="help-card">
            <div className="help-icon">
              <CircleHelp size={17} />
            </div>

            <div>
              <strong>Need a hand?</strong>
              <span>Explore the security guide</span>
            </div>

            <ArrowUpRight size={15} />
          </div>

          <NavLink
            to="/settings"
            className="nav-link settings-link"
            onClick={onClose}
          >
            <Settings size={17} />
            <span>Settings</span>
          </NavLink>

          <button
            type="button"
            className="nav-link settings-link"
            onClick={() => {
              onClose()
              logout()
            }}
            aria-label="Log out of CreatorXDR"
            style={{
              width: '100%',
              border: 0,
              background: 'transparent',
              textAlign: 'left',
              font: 'inherit',
              cursor: 'pointer',
            }}
          >
            <LogOut size={17} />
            <span>Log out</span>
          </button>

          <div className="profile-row">
            <div className="profile-avatar">
              {initials}
            </div>

            <div className="profile-copy">
              <strong>{displayName}</strong>
              <span>{accountLabel}</span>
            </div>

            <button
              className="icon-button profile-menu"
              aria-label="Profile menu"
            >
              <MoreIcon />
            </button>
          </div>
        </div>
      </aside>
    </>
  )
}

function MoreIcon() {
  return (
    <span className="more-dots" aria-hidden="true">
      <span />
      <span />
      <span />
    </span>
  )
}

function Topbar({
  onMenuClick,
}: {
  onMenuClick: () => void
}) {
  const [notificationsOpen, setNotificationsOpen] =
    useState(false)

  const { user } = useAuth()

  const displayName = getDisplayName(
    user?.full_name,
    user?.email,
  )

  const initials = getInitials(displayName)

  return (
    <header className="topbar">
      <div className="topbar-left">
        <button
          className="icon-button mobile-menu-button"
          onClick={onMenuClick}
          aria-label="Open navigation"
        >
          <Menu size={21} />
        </button>

        <div className="breadcrumb">
          <span>Workspace</span>
          <span className="breadcrumb-separator">/</span>
          <strong>Overview</strong>
        </div>
      </div>

      <div className="topbar-actions">
        <div className="system-status">
          <span className="status-dot" />
          Systems operational
        </div>

        <div className="notification-wrapper">
          <button
            className="icon-button notification-button"
            aria-label="Notifications"
            onClick={() =>
              setNotificationsOpen(!notificationsOpen)
            }
          >
            <Bell size={19} />
            <span className="notification-indicator" />
          </button>

          {notificationsOpen && (
            <div className="notification-popover">
              <div className="notification-popover-header">
                <strong>Notifications</strong>
                <span className="demo-tag">DEMO</span>
              </div>

              <div className="notification-item">
                <div className="notification-item-icon warning-icon">
                  <AlertTriangle size={16} />
                </div>

                <div>
                  <strong>Unusual sign-in detected</strong>
                  <p>
                    Example security event for the dashboard preview.
                  </p>
                  <span>Demo notification</span>
                </div>
              </div>

              <div className="notification-item">
                <div className="notification-item-icon success-icon">
                  <ShieldCheck size={16} />
                </div>

                <div>
                  <strong>Security checks active</strong>
                  <p>
                    Your local workspace is ready for setup.
                  </p>
                  <span>Demo notification</span>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="topbar-divider" />

        <button
          className="topbar-avatar"
          aria-label={`Account: ${displayName}`}
        >
          {initials}
        </button>
      </div>
    </header>
  )
}

function MetricCard({
  label,
  value,
  detail,
  icon: Icon,
  tone,
  trend,
}: {
  label: string
  value: string
  detail: string
  icon: LucideIcon
  tone: 'blue' | 'green' | 'amber' | 'violet'
  trend?: 'up' | 'down'
}) {
  return (
    <article className="metric-card">
      <div className="metric-card-top">
        <span className="metric-label">{label}</span>

        <span className={`metric-icon metric-${tone}`}>
          <Icon size={18} strokeWidth={1.9} />
        </span>
      </div>

      <div className="metric-value">
        {value}
      </div>

      <div className="metric-footer">
        <span
          className={`metric-trend ${
            trend === 'down' ? 'trend-down' : ''
          }`}
        >
          {trend === 'down' ? (
            <ArrowDownRight size={14} />
          ) : (
            <ArrowUpRight size={14} />
          )}

          {detail}
        </span>

        <span className="metric-period">
          vs. last 30 days
        </span>
      </div>
    </article>
  )
}

function SecurityScore() {
  return (
    <section className="panel score-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">YOUR SECURITY</p>
          <h2>Security posture</h2>
        </div>

        <span className="demo-tag">
          DEMO DATA
        </span>
      </div>

      <div className="score-content">
        <div className="score-ring">
          <svg
            viewBox="0 0 160 160"
            role="img"
            aria-label="Demo security score 82 out of 100"
          >
            <circle
              cx="80"
              cy="80"
              r="67"
              fill="none"
              stroke="rgba(255,255,255,0.07)"
              strokeWidth="9"
            />

            <circle
              cx="80"
              cy="80"
              r="67"
              fill="none"
              stroke="#64d8b0"
              strokeWidth="9"
              strokeLinecap="round"
              strokeDasharray="344 421"
              transform="rotate(-90 80 80)"
            />
          </svg>

          <div className="score-number">
            <strong>82</strong>
            <span>OUT OF 100</span>
          </div>
        </div>

        <div className="score-description">
          <div className="score-status">
            <span className="score-status-dot" />
            Good standing
          </div>

          <h3>Your security foundation looks strong.</h3>

          <p>
            This is a sample score for the interface preview. It will be
            calculated from real security signals once monitoring is connected.
          </p>

          <button
            className="text-action"
            onClick={() => window.location.assign('/reports')}
          >
            View security report <ArrowRight size={15} />
          </button>
        </div>
      </div>

      <div className="score-breakdown">
        <div className="breakdown-item">
          <span>Identity protection</span>
          <div className="breakdown-track">
            <span style={{ width: '90%' }} />
          </div>
          <strong>90%</strong>
        </div>

        <div className="breakdown-item">
          <span>Account security</span>
          <div className="breakdown-track">
            <span style={{ width: '76%' }} />
          </div>
          <strong>76%</strong>
        </div>

        <div className="breakdown-item">
          <span>Threat awareness</span>
          <div className="breakdown-track">
            <span style={{ width: '80%' }} />
          </div>
          <strong>80%</strong>
        </div>
      </div>
    </section>
  )
}

function ActivityPanel() {
  const events = [
    {
      icon: ShieldCheck,
      tone: 'activity-green',
      title: 'Identity verification workspace created',
      description: 'Your verification profile is ready to be completed.',
      time: 'Getting started',
      status: 'INFO',
    },
    {
      icon: LockKeyhole,
      tone: 'activity-blue',
      title: 'Account security initialized',
      description: 'Local account security services are available.',
      time: 'Getting started',
      status: 'INFO',
    },
    {
      icon: AlertTriangle,
      tone: 'activity-amber',
      title: 'Sample phishing alert',
      description: 'Illustrative event. No URL has been analyzed.',
      time: 'Demo event',
      status: 'DEMO',
    },
  ]

  return (
    <section className="panel activity-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">WHAT'S HAPPENING</p>
          <h2>Recent activity</h2>
        </div>

        <span className="demo-tag">DEMO DATA</span>
      </div>

      <div className="activity-list">
        {events.map((event, index) => {
          const Icon = event.icon

          return (
            <div className="activity-item" key={event.title}>
              <div className={`activity-icon ${event.tone}`}>
                <Icon size={17} />
              </div>

              <div className="activity-copy">
                <strong>{event.title}</strong>
                <p>{event.description}</p>
                <span>{event.time}</span>
              </div>

              <span
                className={`activity-status ${
                  index === 2 ? 'activity-demo' : ''
                }`}
              >
                {event.status}
              </span>
            </div>
          )
        })}
      </div>

      <button
        className="panel-footer-action"
        onClick={() => window.location.assign('/audit')}
      >
        View activity history <ArrowRight size={15} />
      </button>
    </section>
  )
}

function SetupPanel() {
  const steps = [
    { label: 'Create your account', complete: true },
    { label: 'Verify your identity', complete: false },
    { label: 'Connect creator accounts', complete: false },
    { label: 'Activate threat monitoring', complete: false },
  ]

  return (
    <section className="panel setup-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">GETTING STARTED</p>
          <h2>Secure your creator identity</h2>
        </div>

        <span className="setup-count">1 of 4</span>
      </div>

      <p className="setup-description">
        Complete these steps to establish your CreatorXDR security profile.
      </p>

      <div className="setup-progress">
        <span />
      </div>

      <div className="setup-steps">
        {steps.map((step, index) => (
          <div
            className={`setup-step ${
              step.complete ? 'step-complete' : ''
            }`}
            key={step.label}
          >
            <span className="step-indicator">
              {step.complete ? (
                <ShieldCheck size={15} />
              ) : (
                index + 1
              )}
            </span>

            <span>{step.label}</span>

            {step.complete && (
              <span className="step-done">DONE</span>
            )}

            {!step.complete && index === 1 && (
              <span className="step-next">NEXT</span>
            )}
          </div>
        ))}
      </div>

      <button
        className="primary-button"
        onClick={() => window.location.assign('/identity')}
      >
        Continue setup <ArrowRight size={16} />
      </button>
    </section>
  )
}

function Dashboard() {
  const { user } = useAuth()

  const hour = new Date().getHours()

  const greeting =
    hour < 12
      ? 'Good morning'
      : hour < 17
        ? 'Good afternoon'
        : 'Good evening'

  const firstName =
    user?.full_name?.trim().split(/\s+/)[0] || 'there'

  return (
    <div className="page-content">
      <div className="page-heading">
        <div>
          <div className="page-kicker">
            <span className="kicker-line" />
            CREATORXDR WORKSPACE
          </div>

          <h1>
            {greeting}, {firstName}
            <span className="heading-period">.</span>
          </h1>

          <p className="page-subtitle">
            Here's the current overview of your creator security workspace.
          </p>
        </div>

        <div className="heading-actions">
          <span className="workspace-badge">
            <span className="status-dot" />
            PERSONAL WORKSPACE
          </span>
        </div>
      </div>

      <div className="demo-notice">
        <div className="demo-notice-icon">
          <Activity size={17} />
        </div>

        <p>
          <strong>Preview environment</strong>
          Dashboard metrics and activity below are illustrative. Live monitoring
          data will appear after the relevant services are integrated.
        </p>

        <span>DEMO</span>
      </div>

      <div className="metrics-grid">
        <MetricCard
          label="Security score"
          value="82/100"
          detail="4 pts"
          icon={ShieldCheck}
          tone="green"
          trend="up"
        />

        <MetricCard
          label="Connected accounts"
          value="0"
          detail="Ready to connect"
          icon={Users}
          tone="blue"
        />

        <MetricCard
          label="Threat alerts"
          value="02"
          detail="Sample alerts"
          icon={ShieldAlert}
          tone="amber"
          trend="down"
        />

        <MetricCard
          label="Identity status"
          value="Pending"
          detail="Verification required"
          icon={Fingerprint}
          tone="violet"
        />
      </div>

      <div className="dashboard-main-grid">
        <SecurityScore />
        <SetupPanel />
      </div>

      <div className="dashboard-bottom-grid">
        <ActivityPanel />

        <section className="panel protection-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">PROTECTION CENTER</p>
              <h2>Your security toolkit</h2>
            </div>

            <Shield size={19} className="muted-icon" />
          </div>

          <div className="toolkit-list">
            <div className="toolkit-item">
              <div className="toolkit-icon toolkit-blue">
                <ScanSearch size={17} />
              </div>

              <div>
                <strong>Phishing analysis</strong>
                <span>Inspect suspicious links</span>
              </div>

              <span className="toolkit-state">AVAILABLE</span>
            </div>

            <div className="toolkit-item">
              <div className="toolkit-icon toolkit-violet">
                <Fingerprint size={17} />
              </div>

              <div>
                <strong>Identity verification</strong>
                <span>Establish your creator identity</span>
              </div>

              <span className="toolkit-state">SETUP</span>
            </div>

            <div className="toolkit-item">
              <div className="toolkit-icon toolkit-amber">
                <Users size={17} />
              </div>

              <div>
                <strong>Impersonation reports</strong>
                <span>Review suspicious profiles</span>
              </div>

              <span className="toolkit-state">SETUP</span>
            </div>
          </div>

          <div className="protection-footnote">
            <LockKeyhole size={14} />
            Tools activate as their integrations become available.
          </div>
        </section>
      </div>

      <footer className="page-footer">
        <span>
          CREATORXDR <span className="footer-dot">•</span> CREATOR SECURITY
          PLATFORM
        </span>

        <span>
          LOCAL DEVELOPMENT BUILD{' '}
          <span className="footer-version">v0.1.0</span>
        </span>
      </footer>
    </div>
  )
}

function PlaceholderPage({ title }: { title: string }) {
  return (
    <div className="page-content placeholder-page">
      <div className="page-heading">
        <div>
          <div className="page-kicker">
            <span className="kicker-line" />
            CREATORXDR WORKSPACE
          </div>

          <h1>
            {title}
            <span className="heading-period">.</span>
          </h1>

          <p className="page-subtitle">
            This section is part of the CreatorXDR workspace.
          </p>
        </div>
      </div>

      <section className="panel placeholder-panel">
        <div className="placeholder-icon">
          <Blocks size={24} />
        </div>

        <span className="demo-tag">IN DEVELOPMENT</span>

        <h2>{title} is being built.</h2>

        <p>
          This section will be connected to the backend services as development
          progresses. No simulated security actions are being performed here.
        </p>
      </section>
    </div>
  )
}

function CompleteProfile() {
  const { updateProfile, logout } = useAuth()

  const [fullName, setFullName] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    const name = fullName.trim()

    if (!name) {
      setError('Please enter your full name.')
      return
    }

    if (name.length > 120) {
      setError('Your name must be 120 characters or fewer.')
      return
    }

    try {
      setSaving(true)
      setError('')

      await updateProfile(name)
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to update your profile. Please try again.',
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="app-shell">
      <main
        className="main-area"
        style={{
          minHeight: '100vh',
          display: 'grid',
          placeItems: 'center',
          padding: '24px',
        }}
      >
        <section
          className="panel"
          style={{
            width: '100%',
            maxWidth: '460px',
            padding: '32px',
          }}
        >
          <div
            className="brand-mark"
            style={{ marginBottom: '24px' }}
          >
            <ShieldCheck size={22} />
          </div>

          <p className="eyebrow">
            COMPLETE YOUR PROFILE
          </p>

          <h1 style={{ marginBottom: '12px' }}>
            What should we call you?
          </h1>

          <p
            className="page-subtitle"
            style={{ marginBottom: '24px' }}
          >
            Add your name to personalize your CreatorXDR workspace.
          </p>

          <form onSubmit={handleSubmit}>
            <label
              htmlFor="profile-full-name"
              style={{
                display: 'block',
                marginBottom: '8px',
              }}
            >
              Full name
            </label>

            <input
              id="profile-full-name"
              type="text"
              value={fullName}
              onChange={(event) => setFullName(event.target.value)}
              placeholder="Enter your full name"
              autoComplete="name"
              maxLength={120}
              required
              style={{
                width: '100%',
                padding: '13px',
                marginBottom: '16px',
                borderRadius: '8px',
                border: '1px solid #d2d2d7',
                font: 'inherit',
                boxSizing: 'border-box',
              }}
            />

            {error && (
              <p
                role="alert"
                style={{
                  color: '#c62828',
                  marginBottom: '16px',
                }}
              >
                {error}
              </p>
            )}

            <button
              type="submit"
              className="primary-button"
              disabled={saving}
              style={{
                width: '100%',
                justifyContent: 'center',
              }}
            >
              {saving ? 'Saving...' : 'Save and continue'}
              <ArrowRight size={16} />
            </button>
          </form>

          <button
            type="button"
            onClick={logout}
            className="text-action"
            style={{ marginTop: '20px' }}
          >
            Log out
          </button>
        </section>
      </main>
    </div>
  )
}

function WorkspaceLayout() {
  const [mobileOpen, setMobileOpen] = useState(false)

  const location = useLocation()

  const { user } = useAuth()

  const isEligibleCreator =
    user?.role?.toUpperCase() === 'CREATOR' && Boolean(user.email_verified)

  const currentPage =
    navigation.find(
      (item) => item.path === location.pathname,
    )?.label ??
    (location.pathname === '/settings'
      ? 'Settings'
      : 'Workspace')

  if (user && !user.full_name?.trim()) {
    return <CompleteProfile />
  }

  return (
    <div className="app-shell">
      <Sidebar
        mobileOpen={mobileOpen}
        onClose={() => setMobileOpen(false)}
      />

      <main className="main-area">
        <Topbar
          onMenuClick={() => setMobileOpen(true)}
        />

        <Routes>
          <Route
            path="/"
            element={<Dashboard />}
          />

          <Route
            path="/identity"
            element={<IdentityPage />}
          />

          <Route
            path="/admin/verification"
            element={
              user?.role?.toUpperCase() === 'ADMIN' ? (
                <AdminVerificationPage />
              ) : (
                <PlaceholderPage title="Access denied" />
              )
            }
          />

          <Route
            path="/admin/blockchain"
            element={
              user?.role?.toUpperCase() === 'ADMIN' ? (
                <AdminBlockchainPage />
              ) : (
                <PlaceholderPage title="Access denied" />
              )
            }
          />

          <Route
            path="/accounts"
            element={
              <PlaceholderPage title="Connected accounts" />
            }
          />

          <Route
            path="/threats"
            element={
              isEligibleCreator ? (
                <ThreatMonitoringPage />
              ) : (
                <PlaceholderPage title="Access denied" />
              )
            }
          />
          <Route
            path="/reports"
            element={
              <PlaceholderPage title="Security reports" />
            }
          />

          <Route
            path="/audit"
            element={
              <PlaceholderPage title="Audit trail" />
            }
          />

          <Route
            path="/settings"
            element={
              <PlaceholderPage title="Settings" />
            }
          />

          <Route
            path="/forgot-password"
            element={<ForgotPasswordPage />}
          />

          <Route
            path="/reset-password"
            element={<ResetPasswordPage />}
          />

          <Route
            path="*"
            element={
              <PlaceholderPage title={currentPage} />
            }
          />
        </Routes>
      </main>
    </div>
  )
}

function App() {
  return <WorkspaceLayout />
}

export default App
