
import { useCallback, useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  CircleHelp,
  Clock3,
  ImagePlus,
  LoaderCircle,
  Plus,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  UserRound,
  X,
} from 'lucide-react'
import {
  analyzeCandidateProfile,
  createReferenceProfile,
  getReferenceProfiles,
  getThreatDetections,
  updateThreatStatus,
  uploadReferenceProfileImage,
  ThreatApiError,
} from '../services/threatApi'
import type {
  InvestigationStatus,
  ProfileInput,
  RiskLevel,
  SocialPlatform,
  SocialProfile,
  ThreatDetection,
} from '../services/threatApi'
import { useAuth } from '../context/AuthContext'
import './ThreatMonitoring.css'

const PLATFORMS: SocialPlatform[] = [
  'INSTAGRAM',
  'YOUTUBE',
  'TIKTOK',
  'X',
  'OTHER',
]

const STATUSES: InvestigationStatus[] = [
  'NEW',
  'REVIEWING',
  'CONFIRMED',
  'SAFE',
  'DISMISSED',
]

function formatDate(value: string): string {
  const date = new Date(value)

  if (Number.isNaN(date.getTime())) return 'Date unavailable'

  return new Intl.DateTimeFormat(undefined, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

function platformLabel(value: string): string {
  return value === 'X' ? 'X' : value.charAt(0) + value.slice(1).toLowerCase()
}

function statusLabel(value: string): string {
  return value.charAt(0) + value.slice(1).toLowerCase().replaceAll('_', ' ')
}

function getErrorMessage(error: unknown): string {
  if (error instanceof ThreatApiError && error.status === 401) {
    return 'Your session has expired. Please sign in again.'
  }

  return error instanceof Error
    ? error.message
    : 'Something went wrong. Please try again.'
}

function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span className={`threat-risk-badge threat-risk-${level.toLowerCase()}`}>
      <span />
      {level}
    </span>
  )
}

function StatusBadge({ status }: { status: InvestigationStatus }) {
  return (
    <span className={`threat-status-badge threat-status-${status.toLowerCase()}`}>
      {statusLabel(status)}
    </span>
  )
}

function MetricCard({
  label,
  value,
  description,
  icon: Icon,
}: {
  label: string
  value: number
  description: string
  icon: typeof ShieldAlert
}) {
  return (
    <article className="threat-metric-card">
      <div className="threat-metric-top">
        <span>{label}</span>
        <span className="threat-metric-icon">
          <Icon size={18} />
        </span>
      </div>
      <strong>{value}</strong>
      <p>{description}</p>
    </article>
  )
}

function ProfileForm({
  title,
  description,
  submitLabel,
  busy,
  onSubmit,
  onCancel,
}: {
  title: string
  description: string
  submitLabel: string
  busy: boolean
  onSubmit: (profile: ProfileInput, image?: File) => Promise<void>
  onCancel?: () => void
}) {
  const [platform, setPlatform] = useState<SocialPlatform>('INSTAGRAM')
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [bio, setBio] = useState('')
  const [formError, setFormError] = useState('')
  const [image, setImage] = useState<File | undefined>()

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setFormError('')

    if (!username.trim()) {
      setFormError('Enter a username to continue.')
      return
    }

    try {
      await onSubmit(
        {
          platform,
          username: username.trim().replace(/^@/, ''),
          display_name: displayName.trim(),
          bio: bio.trim(),
        },
        image,
      )
      setImage(undefined)
      setUsername('')
      setDisplayName('')
      setBio('')
    } catch (error) {
      setFormError(getErrorMessage(error))
    }
  }

  return (
    <form className="threat-form" onSubmit={handleSubmit}>
      <div className="threat-form-heading">
        <div>
          <h3>{title}</h3>
          <p>{description}</p>
        </div>
        {onCancel && (
          <button
            type="button"
            className="threat-icon-button"
            onClick={onCancel}
            aria-label="Close form"
          >
            <X size={18} />
          </button>
        )}
      </div>

      <label className="threat-field">
        <span>Platform</span>
        <select
          value={platform}
          onChange={(event) => setPlatform(event.target.value as SocialPlatform)}
          disabled={busy}
        >
          {PLATFORMS.map((item) => (
            <option key={item} value={item}>
              {platformLabel(item)}
            </option>
          ))}
        </select>
      </label>

      <label className="threat-field">
        <span>Username <small>Required</small></span>
        <input
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          placeholder="@username"
          maxLength={100}
          disabled={busy}
          required
        />
      </label>

      <label className="threat-field">
        <span>Display name</span>
        <input
          value={displayName}
          onChange={(event) => setDisplayName(event.target.value)}
          placeholder="Profile display name"
          maxLength={150}
          disabled={busy}
        />
      </label>

      <label className="threat-field">
        <span>Bio</span>
        <textarea
          value={bio}
          onChange={(event) => setBio(event.target.value)}
          placeholder="Paste the profile biography"
          maxLength={5000}
          rows={3}
          disabled={busy}
        />
      </label>
      <label className="threat-field">
  <span>Profile image <small>Optional</small></span>
  <input
    type="file"
    accept="image/jpeg,image/png,image/webp"
    disabled={busy}
    onChange={(event) => {
      const file = event.target.files?.[0]

      if (!file) {
        setImage(undefined)
        return
      }

      const allowedTypes = [
        'image/jpeg',
        'image/png',
        'image/webp',
      ]

      if (!allowedTypes.includes(file.type)) {
        setFormError('Choose a JPEG, PNG or WebP image.')
        event.target.value = ''
        setImage(undefined)
        return
      }

      if (file.size > 5 * 1024 * 1024) {
        setFormError('The image must be smaller than 5 MB.')
        event.target.value = ''
        setImage(undefined)
        return
      }

      setFormError('')
      setImage(file)
    }}
  />
  <small>
    {image ? `Selected: ${image.name}` : 'Maximum size 5 MB. Image comparison is optional.'}
  </small>
</label>
      {formError && (
        <div className="threat-message threat-message-error" role="alert">
          <AlertCircle size={16} />
          {formError}
        </div>
      )}

      <div className="threat-form-actions">
        {onCancel && (
          <button
            type="button"
            className="threat-secondary-button"
            onClick={onCancel}
            disabled={busy}
          >
            Cancel
          </button>
        )}
        <button
          type="submit"
          className="primary-button threat-submit-button"
          disabled={busy}
        >
          {busy ? (
            <>
              <LoaderCircle size={16} className="threat-spinner" />
              Processing
            </>
          ) : (
            <>
              {submitLabel}
              <ChevronRight size={16} />
            </>
          )}
        </button>
      </div>
    </form>
  )
}

function DetectionDetails({
  detection,
  onStatusChange,
  updating,
  onClose,
}: {
  detection: ThreatDetection
  onStatusChange: (status: InvestigationStatus) => void
  updating: boolean
  onClose: () => void
}) {
  const scores = Object.entries(detection.feature_scores ?? {})

  return (
    <section className="panel threat-detail-panel">
      <div className="threat-detail-heading">
        <div>
          <p className="eyebrow">DETECTION DETAILS</p>
          <h2>@{detection.candidate_username ?? detection.candidate_profile?.username ?? 'Unknown'}</h2>
        </div>
        <button
          type="button"
          className="threat-icon-button"
          onClick={onClose}
          aria-label="Close detection details"
        >
          <X size={18} />
        </button>
      </div>

      <div className="threat-detail-summary">
        <div>
          <span>Risk score</span>
          <strong>{detection.risk_score.toFixed(1)}<small>/100</small></strong>
        </div>
        <RiskBadge level={detection.risk_level} />
      </div>

      <div className="threat-detail-meta">
        <div>
          <span>Reference profile</span>
          <strong>@{detection.reference_username ?? 'Unknown'}</strong>
        </div>
        <div>
          <span>Candidate platform</span>
          <strong>{platformLabel(detection.candidate_profile?.platform ?? 'OTHER')}</strong>
        </div>
        <div>
          <span>Detected</span>
          <strong>{formatDate(detection.created_at)}</strong>
        </div>
      </div>

      <div className="threat-detail-section">
        <h3>Signal comparison</h3>
        {scores.length === 0 ? (
          <p className="threat-muted">No feature scores were returned.</p>
        ) : (
          <div className="threat-score-list">
            {scores.map(([name, score]) => (
              <div className="threat-score-row" key={name}>
                <div className="threat-score-label">
                  <span>{name.replaceAll('_', ' ')}</span>
                  <strong>
                    {typeof score === 'number' ? `${score.toFixed(1)}%` : 'Unavailable'}
                  </strong>
                </div>
                <div className="threat-score-track">
                  <span
                    style={{
                      width: `${typeof score === 'number' ? Math.min(100, Math.max(0, score)) : 0}%`,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="threat-detail-section">
        <h3>Evidence</h3>
        {detection.evidence?.length ? (
          <ul className="threat-evidence-list">
            {detection.evidence.map((item, index) => (
              <li key={`${item}-${index}`}>
                <CheckCircle2 size={15} />
                {item}
              </li>
            ))}
          </ul>
        ) : (
          <p className="threat-muted">No evidence details available.</p>
        )}
      </div>

      <div className="threat-detail-section">
        <h3>Signal availability</h3>
        <div className="threat-signal-tags">
          {(detection.available_signals ?? []).map((signal) => (
            <span className="signal-available" key={signal}>{signal.replaceAll('_', ' ')}</span>
          ))}
          {(detection.missing_signals ?? []).map((signal) => (
            <span className="signal-missing" key={signal}>{signal.replaceAll('_', ' ')} unavailable</span>
          ))}
        </div>
      </div>

      {detection.scoring_note && (
        <p className="threat-scoring-note">
          <CircleHelp size={15} />
          {detection.scoring_note}
        </p>
      )}

      <div className="threat-detail-section">
        <label className="threat-field">
          <span>Investigation status</span>
          <select
            value={detection.investigation_status}
            disabled={updating}
            onChange={(event) =>
              onStatusChange(event.target.value as InvestigationStatus)
            }
          >
            {STATUSES.map((status) => (
              <option key={status} value={status}>
                {statusLabel(status)}
              </option>
            ))}
          </select>
        </label>
      </div>
    </section>
  )
}

export default function ThreatMonitoringPage() {
  const { user } = useAuth()
  const isEligibleCreator =
    user?.role?.toUpperCase() === 'CREATOR' && Boolean(user.email_verified)

  const [profiles, setProfiles] = useState<SocialProfile[]>([])
  const [detections, setDetections] = useState<ThreatDetection[]>([])
  const [selectedDetectionId, setSelectedDetectionId] = useState<string | null>(null)
  const [selectedReferenceId, setSelectedReferenceId] = useState('')
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [savingProfile, setSavingProfile] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [updatingStatus, setUpdatingStatus] = useState(false)
  const [showReferenceForm, setShowReferenceForm] = useState(false)
  const [showAnalysisForm, setShowAnalysisForm] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [search, setSearch] = useState('')
  const [uploadingReferenceId, setUploadingReferenceId] = useState<string | null>(null)
  const loadDashboard = useCallback(async (refresh = false) => {
    if (!isEligibleCreator) {
      return
    }

    if (refresh) setRefreshing(true)
    else setLoading(true)

    setError('')

    try {
      const [profileData, detectionData] = await Promise.all([
        getReferenceProfiles(),
        getThreatDetections(),
      ])

      setProfiles(profileData)
      setDetections(detectionData.detections)

      setSelectedReferenceId((current) => {
        if (current && profileData.some((profile) => profile.id === current)) {
          return current
        }
        return profileData[0]?.id ?? ''
      })
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [isEligibleCreator])

  useEffect(() => {
    if (!isEligibleCreator) {
      return
    }
    void loadDashboard()
  }, [isEligibleCreator, loadDashboard])

  const selectedDetection = useMemo(
    () => detections.find((item) => item.id === selectedDetectionId) ?? null,
    [detections, selectedDetectionId],
  )

  const metrics = useMemo(() => ({
    total: detections.length,
    highRisk: detections.filter(
      (item) => item.risk_level === 'HIGH' || item.risk_level === 'CRITICAL',
    ).length,
    critical: detections.filter((item) => item.risk_level === 'CRITICAL').length,
    reviewing: detections.filter(
      (item) => item.investigation_status === 'REVIEWING',
    ).length,
  }), [detections])

  const filteredDetections = useMemo(() => {
    const query = search.trim().toLowerCase()

    if (!query) return detections

    return detections.filter((item) => {
      const username = item.candidate_username ?? item.candidate_profile?.username ?? ''
      const reference = item.reference_username ?? ''
      return (
        username.toLowerCase().includes(query) ||
        reference.toLowerCase().includes(query) ||
        item.risk_level.toLowerCase().includes(query) ||
        item.investigation_status.toLowerCase().includes(query)
      )
    })
  }, [detections, search])
  async function handleReferenceImageUpload(
    profileId: string,
    image?: File,
  ) {
    if (!image) return

    setUploadingReferenceId(profileId)
    setError('')
    setNotice('')

    try {
      const updatedProfile = await uploadReferenceProfileImage(
        profileId,
        image,
      )

      setProfiles((current) =>
        current.map((profile) =>
          profile.id === profileId ? updatedProfile : profile,
        ),
      )

      setNotice('Reference profile image uploaded successfully.')
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setUploadingReferenceId(null)
    }
  }
  async function handleCreateReference(
    profile: ProfileInput,
    image?: File,
  ) {
    setSavingProfile(true)
    setError('')
    setNotice('')

    try {
      const created = await createReferenceProfile(profile, image)

      setProfiles((current) => [created, ...current])
      setSelectedReferenceId(created.id)
      setShowReferenceForm(false)
      setNotice('Your reference profile has been saved.')
    } finally {
      setSavingProfile(false)
    }
  }

  async function handleAnalyze(
    profile: ProfileInput,
    image?: File,
  ) {
    if (!selectedReferenceId) {
      setError('Add a genuine reference profile before analyzing candidates.')
      return
    }

    setAnalyzing(true)
    setError('')
    setNotice('')

    try {
      const detection = await analyzeCandidateProfile(
        {
          reference_profile_id: selectedReferenceId,
          candidate_profile: profile,
        },
        image,
      )

      setDetections((current) => [detection, ...current])
      setSelectedDetectionId(detection.id)
      setShowAnalysisForm(false)
      setNotice('Candidate profile analyzed successfully.')
    } finally {
      setAnalyzing(false)
    }
  }

  async function handleStatusChange(status: InvestigationStatus) {
    if (!selectedDetection) return

    setUpdatingStatus(true)
    setError('')

    try {
      const updated = await updateThreatStatus(selectedDetection.id, status)
      setDetections((current) =>
        current.map((item) => item.id === updated.id ? {
          ...item,
          ...updated,
          candidate_profile: item.candidate_profile,
          candidate_username: item.candidate_username,
          reference_username: item.reference_username,
        } : item),
      )
      setNotice('Investigation status updated.')
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setUpdatingStatus(false)
    }
  }

  if (!isEligibleCreator) {
    return (
      <div className="page-content threat-page">
        <div className="panel threat-empty-state" role="alert">
          <div className="threat-empty-icon">
            <ShieldAlert size={25} />
          </div>
          <h3>Access denied</h3>
          <p>
            Threat monitoring is only available to email-verified creator accounts.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="page-content threat-page">
      <div className="page-heading">
        <div>
          <div className="page-kicker">
            <span className="kicker-line" />
            CREATORXDR SECURITY
          </div>
          <h1>
            Threat monitoring<span className="heading-period">.</span>
          </h1>
          <p className="page-subtitle">
            Identify suspicious profiles that may be impersonating your creator identity.
          </p>
        </div>

        <div className="threat-heading-actions">
          <span className="threat-live-label">
            <span />
            MANUAL ANALYSIS
          </span>
          <button
            type="button"
            className="threat-secondary-button"
            onClick={() => void loadDashboard(true)}
            disabled={refreshing}
          >
            <RefreshCw size={15} className={refreshing ? 'threat-spinner' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="threat-message threat-message-error threat-page-message" role="alert">
          <AlertCircle size={17} />
          {error}
          <button type="button" onClick={() => setError('')} aria-label="Dismiss error">
            <X size={15} />
          </button>
        </div>
      )}

      {notice && (
        <div className="threat-message threat-message-success threat-page-message" role="status">
          <CheckCircle2 size={17} />
          {notice}
          <button type="button" onClick={() => setNotice('')} aria-label="Dismiss message">
            <X size={15} />
          </button>
        </div>
      )}

      <section className="threat-metrics-grid">
        <MetricCard
          label="Profiles analyzed"
          value={metrics.total}
          description="Total saved detections"
          icon={Search}
        />
        <MetricCard
          label="High-risk profiles"
          value={metrics.highRisk}
          description="High and critical risk"
          icon={ShieldAlert}
        />
        <MetricCard
          label="Critical alerts"
          value={metrics.critical}
          description="Requires careful review"
          icon={AlertTriangle}
        />
        <MetricCard
          label="Under investigation"
          value={metrics.reviewing}
          description="Currently being reviewed"
          icon={Clock3}
        />
      </section>

      <section className="threat-workspace-grid">
        <div className="panel threat-reference-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">IDENTITY BASELINE</p>
              <h2>Your genuine profiles</h2>
            </div>
            <UserRound size={19} className="muted-icon" />
          </div>

          <p className="threat-section-description">
            Register accounts you own. Candidate profiles are compared against these references.
          </p>

          {loading ? (
            <div className="threat-loading">
              <LoaderCircle className="threat-spinner" size={19} />
              Loading profiles
            </div>
          ) : profiles.length === 0 ? (
            <div className="threat-empty-inline">
              <UserRound size={23} />
              <strong>No reference profiles yet</strong>
              <span>Add your genuine social account to establish a baseline.</span>
            </div>
          ) : (
                                <div className="threat-profile-list">
  {profiles.map((profile) => (
    <div
      key={profile.id}
      className={`threat-profile-row ${selectedReferenceId === profile.id ? 'selected' : ''}`}
    >
      <button
        type="button"
        className="threat-profile-item"
        onClick={() => setSelectedReferenceId(profile.id)}
      >
        <span className="threat-profile-avatar">
          {profile.username.charAt(0).toUpperCase()}
        </span>

        <span className="threat-profile-copy">
          <strong>@{profile.username}</strong>
          <small>
            {platformLabel(profile.platform)} · {profile.display_name || 'No display name'}
          </small>
          <small>
            {profile.has_profile_image ? 'Image available' : 'No profile image'}
          </small>
        </span>

        {selectedReferenceId === profile.id && (
          <CheckCircle2 size={17} className="threat-selected-icon" />
        )}
      </button>

      <label
        className="threat-image-upload-button"
        title="Upload or replace profile image"
      >
        {uploadingReferenceId === profile.id ? (
          <LoaderCircle size={16} className="threat-spinner" />
        ) : (
          <ImagePlus size={16} />
        )}

        <input
          type="file"
          accept="image/jpeg,image/png,image/webp"
          disabled={uploadingReferenceId !== null}
          onChange={(event) => {
            const file = event.target.files?.[0]
            event.target.value = ''

            if (!file) return

            if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) {
              setError('Choose a JPEG, PNG or WebP image.')
              return
            }

            if (file.size > 5 * 1024 * 1024) {
              setError('The image must be smaller than 5 MB.')
              return
            }

            void handleReferenceImageUpload(profile.id, file)
          }}
        />
      </label>
    </div>
  ))}
</div>
          )}

          <button
            type="button"
            className="threat-outline-action"
            onClick={() => setShowReferenceForm((current) => !current)}
          >
            <Plus size={16} />
            Add genuine profile
          </button>
        </div>

        <div className="panel threat-analyze-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">PROFILE ANALYSIS</p>
              <h2>Analyze a suspicious account</h2>
            </div>
            <ShieldCheck size={20} className="muted-icon" />
          </div>

          <p className="threat-section-description">
            Submit a profile's public username, display name and bio for comparison against your selected reference.
          </p>

          <div className="threat-selected-reference">
            <span>Comparing against</span>
            <strong>
              {profiles.find((item) => item.id === selectedReferenceId)
                ? `@${profiles.find((item) => item.id === selectedReferenceId)?.username}`
                : 'No reference profile selected'}
            </strong>
          </div>

          <button
            type="button"
            className="primary-button threat-analyze-button"
            onClick={() => setShowAnalysisForm((current) => !current)}
            disabled={!selectedReferenceId || analyzing}
          >
            <Search size={16} />
            Analyze candidate profile
            <ChevronRight size={16} />
          </button>

          {!selectedReferenceId && (
            <p className="threat-inline-hint">
              Add a genuine profile first to enable analysis.
            </p>
          )}
        </div>
      </section>

      {showReferenceForm && (
        <section className="panel threat-form-panel">
          <ProfileForm
            title="Add a genuine profile"
            description="Only register social accounts that you own or are authorized to manage."
            submitLabel="Save reference profile"
            busy={savingProfile}
            onSubmit={handleCreateReference}
            onCancel={() => setShowReferenceForm(false)}
          />
        </section>
      )}

      {showAnalysisForm && (
        <section className="panel threat-form-panel">
          <ProfileForm
            title="Analyze candidate profile"
            description="Enter the publicly visible details of the profile you want to investigate."
            submitLabel="Run profile analysis"
            busy={analyzing}
            onSubmit={handleAnalyze}
            onCancel={() => setShowAnalysisForm(false)}
          />
        </section>
      )}

      <section className="panel threat-detections-panel">
        <div className="panel-heading threat-detections-heading">
          <div>
            <p className="eyebrow">DETECTION HISTORY</p>
            <h2>Analyzed profiles</h2>
          </div>
          <span className="threat-result-count">{filteredDetections.length} results</span>
        </div>

        <div className="threat-table-toolbar">
          <label className="threat-search">
            <Search size={16} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search usernames or status"
              aria-label="Search detections"
            />
          </label>
        </div>

        {loading ? (
          <div className="threat-loading threat-table-loading">
            <LoaderCircle size={20} className="threat-spinner" />
            Loading detections
          </div>
        ) : filteredDetections.length === 0 ? (
          <div className="threat-empty-state">
            <div className="threat-empty-icon">
              <ShieldCheck size={25} />
            </div>
            <h3>{detections.length === 0 ? 'No profiles analyzed yet' : 'No matching detections'}</h3>
            <p>
              {detections.length === 0
                ? 'Add a genuine profile and analyze a candidate account to see results here.'
                : 'Try another username, risk level or investigation status.'}
            </p>
          </div>
        ) : (
          <div className="threat-table-wrap">
            <table className="threat-table">
              <thead>
                <tr>
                  <th>Candidate profile</th>
                  <th>Reference</th>
                  <th>Risk score</th>
                  <th>Risk level</th>
                  <th>Investigation</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {filteredDetections.map((detection) => (
                  <tr
                    key={detection.id}
                    className={selectedDetectionId === detection.id ? 'threat-row-selected' : ''}
                  >
                    <td>
                      <strong>
                        @{detection.candidate_username ?? detection.candidate_profile?.username ?? 'Unknown'}
                      </strong>
                      <small>
                        {platformLabel(detection.candidate_profile?.platform ?? 'OTHER')}
                      </small>
                    </td>
                    <td>
                      @{detection.reference_username ?? 'Unknown'}
                    </td>
                    <td>
                      <strong className="threat-table-score">
                        {detection.risk_score.toFixed(1)}
                      </strong>
                    </td>
                    <td><RiskBadge level={detection.risk_level} /></td>
                    <td><StatusBadge status={detection.investigation_status} /></td>
                    <td>
                      <button
                        type="button"
                        className="threat-view-button"
                        onClick={() => setSelectedDetectionId(detection.id)}
                      >
                        Details <ChevronRight size={15} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {selectedDetection && (
        <DetectionDetails
          detection={selectedDetection}
          onStatusChange={(status) => void handleStatusChange(status)}
          updating={updatingStatus}
          onClose={() => setSelectedDetectionId(null)}
        />
      )}

      <div className="threat-methodology-note">
        <CircleHelp size={16} />
        <p>
          Risk scores are heuristic indicators, not calibrated probabilities or proof of impersonation.
          Review the evidence before making a decision. Image similarity is calculated when both reference and candidate images are available.
        </p>
      </div>
    </div>
  )
}
