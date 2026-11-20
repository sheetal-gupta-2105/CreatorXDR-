import { useCallback, useEffect, useRef, useState } from 'react'
import {
  AlertCircle,
  CheckCircle2,
  Clock3,
  FileCheck2,
  FileImage,
  FileText,
  Fingerprint,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  ShieldCheck,
  Upload,
} from 'lucide-react'
import {
  getIdentitySubmissions,
  IdentityApiError,
  uploadIdentityDocument,
} from '../services/identityApi'
import type { IdentitySubmission } from '../services/identityApi'
import './Identity.css'

const DOCUMENT_TYPES = [
  { value: 'PASSPORT', label: 'Passport' },
  { value: 'DRIVING_LICENSE', label: 'Driving licence' },
  { value: 'NATIONAL_ID', label: 'National identity card' },
  { value: 'PAN_CARD', label: 'PAN card' },
  { value: 'AADHAAR', label: 'Aadhaar card' },
]

const STATUS_LABELS: Record<string, string> = {
  PENDING_REVIEW: 'Pending review',
  UNDER_REVIEW: 'Under review',
  NEEDS_RESUBMISSION: 'Resubmission required',
  REJECTED: 'Rejected',
  APPROVED: 'Approved',
  PENDING_CHAIN: 'Blockchain registration pending',
  CHAIN_FAILED: 'Blockchain registration failed',
  VERIFIED: 'Verified',
  FAILED: 'Processing failed',
}

function formatDate(value: string): string {
  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return 'Date unavailable'
  }

  return new Intl.DateTimeFormat(undefined, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

function getStatusClass(status: string): string {
  switch (status) {
    case 'VERIFIED':
    case 'APPROVED':
      return 'identity-status-success'
    case 'REJECTED':
    case 'FAILED':
    case 'CHAIN_FAILED':
      return 'identity-status-danger'
    case 'UNDER_REVIEW':
    case 'PENDING_CHAIN':
      return 'identity-status-progress'
    case 'NEEDS_RESUBMISSION':
      return 'identity-status-warning'
    default:
      return 'identity-status-pending'
  }
}

function getDocumentLabel(documentType: string): string {
  return (
    DOCUMENT_TYPES.find((item) => item.value === documentType)?.label ??
    documentType.replaceAll('_', ' ')
  )
}

function getOcrLabel(status: string): string {
  switch (status) {
    case 'COMPLETED':
      return 'Completed'
    case 'FAILED':
      return 'Could not complete'
    case 'PENDING':
      return 'Pending'
    default:
      return status.replaceAll('_', ' ').toLowerCase()
  }
}

function SubmissionCard({
  submission,
}: {
  submission: IdentitySubmission
}) {
  const isVerified = submission.status === 'VERIFIED'

  return (
    <article className="identity-submission-card">
      <div className="identity-submission-icon">
        <FileText size={19} />
      </div>

      <div className="identity-submission-main">
        <div className="identity-submission-title">
          <strong>{getDocumentLabel(submission.document_type)}</strong>
          <span className={`identity-status ${getStatusClass(submission.status)}`}>
            {STATUS_LABELS[submission.status] ??
              submission.status.replaceAll('_', ' ')}
          </span>
        </div>

        <p>
          Issued by country code: {submission.issuing_country}
        </p>

        <div className="identity-submission-meta">
          <span>Submitted {formatDate(submission.submitted_at)}</span>
          {submission.reviewed_at && (
            <span>Reviewed {formatDate(submission.reviewed_at)}</span>
          )}
        </div>

        <div className="identity-ocr-row">
          <span className="identity-ocr-label">
            OCR processing: {getOcrLabel(submission.ocr_status)}
          </span>

          {typeof submission.ocr_confidence === 'number' && (
            <span>
              OCR confidence: {
            `${Math.min(100, Math.max(0, submission.ocr_confidence)).toFixed(1)}%`
                }
            </span>
          )}
        </div>

        {isVerified && (
          <div className="identity-verified-note">
            <CheckCircle2 size={14} />
            Identity verification completed
          </div>
        )}
      </div>
    </article>
  )
}

export default function IdentityPage() {
  const [submissions, setSubmissions] = useState<IdentitySubmission[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [documentType, setDocumentType] = useState('PASSPORT')
  const [issuingCountry, setIssuingCountry] = useState('IN')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const loadSubmissions = useCallback(async (showRefresh = false) => {
    if (showRefresh) {
      setRefreshing(true)
    } else {
      setLoading(true)
    }

    setError('')

    try {
      const data = await getIdentitySubmissions()
      setSubmissions(data)
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to load your verification submissions.',
      )
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    void loadSubmissions()
  }, [loadSubmissions])

  function handleFileChange(
    event: React.ChangeEvent<HTMLInputElement>,
  ) {
    const file = event.target.files?.[0] ?? null
    setError('')
    setNotice('')

    if (!file) {
      setSelectedFile(null)
      return
    }

    const allowedTypes = [
      'application/pdf',
      'image/jpeg',
      'image/png',
    ]

    if (!allowedTypes.includes(file.type)) {
      setSelectedFile(null)
      event.target.value = ''
      setError('Choose a PDF, JPEG, or PNG document.')
      return
    }

    setSelectedFile(file)
  }

  async function handleUpload(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setNotice('')

    if (!selectedFile) {
      setError('Select a document before submitting.')
      return
    }

    if (!/^[A-Za-z]{2}$/.test(issuingCountry.trim())) {
      setError('Enter a valid two-letter country code, such as IN.')
      return
    }

    setUploading(true)

    try {
      await uploadIdentityDocument(
        selectedFile,
        documentType,
        issuingCountry.trim(),
      )

      setNotice(
        'Your document was submitted. It is awaiting the verification process.',
      )
      setSelectedFile(null)

      if (fileInputRef.current) {
        fileInputRef.current.value = ''
      }

      await loadSubmissions(true)
    } catch (err) {
      if (err instanceof IdentityApiError && err.status === 401) {
        setError('Your session has expired. Sign in again to continue.')
      } else {
        setError(
          err instanceof Error
            ? err.message
            : 'The document could not be uploaded.',
        )
      }
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="page-content identity-page">
      <div className="page-heading">
        <div>
          <div className="page-kicker">
            <span className="kicker-line" />
            CREATORXDR WORKSPACE
          </div>
          <h1>
            Identity verification<span className="heading-period">.</span>
          </h1>
          <p className="page-subtitle">
            Establish your identity before connecting creator accounts.
          </p>
        </div>

        <div className="heading-actions">
          <span className="workspace-badge">
            <span className="status-dot" />
            PRIVATE VERIFICATION
          </span>
        </div>
      </div>

      <div className="identity-intro-grid">
        <section className="panel identity-intro-panel">
          <div className="identity-intro-icon">
            <Fingerprint size={25} />
          </div>
          <div>
            <p className="eyebrow">IDENTITY FOUNDATION</p>
            <h2>Prove your identity. Protect your creator presence.</h2>
            <p>
              Submit a valid government-issued photo ID. Your submission will
              be reviewed by an authorized administrator before verification
              can be completed.
            </p>
          </div>
        </section>

        <section className="panel identity-privacy-panel">
          <div className="identity-privacy-heading">
            <LockKeyhole size={18} />
            <strong>Privacy by design</strong>
          </div>
          <ul>
            <li>Your ID document is not published on your profile.</li>
            <li>Identity documents are not written to the blockchain.</li>
            <li>OCR assists review and does not approve identities.</li>
          </ul>
        </section>
      </div>

      <div className="identity-content-grid">
        <section className="panel identity-upload-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">SUBMIT DOCUMENT</p>
              <h2>Start verification</h2>
            </div>
            <ShieldCheck size={20} className="muted-icon" />
          </div>

          <p className="identity-form-description">
            Use a clear, readable image or PDF of a valid government-issued
            photo ID.
          </p>

          <form onSubmit={handleUpload} className="identity-form">
            <label className="identity-field">
              <span>Document type</span>
              <select
                value={documentType}
                onChange={(event) => setDocumentType(event.target.value)}
                disabled={uploading}
              >
                {DOCUMENT_TYPES.map((item) => (
                  <option key={item.value} value={item.value}>
                    {item.label}
                  </option>
                ))}
              </select>
            </label>

            <label className="identity-field">
              <span>Issuing country code</span>
              <input
                type="text"
                value={issuingCountry}
                onChange={(event) =>
                  setIssuingCountry(event.target.value.toUpperCase())
                }
                maxLength={2}
                placeholder="IN"
                autoComplete="country"
                disabled={uploading}
              />
              <small>Use a two-letter ISO country code, for example IN.</small>
            </label>

            <div className="identity-field">
              <span>Identity document</span>

              <button
                type="button"
                className={`identity-file-picker ${selectedFile ? 'file-selected' : ''}`}
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading}
              >
                {selectedFile ? (
                  <FileCheck2 size={22} />
                ) : (
                  <FileImage size={22} />
                )}

                <span>
                  <strong>
                    {selectedFile ? selectedFile.name : 'Choose a document'}
                  </strong>
                  <small>
                    {selectedFile
                      ? `${(selectedFile.size / 1024 / 1024).toFixed(2)} MB`
                      : 'PDF, JPEG, or PNG'}
                  </small>
                </span>

                <Upload size={17} />
              </button>

              <input
                ref={fileInputRef}
                type="file"
                accept=".pdf,.jpg,.jpeg,.png,application/pdf,image/jpeg,image/png"
                onChange={handleFileChange}
                className="identity-hidden-input"
                disabled={uploading}
              />
            </div>

            {error && (
              <div className="identity-message identity-message-error" role="alert">
                <AlertCircle size={17} />
                <span>{error}</span>
              </div>
            )}

            {notice && (
              <div className="identity-message identity-message-success" role="status">
                <CheckCircle2 size={17} />
                <span>{notice}</span>
              </div>
            )}

            <button
              type="submit"
              className="primary-button identity-submit-button"
              disabled={uploading || !selectedFile}
            >
              {uploading ? (
                <>
                  <LoaderCircle size={17} className="identity-spinner" />
                  Submitting document
                </>
              ) : (
                <>
                  Submit for review
                  <Upload size={16} />
                </>
              )}
            </button>

            <p className="identity-upload-disclaimer">
              Only submit your own document. Do not upload documents belonging
              to another person.
            </p>
          </form>
        </section>

        <section className="panel identity-process-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">WHAT HAPPENS NEXT</p>
              <h2>Verification process</h2>
            </div>
            <Clock3 size={19} className="muted-icon" />
          </div>

          <div className="identity-process-list">
            <div className="identity-process-step">
              <span className="identity-process-number">01</span>
              <div>
                <strong>Secure submission</strong>
                <p>Your document is uploaded to private local storage.</p>
              </div>
            </div>

            <div className="identity-process-step">
              <span className="identity-process-number">02</span>
              <div>
                <strong>OCR assistance</strong>
                <p>
                  Text extraction can assist the review process. It is not a
                  final identity decision.
                </p>
              </div>
            </div>

            <div className="identity-process-step">
              <span className="identity-process-number">03</span>
              <div>
                <strong>Administrator review</strong>
                <p>
                  An authorized reviewer checks the submission and records a
                  decision.
                </p>
              </div>
            </div>

            <div className="identity-process-step">
              <span className="identity-process-number">04</span>
              <div>
                <strong>Verification credential</strong>
                <p>
                  Blockchain registration follows approval. Verification is
                  complete only after the required confirmation.
                </p>
              </div>
            </div>
          </div>

          <div className="identity-process-note">
            <LockKeyhole size={15} />
            Your identity details remain off-chain.
          </div>
        </section>
      </div>

      <section className="panel identity-history-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">YOUR RECORDS</p>
            <h2>Submission history</h2>
          </div>

          <button
            type="button"
            className="identity-refresh-button"
            onClick={() => void loadSubmissions(true)}
            disabled={refreshing || loading}
          >
            <RefreshCw
              size={15}
              className={refreshing ? 'identity-spinner' : ''}
            />
            Refresh
          </button>
        </div>

        {loading ? (
          <div className="identity-empty-state">
            <LoaderCircle size={22} className="identity-spinner" />
            <span>Loading your submissions...</span>
          </div>
        ) : error && submissions.length === 0 ? (
          <div className="identity-empty-state identity-empty-error">
            <AlertCircle size={22} />
            <span>{error}</span>
          </div>
        ) : submissions.length === 0 ? (
          <div className="identity-empty-state">
            <FileText size={24} />
            <strong>No identity submissions yet</strong>
            <span>Your submitted documents will appear here.</span>
          </div>
        ) : (
          <div className="identity-submission-list">
            {submissions.map((submission) => (
              <SubmissionCard
                key={submission.id}
                submission={submission}
              />
            ))}
          </div>
        )}
      </section>

      <footer className="page-footer">
        <span>
          CREATORXDR <span className="footer-dot">•</span> CREATOR SECURITY PLATFORM
        </span>
        <span>
          PRIVATE IDENTITY WORKFLOW <span className="footer-version">v0.1.0</span>
        </span>
      </footer>
    </div>
  )
}