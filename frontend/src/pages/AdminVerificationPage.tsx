import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Activity,
  AlertCircle,
  CheckCircle2,
  Clock3,
  FileText,
  Fingerprint,
  LoaderCircle,
  RefreshCw,
  ShieldCheck,
  XCircle,
} from 'lucide-react'

import {
  AdminApiError,
  getAdminAuditLogs,
  getAdminDocument,
  getAdminQueue,
  getAdminSubmission,
  submitAdminDecision,
} from '../services/adminVerificationApi'

import type {
  AdminSubmission,
  AuditLog,
  SubmissionDetails,
} from '../services/adminVerificationApi'

import './AdminVerification.css'

type Decision = 'APPROVED' | 'REJECTED' | 'NEEDS_RESUBMISSION'

const DOCUMENT_LABELS: Record<string, string> = {
  AADHAAR: 'Aadhaar',
  PAN_CARD: 'PAN card',
  PASSPORT: 'Passport',
  DRIVING_LICENSE: 'Driving licence',
  NATIONAL_ID: 'National ID',
  OTHER: 'Other document',
}

function formatDate(value?: string | null) {
  if (!value) return 'Not available'

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) return 'Not available'

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

function formatLabel(value?: string | null) {
  if (!value) return 'Unknown'
  return value.replaceAll('_', ' ').toLowerCase()
}

function getConfidence(value: number | null | undefined) {
  if (value == null || !Number.isFinite(value)) return null
  return Math.min(100, Math.max(0, value))
}

function StatusPill({ value }: { value: string }) {
  const status = value.toLowerCase()

  const tone =
    status.includes('completed') || status.includes('approved')
      ? 'success'
      : status.includes('failed') ||
          status.includes('rejected') ||
          status.includes('duplicate')
        ? 'danger'
        : 'pending'

  return (
    <span className={`admin-status admin-status-${tone}`}>
      {formatLabel(value)}
    </span>
  )
}

function AdminVerificationPage() {
  const [submissions, setSubmissions] = useState<AdminSubmission[]>([])
  const [total, setTotal] = useState(0)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [details, setDetails] = useState<SubmissionDetails | null>(null)
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([])

  const [documentUrl, setDocumentUrl] = useState<string | null>(null)
  const [documentMimeType, setDocumentMimeType] = useState('')

  const [loading, setLoading] = useState(true)
  const [detailsLoading, setDetailsLoading] = useState(false)
  const [documentLoading, setDocumentLoading] = useState(false)
  const [decisionLoading, setDecisionLoading] = useState(false)

  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const [decision, setDecision] = useState<Decision>('APPROVED')
  const [reasonCode, setReasonCode] = useState('')
  const [reviewerNotes, setReviewerNotes] = useState('')

  // Prevent older requests from overwriting a newer selection.
  const selectionRequest = useRef(0)

  const clearDocumentPreview = useCallback(() => {
    setDocumentUrl((currentUrl) => {
      if (currentUrl) URL.revokeObjectURL(currentUrl)
      return null
    })

    setDocumentMimeType('')
  }, [])

  const loadQueue = useCallback(async () => {
    setLoading(true)
    setError('')

    try {
      const [queue, audit] = await Promise.all([
        getAdminQueue(),
        getAdminAuditLogs(),
      ])

      setSubmissions(queue.submissions)
      setTotal(queue.total)
      setAuditLogs(audit.audit_logs)

      setSelectedId((currentId) => {
        if (
          currentId &&
          !queue.submissions.some((item) => item.id === currentId)
        ) {
          setDetails(null)
          clearDocumentPreview()
          return null
        }

        return currentId
      })
    } catch (err) {
      setError(
        err instanceof AdminApiError
          ? err.message
          : 'Unable to load the administrator workspace.',
      )
    } finally {
      setLoading(false)
    }
  }, [clearDocumentPreview])

  useEffect(() => {
    void loadQueue()
  }, [loadQueue])

  useEffect(() => {
    return () => {
      selectionRequest.current += 1
    }
  }, [])

  useEffect(() => {
    return () => {
      if (documentUrl) URL.revokeObjectURL(documentUrl)
    }
  }, [documentUrl])

  const selectSubmission = async (submission: AdminSubmission) => {
    const requestId = ++selectionRequest.current

    setSelectedId(submission.id)
    setDetails(null)
    setSuccess('')
    setError('')
    setDetailsLoading(true)
    setDecision('APPROVED')
    setReasonCode('')
    setReviewerNotes('')
    clearDocumentPreview()

    try {
      const result = await getAdminSubmission(submission.id)

      if (requestId !== selectionRequest.current) return

      setDetails(result)
    } catch (err) {
      if (requestId !== selectionRequest.current) return

      setError(
        err instanceof AdminApiError
          ? err.message
          : 'Unable to load submission details.',
      )
    } finally {
      if (requestId === selectionRequest.current) {
        setDetailsLoading(false)
      }
    }
  }

  const openDocument = async () => {
    if (!selectedId) return

    const requestedId = selectedId

    setDocumentLoading(true)
    setError('')

    try {
      const blob = await getAdminDocument(requestedId)

      if (requestedId !== selectedId) return

      const url = URL.createObjectURL(blob)

      clearDocumentPreview()
      setDocumentUrl(url)
      setDocumentMimeType(blob.type || 'application/octet-stream')
    } catch (err) {
      setError(
        err instanceof AdminApiError
          ? err.message
          : 'Unable to retrieve the document.',
      )
    } finally {
      setDocumentLoading(false)
    }
  }

  const handleDecision = async () => {
    if (!selectedId) return

    if (decision !== 'APPROVED' && !reasonCode.trim()) {
      setError('A reason code is required for this decision.')
      return
    }

    if (
      details?.submission.duplicate_detected &&
      decision === 'APPROVED'
    ) {
      setError(
        'A potential duplicate was detected. Resolve the duplicate warning before approving.',
      )
      return
    }

    const confirmed = window.confirm(
      `Are you sure you want to ${formatLabel(decision)} this submission?`,
    )

    if (!confirmed) return

    setDecisionLoading(true)
    setError('')
    setSuccess('')

    try {
      await submitAdminDecision(selectedId, {
        decision,
        ...(decision !== 'APPROVED'
          ? { reason_code: reasonCode.trim().toUpperCase() }
          : {}),
        reviewer_notes: reviewerNotes.trim(),
      })

      setSuccess('Review decision recorded successfully.')

      setDetails(null)
      setSelectedId(null)
      setReasonCode('')
      setReviewerNotes('')
      setDecision('APPROVED')
      clearDocumentPreview()

      await loadQueue()
    } catch (err) {
      setError(
        err instanceof AdminApiError
          ? err.message
          : 'Unable to save the review decision.',
      )
    } finally {
      setDecisionLoading(false)
    }
  }

  const selectedSubmission =
    submissions.find((item) => item.id === selectedId) ?? null

  const pendingCount = submissions.filter(
    (item) => item.status === 'PENDING_REVIEW',
  ).length

  const ocrCompleted = submissions.filter(
    (item) => item.ocr_status === 'COMPLETED',
  ).length

  const confidence = getConfidence(
    details?.submission.ocr_confidence,
  )

  const isImageDocument = documentMimeType.startsWith('image/')
  const isPdfDocument = documentMimeType === 'application/pdf'

  return (
    <div className="page-content admin-page">
      {/* PAGE HEADER */}
      <div className="page-heading">
        <div>
          <div className="page-kicker">
            <span className="kicker-line" />
            CREATORXDR ADMINISTRATION
          </div>

          <h1>
            Identity review<span className="heading-period">.</span>
          </h1>

          <p className="page-subtitle">
            Review submitted identity documents and record verification decisions.
          </p>
        </div>

        <button
          className="admin-refresh-button"
          onClick={() => void loadQueue()}
          disabled={loading}
        >
          <RefreshCw
            size={15}
            className={loading ? 'admin-spin' : ''}
          />
          Refresh queue
        </button>
      </div>

      {/* ALERTS */}
      {error && (
        <div className="admin-alert admin-alert-error" role="alert">
          <AlertCircle size={17} />
          {error}
        </div>
      )}

      {success && (
        <div className="admin-alert admin-alert-success" role="status">
          <CheckCircle2 size={17} />
          {success}
        </div>
      )}

      {/* METRICS */}
      <div className="admin-metrics">
        <article className="admin-metric">
          <span>Open submissions</span>
          <strong>{total}</strong>
          <small>
            <Clock3 size={13} />
            Awaiting review
          </small>
        </article>

        <article className="admin-metric">
          <span>Pending review</span>
          <strong>{pendingCount}</strong>
          <small>
            <Activity size={13} />
            Not yet reviewed
          </small>
        </article>

        <article className="admin-metric">
          <span>OCR completed</span>
          <strong>{ocrCompleted}</strong>
          <small>
            <FileText size={13} />
            Extraction finished
          </small>
        </article>

        <article className="admin-metric">
          <span>Audit events loaded</span>
          <strong>{auditLogs.length}</strong>
          <small>
            <ShieldCheck size={13} />
            Recorded activity
          </small>
        </article>
      </div>

      {/* MAIN WORKSPACE */}
      <div className="admin-workspace">
        {/* SUBMISSION QUEUE */}
        <section className="panel admin-queue-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">INCOMING REQUESTS</p>
              <h2>Verification queue</h2>
            </div>

            <span className="admin-count">{total} total</span>
          </div>

          {loading ? (
            <div className="admin-empty">
              <LoaderCircle className="admin-spin" size={22} />
              Loading submissions...
            </div>
          ) : submissions.length === 0 ? (
            <div className="admin-empty">
              <CheckCircle2 size={24} />
              <strong>Queue is clear</strong>
              <span>No submissions are waiting for review.</span>
            </div>
          ) : (
            <div className="admin-submission-list">
              {submissions.map((submission) => (
                <button
                  key={submission.id}
                  type="button"
                  className={`admin-submission-row ${
                    selectedId === submission.id ? 'selected' : ''
                  }`}
                  onClick={() => void selectSubmission(submission)}
                >
                  <span className="admin-document-icon">
                    <Fingerprint size={18} />
                  </span>

                  <span className="admin-submission-copy">
                    <strong>
                      {DOCUMENT_LABELS[submission.document_type] ??
                        submission.document_type}
                    </strong>

                    <small>{submission.user_email}</small>
                    <small>{formatDate(submission.submitted_at)}</small>
                  </span>

                  <span className="admin-row-meta">
                    <StatusPill value={submission.status} />
                    <small>OCR: {formatLabel(submission.ocr_status)}</small>
                  </span>
                </button>
              ))}
            </div>
          )}
        </section>

        {/* SUBMISSION DETAILS */}
        <section className="panel admin-detail-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">REVIEW WORKSPACE</p>
              <h2>Submission details</h2>
            </div>

            {selectedSubmission && (
              <StatusPill value={selectedSubmission.status} />
            )}
          </div>

          {!selectedId ? (
            <div className="admin-empty admin-detail-empty">
              <FileText size={27} />
              <strong>Select a submission</strong>
              <span>Choose a request from the queue to inspect it.</span>
            </div>
          ) : detailsLoading ? (
            <div className="admin-empty">
              <LoaderCircle className="admin-spin" size={22} />
              Loading submission details...
            </div>
          ) : details ? (
            <div className="admin-detail-content">
              {/* APPLICANT INFORMATION */}
              <div className="admin-info-grid">
                <div>
                  <span>Applicant</span>
                  <strong>{details.submission.user_email}</strong>
                </div>

                <div>
                  <span>Document type</span>
                  <strong>
                    {DOCUMENT_LABELS[details.submission.document_type] ??
                      details.submission.document_type}
                  </strong>
                </div>

                <div>
                  <span>Issuing country</span>
                  <strong>
                    {details.submission.issuing_country || 'Not available'}
                  </strong>
                </div>

                <div>
                  <span>Submitted</span>
                  <strong>
                    {formatDate(details.submission.submitted_at)}
                  </strong>
                </div>
              </div>

              {/* OCR INFORMATION */}
              <div className="admin-ocr-card">
                <div className="admin-ocr-heading">
                  <strong>OCR extraction</strong>
                  <StatusPill value={details.submission.ocr_status} />
                </div>

                <div className="admin-ocr-confidence">
                  <span>Extraction confidence</span>
                  <strong>
                    {confidence == null
                      ? 'Unavailable'
                      : `${confidence.toFixed(1)}%`}
                  </strong>
                </div>

                <div className="admin-progress">
                  <span
                    style={{
                      width: `${confidence ?? 0}%`,
                    }}
                  />
                </div>

                <p className="admin-disclaimer">
                  OCR confidence measures text extraction quality. It does not
                  establish document authenticity or identity.
                </p>

                {details.ocr?.identity_data && (
                  <div className="admin-ocr-data">
                    <strong>Extracted fields</strong>
                    <pre>
                      {JSON.stringify(details.ocr.identity_data, null, 2)}
                    </pre>
                  </div>
                )}

                {details.ocr?.text && (
                  <details className="admin-ocr-text">
                    <summary>View extracted text</summary>
                    <pre>{details.ocr.text}</pre>
                  </details>
                )}
              </div>

              {/* ORIGINAL DOCUMENT */}
              <div className="admin-document-section">
                <div>
                  <strong>Original document</strong>
                  <p>
                    Access is recorded in the administrator audit trail.
                  </p>
                </div>

                <button
                  type="button"
                  className="admin-secondary-button"
                  onClick={() => void openDocument()}
                  disabled={documentLoading}
                >
                  {documentLoading ? (
                    <LoaderCircle size={15} className="admin-spin" />
                  ) : (
                    <FileText size={15} />
                  )}
                  Load document
                </button>
              </div>

              {documentUrl && (
                <div className="admin-document-preview">
                  {isImageDocument ? (
                    <img
                      src={documentUrl}
                      alt="Submitted identity document"
                    />
                  ) : isPdfDocument ? (
                    <iframe
                      title="Identity document preview"
                      src={documentUrl}
                    />
                  ) : (
                    <div className="admin-empty">
                      <FileText size={24} />
                      <strong>Preview unavailable</strong>
                      <span>
                        This file type cannot be previewed here.
                      </span>
                    </div>
                  )}

                  <a
                    href={documentUrl}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Open document in new tab
                  </a>
                </div>
              )}

              {/* DUPLICATE WARNING */}
              {details.submission.duplicate_detected && (
                <div className="admin-alert admin-alert-error">
                  <AlertCircle size={16} />
                  Potential duplicate detected. Investigate before making a decision.
                </div>
              )}

              {/* REVIEW FORM */}
              <div className="admin-review-form">
                <div>
                  <p className="eyebrow">ADMINISTRATOR DECISION</p>
                  <h3>Record review outcome</h3>
                </div>

                <label>
                  Decision

                  <select
                    value={decision}
                    onChange={(event) =>
                      setDecision(event.target.value as Decision)
                    }
                  >
                    <option value="APPROVED">Approve</option>
                    <option value="REJECTED">Reject</option>
                    <option value="NEEDS_RESUBMISSION">
                      Request resubmission
                    </option>
                  </select>
                </label>

                {decision !== 'APPROVED' && (
                  <label>
                    Reason code (required)

                    <input
                      value={reasonCode}
                      onChange={(event) =>
                        setReasonCode(
                          event.target.value
                            .toUpperCase()
                            .replace(/[^A-Z0-9_]/g, '_'),
                        )
                      }
                      placeholder="e.g. DOCUMENT_UNCLEAR"
                      maxLength={50}
                    />
                  </label>
                )}

                <label>
                  Reviewer notes (optional)

                  <textarea
                    value={reviewerNotes}
                    onChange={(event) =>
                      setReviewerNotes(event.target.value)
                    }
                    placeholder="Add internal review notes..."
                    maxLength={2000}
                    rows={3}
                  />
                </label>

                <button
                  type="button"
                  className="admin-primary-button"
                  onClick={() => void handleDecision()}
                  disabled={
                    decisionLoading ||
                    (decision === 'APPROVED' &&
                      details.submission.duplicate_detected)
                  }
                >
                  {decisionLoading ? (
                    <LoaderCircle size={16} className="admin-spin" />
                  ) : decision === 'APPROVED' ? (
                    <CheckCircle2 size={16} />
                  ) : decision === 'REJECTED' ? (
                    <XCircle size={16} />
                  ) : (
                    <RefreshCw size={16} />
                  )}

                  {decisionLoading ? 'Saving...' : 'Submit decision'}
                </button>
              </div>

              {/* REVIEW HISTORY */}
              {details.reviews.length > 0 && (
                <div className="admin-review-history">
                  <strong>Previous reviews</strong>

                  {details.reviews.map((review, index) => (
                    <div key={review.id ?? index}>
                      <StatusPill value={review.decision} />
                      <span>
                        {review.reviewer_notes ?? 'No notes'}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="admin-empty">
              <AlertCircle size={22} />
              <strong>Unable to display submission</strong>
              <span>Try selecting the submission again.</span>
            </div>
          )}
        </section>
      </div>

      {/* ADMIN AUDIT TRAIL */}
      <section className="panel admin-audit-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">ACCOUNTABILITY</p>
            <h2>Administrator audit trail</h2>
          </div>

          <span className="admin-count">
            {auditLogs.length} events
          </span>
        </div>

        {auditLogs.length === 0 ? (
          <p className="admin-audit-empty">
            No audit events available.
          </p>
        ) : (
          <div className="admin-audit-list">
            {auditLogs.map((log, index) => (
              <div
                className="admin-audit-row"
                key={log.id ?? index}
              >
                <span className="admin-audit-icon">
                  <Activity size={15} />
                </span>

                <div>
                  <strong>{formatLabel(log.event_type)}</strong>
                  <small>
                    {log.submission_id
                      ? `Submission ${log.submission_id}`
                      : 'Administrator activity'}
                  </small>
                </div>

                <time>{formatDate(log.created_at)}</time>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}

export default AdminVerificationPage;