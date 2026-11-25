import { refreshAccessToken } from './api'

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:5001/api'

const ACCESS_TOKEN_KEY = 'creatorxdr_access_token'

// --------------------------------------------------
// TYPES
// --------------------------------------------------

export interface AdminSubmission {
  id: string
  user_id?: string
  user_email: string
  document_type: string
  issuing_country?: string | null
  status: string
  ocr_status: string
  ocr_confidence?: number | null
  duplicate_detected: boolean
  submitted_at?: string | null
  created_at?: string | null
  [key: string]: unknown
}

export interface AdminReview {
  id?: string
  decision: string
  reviewer_notes?: string | null
  reason_code?: string | null
  created_at?: string | null
  reviewer_email?: string | null
  [key: string]: unknown
}

export interface SubmissionDetails {
  submission: AdminSubmission
  ocr?: {
    identity_data?: Record<string, unknown> | null
    text?: string | null
    [key: string]: unknown
  } | null
  reviews: AdminReview[]
}

export interface AuditLog {
  id?: string
  event_type: string
  submission_id?: string | null
  created_at?: string | null
  [key: string]: unknown
}

export interface AdminQueueResponse {
  submissions: AdminSubmission[]
  total: number
}

export interface AdminAuditResponse {
  audit_logs: AuditLog[]
}

export interface AdminDecisionPayload {
  decision: 'APPROVED' | 'REJECTED' | 'NEEDS_RESUBMISSION'
  reason_code?: string
  reviewer_notes?: string
}

export class AdminApiError extends Error {
  status: number

  constructor(message: string, status = 500) {
    super(message)
    this.name = 'AdminApiError'
    this.status = status
  }
}

// --------------------------------------------------
// AUTHENTICATION
// --------------------------------------------------

function getAccessToken(): string | null {
  return sessionStorage.getItem(ACCESS_TOKEN_KEY)
}

// --------------------------------------------------
// HTTP HELPERS
// --------------------------------------------------

async function authenticatedFetch(
  endpoint: string,
  options: RequestInit = {},
): Promise<Response> {
  let token = getAccessToken()

  if (!token) {
    throw new AdminApiError(
      'You are not authenticated. Please log in again.',
      401,
    )
  }

  const makeRequest = (accessToken: string) => {
    const headers = new Headers(options.headers)

    headers.set('Authorization', `Bearer ${accessToken}`)

    if (!(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json')
    }

    return fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    })
  }

  let response = await makeRequest(token)

  // Retry once if the access token has expired.
  if (response.status === 401) {
    const refreshedToken = await refreshAccessToken()

    if (!refreshedToken) {
      throw new AdminApiError(
        'Your session has expired. Please log in again.',
        401,
      )
    }

    token = refreshedToken
    response = await makeRequest(token)
  }

  if (!response.ok) {
    let message = `Request failed with status ${response.status}`

    try {
      const errorData = await response.json()

      message =
        errorData.error ??
        errorData.message ??
        errorData.msg ??
        message
    } catch {
      // Keep the default HTTP error message.
    }

    throw new AdminApiError(message, response.status)
  }

  return response
}

async function getJson<T>(endpoint: string): Promise<T> {
  const response = await authenticatedFetch(endpoint)
  return (await response.json()) as T
}

// --------------------------------------------------
// ADMIN VERIFICATION API
// --------------------------------------------------

/**
 * Fetch pending and under-review identity submissions.
 *
 * Backend:
 * GET /api/admin/verification/submissions
 */
export async function getAdminQueue(): Promise<AdminQueueResponse> {
  const result = await getJson<AdminQueueResponse>(
    '/admin/verification/submissions?limit=100&offset=0',
  )

  return {
    submissions: Array.isArray(result.submissions)
      ? result.submissions
      : [],
    total: Number(result.total ?? 0),
  }
}

/**
 * Fetch complete details for one submission.
 *
 * Backend:
 * GET /api/admin/verification/submissions/:id
 */
export async function getAdminSubmission(
  submissionId: string,
): Promise<SubmissionDetails> {
  if (!submissionId) {
    throw new AdminApiError('Submission ID is required.', 400)
  }

  const result = await getJson<SubmissionDetails>(
    `/admin/verification/submissions/${encodeURIComponent(submissionId)}`,
  )

  return {
    ...result,
    reviews: Array.isArray(result.reviews) ? result.reviews : [],
  }
}

/**
 * Download the original identity document.
 *
 * Backend:
 * GET /api/admin/verification/submissions/:id/document
 */
export async function getAdminDocument(
  submissionId: string,
): Promise<Blob> {
  if (!submissionId) {
    throw new AdminApiError('Submission ID is required.', 400)
  }

  const response = await authenticatedFetch(
    `/admin/verification/submissions/${encodeURIComponent(
      submissionId,
    )}/document`,
    {
      method: 'GET',
    },
  )

  return response.blob()
}

/**
 * Submit an administrator review decision.
 *
 * Backend:
 * POST /api/admin/verification/submissions/:id/review
 */
export async function submitAdminDecision(
  submissionId: string,
  payload: AdminDecisionPayload,
): Promise<Record<string, unknown>> {
  if (!submissionId) {
    throw new AdminApiError('Submission ID is required.', 400)
  }

  if (
    payload.decision !== 'APPROVED' &&
    !payload.reason_code?.trim()
  ) {
    throw new AdminApiError(
      'A reason code is required for rejection or resubmission.',
      400,
    )
  }

  const response = await authenticatedFetch(
    `/admin/verification/submissions/${encodeURIComponent(
      submissionId,
    )}/review`,
    {
      method: 'POST',
      body: JSON.stringify(payload),
    },
  )

  return (await response.json()) as Record<string, unknown>
}

/**
 * Fetch administrator audit events.
 *
 * Backend:
 * GET /api/admin/verification/audit-logs
 */
export async function getAdminAuditLogs(): Promise<AdminAuditResponse> {
  const result = await getJson<AdminAuditResponse>(
    '/admin/verification/audit-logs',
  )

  return {
    audit_logs: Array.isArray(result.audit_logs)
      ? result.audit_logs
      : [],
  }
}