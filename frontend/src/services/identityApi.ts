
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:5001/api'

const ACCESS_TOKEN_KEY = 'creatorxdr_access_token'
const REFRESH_TOKEN_KEY = 'creatorxdr_refresh_token'

export type IdentitySubmission = {
  id: string
  document_type: string
  issuing_country: string
  status: string
  ocr_status: string
  ocr_confidence: number | null
  submitted_at: string
  reviewed_at: string | null
}

type SubmissionListResponse = {
  submissions: IdentitySubmission[]
}

type UploadResponse = {
  message: string
  submission: IdentitySubmission
}

type ApiErrorBody = {
  error?: string
  message?: string
}

export class IdentityApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'IdentityApiError'
    this.status = status
  }
}

async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = sessionStorage.getItem(REFRESH_TOKEN_KEY)

  if (!refreshToken) {
    return null
  }

  try {
    const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${refreshToken}`,
      },
    })

    if (!response.ok) {
      sessionStorage.removeItem(ACCESS_TOKEN_KEY)
      sessionStorage.removeItem(REFRESH_TOKEN_KEY)
      return null
    }

    const data = (await response.json()) as {
      access_token?: string
    }

    if (!data.access_token) {
      sessionStorage.removeItem(ACCESS_TOKEN_KEY)
      sessionStorage.removeItem(REFRESH_TOKEN_KEY)
      return null
    }

    sessionStorage.setItem(ACCESS_TOKEN_KEY, data.access_token)
    return data.access_token
  } catch {
    return null
  }
}

async function getErrorMessage(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as ApiErrorBody
    return body.error ?? body.message ?? 'The request could not be completed.'
  } catch {
    return 'The request could not be completed.'
  }
}

async function authenticatedRequest<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  let accessToken = sessionStorage.getItem(ACCESS_TOKEN_KEY)

  if (!accessToken) {
    throw new IdentityApiError(
      'Your session has expired. Please sign in again.',
      401,
    )
  }

  const sendRequest = (token: string) => {
    const headers = new Headers(options.headers)
    headers.set('Authorization', `Bearer ${token}`)

    return fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers,
    })
  }

  let response = await sendRequest(accessToken)

  if (response.status === 401) {
    accessToken = await refreshAccessToken()

    if (!accessToken) {
      throw new IdentityApiError(
        'Your session has expired. Please sign in again.',
        401,
      )
    }

    response = await sendRequest(accessToken)
  }

  if (!response.ok) {
    throw new IdentityApiError(
      await getErrorMessage(response),
      response.status,
    )
  }

  return (await response.json()) as T
}

export async function getIdentitySubmissions(): Promise<IdentitySubmission[]> {
  const data = await authenticatedRequest<SubmissionListResponse>(
    '/verification/submissions',
    {
      method: 'GET',
    },
  )

  return data.submissions ?? []
}

export async function uploadIdentityDocument(
  file: File,
  documentType: string,
  issuingCountry: string,
): Promise<IdentitySubmission> {
  const formData = new FormData()

  formData.append('document', file)
  formData.append('document_type', documentType)
  formData.append('issuing_country', issuingCountry.toUpperCase())

  const data = await authenticatedRequest<UploadResponse>(
    '/verification/upload',
    {
      method: 'POST',
      body: formData,
    },
  )

  return data.submission
}
