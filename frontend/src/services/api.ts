
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:5001/api'

const ACCESS_TOKEN_KEY = 'creatorxdr_access_token'
const REFRESH_TOKEN_KEY = 'creatorxdr_refresh_token'

export type User = {
  id: string
  email: string
  role: string
  email_verified: boolean
}

export type AuthTokens = {
  access_token: string
  refresh_token: string
}

export type RegistrationResponse = {
  message: string
  email: string
  verification_required: boolean
}

export class ApiError extends Error {
  status: number
  details: unknown

  constructor(message: string, status: number, details?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.details = details
  }
}

type ApiOptions = {
  method?: 'GET' | 'POST'
  body?: unknown
  token?: string | null
  retryOnUnauthorized?: boolean
}

function getAccessToken() {
  return sessionStorage.getItem(ACCESS_TOKEN_KEY)
}

function getRefreshToken() {
  return sessionStorage.getItem(REFRESH_TOKEN_KEY)
}

export function saveAuthTokens(tokens: AuthTokens) {
  sessionStorage.setItem(ACCESS_TOKEN_KEY, tokens.access_token)
  sessionStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh_token)
}

export function clearAuthTokens() {
  sessionStorage.removeItem(ACCESS_TOKEN_KEY)
  sessionStorage.removeItem(REFRESH_TOKEN_KEY)
}

export function hasStoredSession() {
  return Boolean(getAccessToken() || getRefreshToken())
}

async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = getRefreshToken()

  if (!refreshToken) {
    clearAuthTokens()
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
      clearAuthTokens()
      return null
    }

    const data = (await response.json()) as {
      access_token: string
    }

    sessionStorage.setItem(ACCESS_TOKEN_KEY, data.access_token)
    return data.access_token
  } catch {
    return null
  }
}

async function apiRequest<T>(
  endpoint: string,
  options: ApiOptions = {},
): Promise<T> {
  const {
    method = 'GET',
    body,
    token = getAccessToken(),
    retryOnUnauthorized = true,
  } = options

  const headers: Record<string, string> = {
    Accept: 'application/json',
  }

  if (body !== undefined && !(body instanceof FormData)) {
    headers['Content-Type'] = 'application/json'
  }

  if (token) {
    headers.Authorization = `Bearer ${token}`
  }

  let response: Response

  try {
    response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method,
      headers,
      body:
        body instanceof FormData
          ? body
          : body !== undefined
            ? JSON.stringify(body)
            : undefined,
    })
  } catch {
    throw new ApiError(
      'Unable to reach the CreatorXDR server. Check that the backend is running.',
      0,
    )
  }

  if (
    response.status === 401 &&
    retryOnUnauthorized &&
    endpoint !== '/auth/login' &&
    endpoint !== '/auth/refresh'
  ) {
    const newAccessToken = await refreshAccessToken()

    if (newAccessToken) {
      return apiRequest<T>(endpoint, {
        ...options,
        token: newAccessToken,
        retryOnUnauthorized: false,
      })
    }

    clearAuthTokens()
  }

  const contentType = response.headers.get('content-type') ?? ''
  const data = contentType.includes('application/json')
    ? await response.json()
    : null

  if (!response.ok) {
    const message =
      data &&
      typeof data === 'object' &&
      'message' in data &&
      typeof data.message === 'string'
        ? data.message
        : `Request failed with status ${response.status}.`

    throw new ApiError(message, response.status, data)
  }

  return data as T
}

export async function registerUser(
  email: string,
  password: string,
): Promise<RegistrationResponse> {
  return apiRequest<RegistrationResponse>('/auth/register', {
    method: 'POST',
    body: { email, password },
    token: null,
    retryOnUnauthorized: false,
  })
}

export async function verifyEmail(
  email: string,
  code: string,
): Promise<{ message: string }> {
  return apiRequest<{ message: string }>('/auth/verify-email', {
    method: 'POST',
    body: { email, code },
    token: null,
    retryOnUnauthorized: false,
  })
}

export async function loginUser(
  email: string,
  password: string,
): Promise<User> {
  const tokens = await apiRequest<AuthTokens & { user: User }>(
    '/auth/login',
    {
      method: 'POST',
      body: { email, password },
      token: null,
      retryOnUnauthorized: false,
    },
  )

  saveAuthTokens(tokens)

  try {
    return await getCurrentUser()
  } catch (error) {
    clearAuthTokens()
    throw error
  }
}

export async function getCurrentUser(): Promise<User> {
  return apiRequest<User>('/auth/me')
}

export function logoutUser() {
  clearAuthTokens()
}
