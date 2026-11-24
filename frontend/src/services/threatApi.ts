
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:5001/api'

const ACCESS_TOKEN_KEY = 'creatorxdr_access_token'
const REFRESH_TOKEN_KEY = 'creatorxdr_refresh_token'

export type SocialPlatform =
  | 'INSTAGRAM'
  | 'YOUTUBE'
  | 'TIKTOK'
  | 'X'
  | 'OTHER'

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export type InvestigationStatus =
  | 'NEW'
  | 'REVIEWING'
  | 'CONFIRMED'
  | 'SAFE'
  | 'DISMISSED'

export type SocialProfile = {
  id: string
  platform: SocialPlatform
  username: string
  display_name: string | null
  bio: string | null
  source: string
  created_at: string
}

export type ProfileInput = {
  platform: SocialPlatform
  username: string
  display_name?: string
  bio?: string
}

export type CandidateAnalysisInput = {
  reference_profile_id: string
  candidate_profile: ProfileInput
}

export type ThreatDetection = {
  id: string
  reference_profile_id: string
  monitored_profile_id: string
  risk_score: number
  risk_level: RiskLevel
  feature_scores: Record<string, number | null>
  evidence: string[]
  available_signals: string[]
  missing_signals: string[]
  scoring_note: string | null
  investigation_status: InvestigationStatus
  created_at: string

  candidate_profile?: SocialProfile
  reference_profile?: SocialProfile

  reference_username?: string
  candidate_username?: string
}

type ProfileListResponse = {
  profiles: SocialProfile[]
}

type DetectionListResponse = {
  total: number
  detections: ThreatDetection[]
}

type CreateProfileResponse = {
  message: string
  profile: SocialProfile
}

type AnalyzeResponse = {
  message: string
  candidate_profile: SocialProfile
  detection: ThreatDetection
}

type DetectionResponse = {
  detection: ThreatDetection
}

type StatusUpdateResponse = {
  message: string
  detection: ThreatDetection
}

type ApiErrorBody = {
  error?: string
  message?: string
}

export class ThreatApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ThreatApiError'
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

    return (
      body.error ??
      body.message ??
      'The request could not be completed.'
    )
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
    throw new ThreatApiError(
      'Your session has expired. Please sign in again.',
      401,
    )
  }

  const sendRequest = (token: string) => {
    const headers = new Headers(options.headers)

    headers.set('Authorization', `Bearer ${token}`)

    if (options.body && !(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json')
    }

    return fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers,
    })
  }

  let response = await sendRequest(accessToken)

  if (response.status === 401) {
    accessToken = await refreshAccessToken()

    if (!accessToken) {
      throw new ThreatApiError(
        'Your session has expired. Please sign in again.',
        401,
      )
    }

    response = await sendRequest(accessToken)
  }

  if (!response.ok) {
    throw new ThreatApiError(
      await getErrorMessage(response),
      response.status,
    )
  }

  return (await response.json()) as T
}

// Get the creator's genuine social profiles.
export async function getReferenceProfiles(): Promise<SocialProfile[]> {
  const data = await authenticatedRequest<ProfileListResponse>(
    '/threats/reference-profiles',
    { method: 'GET' },
  )

  return data.profiles ?? []
}

// Register a genuine creator profile.
export async function createReferenceProfile(
  profile: ProfileInput,
): Promise<SocialProfile> {
  const data = await authenticatedRequest<CreateProfileResponse>(
    '/threats/reference-profiles',
    {
      method: 'POST',
      body: JSON.stringify(profile),
    },
  )

  return data.profile
}

// Analyze a candidate profile against a genuine profile.
export async function analyzeCandidateProfile(
  input: CandidateAnalysisInput,
): Promise<ThreatDetection> {
  const data = await authenticatedRequest<AnalyzeResponse>(
    '/threats/analyze',
    {
      method: 'POST',
      body: JSON.stringify(input),
    },
  )

  return data.detection
}

// Retrieve all detections belonging to the authenticated creator.
export async function getThreatDetections(): Promise<{
  total: number
  detections: ThreatDetection[]
}> {
  const data = await authenticatedRequest<DetectionListResponse>(
    '/threats/detections',
    { method: 'GET' },
  )

  return {
    total: data.total ?? 0,
    detections: data.detections ?? [],
  }
}

// Retrieve a single detection with its reference and candidate profiles.
export async function getThreatDetection(
  detectionId: string,
): Promise<ThreatDetection> {
  const data = await authenticatedRequest<DetectionResponse>(
    `/threats/detections/${encodeURIComponent(detectionId)}`,
    { method: 'GET' },
  )

  return data.detection
}

// Update an investigation status.
export async function updateThreatStatus(
  detectionId: string,
  status: InvestigationStatus,
): Promise<ThreatDetection> {
  const data = await authenticatedRequest<StatusUpdateResponse>(
    `/threats/detections/${encodeURIComponent(detectionId)}/status`,
    {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    },
  )

  return data.detection
}
