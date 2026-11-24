
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:5001/api'

const ACCESS_TOKEN_KEY = 'creatorxdr_access_token'
const REFRESH_TOKEN_KEY = 'creatorxdr_refresh_token'

// --------------------------------------------------
// TYPES
// --------------------------------------------------

export type BatchStatus =
  | 'PENDING_ANCHOR'
  | 'ANCHORED'
  | 'FAILED'

export interface BatchCounts {
  total: number
  pending: number
  anchored: number
  failed: number
}

export interface BlockchainConnection {
  connected: boolean
  chain_id?: number
  account_address?: string
  contract_address?: string
  contract_version?: string
  total_anchored_roots?: number
}

export interface BlockchainOverview {
  success: boolean
  batches: BatchCounts
  blockchain: BlockchainConnection
  error?: string
}

export interface MerkleBatch {
  id: string
  merkle_root: string
  leaf_count: number
  hash_version: string
  status: BatchStatus
  chain_id: number | null
  contract_address: string | null
  transaction_hash: string | null
  block_number: number | null
  created_at: string
  anchored_at: string | null
}

export interface MerkleBatchLeaf {
  id: string
  batch_id: string
  audit_log_id: string
  event_hash: string
  leaf_index: number
  created_at: string
}

export interface MerkleBatchDetails extends MerkleBatch {
  leaves: MerkleBatchLeaf[]
}

export interface BatchListResponse {
  success: boolean
  total: number
  limit: number
  offset: number
  batches: MerkleBatch[]
}

export interface BatchDetailsResponse {
  success: boolean
  batch: MerkleBatchDetails
}

export interface DatabaseIntegrity {
  verified: boolean
}

export interface OnChainVerification {
  checked: boolean
  anchored: boolean
  chain_id?: number
  contract_address?: string
  timestamp?: number
  submitter?: string
  error?: string
}

export interface BatchVerificationResponse {
  success: boolean
  batch_id: string
  merkle_root: string
  database_integrity: DatabaseIntegrity
  on_chain: OnChainVerification
}

export interface AnchorBatchResponse {
  success: boolean
  batch_id?: string
  status?: BatchStatus
  merkle_root?: string
  transaction_hash?: string
  block_number?: number
  error?: string
  [key: string]: unknown
}

export class BlockchainApiError extends Error {
  status: number

  constructor(message: string, status = 500) {
    super(message)
    this.name = 'BlockchainApiError'
    this.status = status
  }
}

// --------------------------------------------------
// AUTHENTICATION
// Uses the same session storage keys as AuthContext.
// --------------------------------------------------

function getAccessToken(): string | null {
  return sessionStorage.getItem(ACCESS_TOKEN_KEY)
}

function getRefreshToken(): string | null {
  return sessionStorage.getItem(REFRESH_TOKEN_KEY)
}

function saveAccessToken(token: string): void {
  sessionStorage.setItem(ACCESS_TOKEN_KEY, token)
}

async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = getRefreshToken()

  if (!refreshToken) return null

  try {
    const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${refreshToken}`,
        'Content-Type': 'application/json',
      },
    })

    if (!response.ok) return null

    const data = await response.json()

    if (!data.access_token) return null

    saveAccessToken(data.access_token)

    return data.access_token
  } catch {
    return null
  }
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
    throw new BlockchainApiError(
      'You are not authenticated. Please log in again.',
      401,
    )
  }

  const makeRequest = (accessToken: string) => {
    const headers = new Headers(options.headers)

    headers.set('Authorization', `Bearer ${accessToken}`)

    if (
      options.body &&
      !(options.body instanceof FormData)
    ) {
      headers.set('Content-Type', 'application/json')
    }

    return fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    })
  }

  let response = await makeRequest(token)

  if (response.status === 401) {
    const refreshedToken = await refreshAccessToken()

    if (!refreshedToken) {
      throw new BlockchainApiError(
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
      // Retain the HTTP status message.
    }

    throw new BlockchainApiError(message, response.status)
  }

  return response
}

async function getJson<T>(endpoint: string): Promise<T> {
  const response = await authenticatedFetch(endpoint)
  return (await response.json()) as T
}

// --------------------------------------------------
// BLOCKCHAIN OVERVIEW
// GET /api/admin/blockchain/overview
// --------------------------------------------------

export async function getBlockchainOverview(): Promise<BlockchainOverview> {
  return getJson<BlockchainOverview>(
    '/admin/blockchain/overview',
  )
}

// --------------------------------------------------
// BATCH LIST
// GET /api/admin/blockchain/batches
// --------------------------------------------------

export async function getBlockchainBatches(
  options: {
    limit?: number
    offset?: number
    status?: BatchStatus | ''
  } = {},
): Promise<BatchListResponse> {
  const params = new URLSearchParams()

  params.set('limit', String(options.limit ?? 25))
  params.set('offset', String(options.offset ?? 0))

  if (options.status) {
    params.set('status', options.status)
  }

  return getJson<BatchListResponse>(
    `/admin/blockchain/batches?${params.toString()}`,
  )
}

// --------------------------------------------------
// BATCH DETAILS
// GET /api/admin/blockchain/batches/:id
// --------------------------------------------------

export async function getBlockchainBatch(
  batchId: string,
): Promise<BatchDetailsResponse> {
  if (!batchId) {
    throw new BlockchainApiError('Batch ID is required.', 400)
  }

  return getJson<BatchDetailsResponse>(
    `/admin/blockchain/batches/${encodeURIComponent(batchId)}`,
  )
}

// --------------------------------------------------
// ANCHOR BATCH
// POST /api/admin/blockchain/batches/:id/anchor
// --------------------------------------------------

export async function anchorBlockchainBatch(
  batchId: string,
): Promise<AnchorBatchResponse> {
  if (!batchId) {
    throw new BlockchainApiError('Batch ID is required.', 400)
  }

  const response = await authenticatedFetch(
    `/admin/blockchain/batches/${encodeURIComponent(batchId)}/anchor`,
    {
      method: 'POST',
    },
  )

  return (await response.json()) as AnchorBatchResponse
}

// --------------------------------------------------
// VERIFY BATCH
// GET /api/admin/blockchain/batches/:id/verify
// --------------------------------------------------

export async function verifyBlockchainBatch(
  batchId: string,
): Promise<BatchVerificationResponse> {
  if (!batchId) {
    throw new BlockchainApiError('Batch ID is required.', 400)
  }

  return getJson<BatchVerificationResponse>(
    `/admin/blockchain/batches/${encodeURIComponent(batchId)}/verify`,
  )
}
