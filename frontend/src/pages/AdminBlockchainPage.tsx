
import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity,
  Blocks,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  Clock3,
  ExternalLink,
  FileCheck2,
  Loader2,
  RefreshCw,
  ShieldCheck,
  XCircle,
} from 'lucide-react'

import {
  anchorBlockchainBatch,
  getBlockchainBatch,
  getBlockchainBatches,
  getBlockchainOverview,
  verifyBlockchainBatch,
  type BatchStatus,
  type BlockchainOverview,
  type BatchVerificationResponse,
  type MerkleBatch,
  type MerkleBatchDetails,
} from '../services/adminBlockchainApi'

import './AdminBlockchain.css'

const PAGE_SIZE = 25

type FilterStatus = BatchStatus | 'ALL'

function shortenHash(value?: string | null, length = 12) {
  if (!value) return 'Not available'
  if (value.length <= length) return value

  const half = Math.floor((length - 3) / 2)
  return `${value.slice(0, half)}...${value.slice(-half)}`
}

function formatDate(value?: string | null) {
  if (!value) return 'Not available'

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) return 'Invalid date'

  return date.toLocaleString()
}

function formatTimestamp(value?: number) {
  if (!value) return 'Not available'
  return new Date(value * 1000).toLocaleString()
}

function getNetworkName(chainId?: number) {
  if (chainId === 31337) return 'Hardhat Local'
  if (chainId === 11155111) return 'Ethereum Sepolia'
  if (chainId === 1) return 'Ethereum Mainnet'
  return chainId ? `Chain ${chainId}` : 'Unknown network'
}

function StatusBadge({ status }: { status: string }) {
  const normalized = status.toUpperCase()

  const className =
    normalized === 'ANCHORED'
      ? 'blockchain-status anchored'
      : normalized === 'FAILED'
        ? 'blockchain-status failed'
        : 'blockchain-status pending'

  return (
    <span className={className}>
      {normalized === 'ANCHORED' && <CheckCircle2 size={13} />}
      {normalized === 'FAILED' && <XCircle size={13} />}
      {normalized !== 'ANCHORED' && normalized !== 'FAILED' && (
        <Clock3 size={13} />
      )}
      {normalized.replaceAll('_', ' ')}
    </span>
  )
}

function MetricCard({
  label,
  value,
  icon,
  accent,
}: {
  label: string
  value: number | string
  icon: React.ReactNode
  accent: string
}) {
  return (
    <div className={`blockchain-metric-card ${accent}`}>
      <div className="blockchain-metric-top">
        <span>{label}</span>
        <span className="blockchain-metric-icon">{icon}</span>
      </div>
      <div className="blockchain-metric-value">{value}</div>
    </div>
  )
}

export default function AdminBlockchainPage() {
  const [overview, setOverview] = useState<BlockchainOverview | null>(null)
  const [batches, setBatches] = useState<MerkleBatch[]>([])
  const [totalBatches, setTotalBatches] = useState(0)

  const [selectedBatch, setSelectedBatch] =
    useState<MerkleBatchDetails | null>(null)

  const [verification, setVerification] =
    useState<BatchVerificationResponse | null>(null)

  const [filter, setFilter] = useState<FilterStatus>('ALL')
  const [offset, setOffset] = useState(0)

  const [loading, setLoading] = useState(true)
  const [detailLoading, setDetailLoading] = useState(false)
  const [verificationLoading, setVerificationLoading] = useState(false)
  const [anchoringId, setAnchoringId] = useState<string | null>(null)

  const [error, setError] = useState<string | null>(null)
  const [actionMessage, setActionMessage] = useState<string | null>(null)

  const loadDashboard = useCallback(async () => {
    setLoading(true)
    setError(null)

    try {
      const [overviewResponse, batchResponse] = await Promise.all([
        getBlockchainOverview(),
        getBlockchainBatches({
          limit: PAGE_SIZE,
          offset,
          status: filter === 'ALL' ? '' : filter,
        }),
      ])

      setOverview(overviewResponse)
      setBatches(batchResponse.batches)
      setTotalBatches(batchResponse.total)
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to load blockchain dashboard.',
      )
    } finally {
      setLoading(false)
    }
  }, [offset, filter])

  useEffect(() => {
    void loadDashboard()
  }, [loadDashboard])

  const loadBatchDetails = async (batchId: string) => {
    setDetailLoading(true)
    setSelectedBatch(null)
    setVerification(null)
    setActionMessage(null)

    try {
      const response = await getBlockchainBatch(batchId)
      setSelectedBatch(response.batch)
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to load batch details.',
      )
    } finally {
      setDetailLoading(false)
    }
  }

  const handleAnchor = async (batch: MerkleBatch) => {
    const confirmed = window.confirm(
      `Anchor batch ${shortenHash(batch.id)} to the connected blockchain?`,
    )

    if (!confirmed) return

    setAnchoringId(batch.id)
    setActionMessage(null)
    setError(null)

    try {
      const response = await anchorBlockchainBatch(batch.id)

      if (response.success === false) {
        throw new Error(response.error || 'Batch anchoring failed.')
      }

      setActionMessage('Batch anchoring request completed successfully.')

      await loadDashboard()

      if (selectedBatch?.id === batch.id) {
        await loadBatchDetails(batch.id)
      }
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Unable to anchor batch.',
      )
    } finally {
      setAnchoringId(null)
    }
  }

  const handleVerify = async (batchId: string) => {
    setVerificationLoading(true)
    setVerification(null)
    setError(null)

    try {
      const response = await verifyBlockchainBatch(batchId)
      setVerification(response)
      setActionMessage('Verification completed.')
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Verification failed.',
      )
    } finally {
      setVerificationLoading(false)
    }
  }

  const filteredLabel = useMemo(() => {
    if (filter === 'ALL') return 'All batches'
    return filter.replaceAll('_', ' ')
  }, [filter])

  const currentPage = Math.floor(offset / PAGE_SIZE) + 1
  const totalPages = Math.max(1, Math.ceil(totalBatches / PAGE_SIZE))

  const connection = overview?.blockchain
  const isConnected = connection?.connected === true

  return (
    <div className="blockchain-page">
      {/* PAGE HEADER */}
      <div className="blockchain-page-header">
        <div>
          <div className="blockchain-eyebrow">
            <Blocks size={15} />
            CREATORXDR / ADMIN
          </div>

          <h1>Blockchain Audit</h1>

          <p>
            Monitor audit batches, anchor Merkle roots and verify
            blockchain integrity.
          </p>
        </div>

        <button
          className="blockchain-refresh-button"
          onClick={() => void loadDashboard()}
          disabled={loading}
        >
          <RefreshCw size={16} className={loading ? 'spin' : ''} />
          Refresh
        </button>
      </div>

      {/* ERROR MESSAGE */}
      {error && (
        <div className="blockchain-alert error">
          <CircleAlert size={18} />
          <span>{error}</span>
          <button onClick={() => setError(null)} aria-label="Dismiss error">
            ×
          </button>
        </div>
      )}

      {actionMessage && (
        <div className="blockchain-alert success">
          <CheckCircle2 size={18} />
          <span>{actionMessage}</span>
          <button
            onClick={() => setActionMessage(null)}
            aria-label="Dismiss message"
          >
            ×
          </button>
        </div>
      )}

      {/* NETWORK CONNECTION */}
      <section className="blockchain-network-panel">
        <div className="blockchain-network-heading">
          <div className="blockchain-network-title">
            <Activity size={19} />
            <h2>Network connection</h2>
          </div>

          <span className={isConnected ? 'connection-pill online' : 'connection-pill offline'}>
            <span className="connection-dot" />
            {isConnected ? 'CONNECTED' : 'DISCONNECTED'}
          </span>
        </div>

        {loading && !overview ? (
          <div className="blockchain-loading">
            <Loader2 className="spin" size={20} />
            Loading network information...
          </div>
        ) : (
          <div className="blockchain-network-grid">
            <div>
              <span className="blockchain-field-label">NETWORK</span>
              <strong>{getNetworkName(connection?.chain_id)}</strong>
            </div>

            <div>
              <span className="blockchain-field-label">CHAIN ID</span>
              <strong>{connection?.chain_id ?? 'Not available'}</strong>
            </div>

            <div>
              <span className="blockchain-field-label">CONTRACT VERSION</span>
              <strong>{connection?.contract_version ?? 'Not available'}</strong>
            </div>

            <div>
              <span className="blockchain-field-label">ANCHORED ROOTS</span>
              <strong>{connection?.total_anchored_roots ?? 0}</strong>
            </div>

            <div className="blockchain-address-field">
              <span className="blockchain-field-label">CONTRACT ADDRESS</span>
              <strong title={connection?.contract_address ?? ''}>
                {shortenHash(connection?.contract_address, 24)}
              </strong>
            </div>

            <div className="blockchain-address-field">
              <span className="blockchain-field-label">SIGNER ADDRESS</span>
              <strong title={connection?.account_address ?? ''}>
                {shortenHash(connection?.account_address, 24)}
              </strong>
            </div>
          </div>
        )}
      </section>

      {/* METRICS */}
      <section className="blockchain-metrics-grid">
        <MetricCard
          label="TOTAL BATCHES"
          value={overview?.batches.total ?? 0}
          icon={<Blocks size={20} />}
          accent="metric-black"
        />

        <MetricCard
          label="PENDING"
          value={overview?.batches.pending ?? 0}
          icon={<Clock3 size={20} />}
          accent="metric-yellow"
        />

        <MetricCard
          label="ANCHORED"
          value={overview?.batches.anchored ?? 0}
          icon={<CheckCircle2 size={20} />}
          accent="metric-blue"
        />

        <MetricCard
          label="FAILED"
          value={overview?.batches.failed ?? 0}
          icon={<XCircle size={20} />}
          accent="metric-red"
        />
      </section>

      {/* BATCH TABLE */}
      <section className="blockchain-batches-panel">
        <div className="blockchain-section-header">
          <div>
            <h2>Merkle batches</h2>
            <p>Review and manage audit records anchored to Ethereum.</p>
          </div>

          <select
            value={filter}
            onChange={(event) => {
              setFilter(event.target.value as FilterStatus)
              setOffset(0)
              setSelectedBatch(null)
              setVerification(null)
            }}
            className="blockchain-filter"
          >
            <option value="ALL">All statuses</option>
            <option value="PENDING_ANCHOR">Pending</option>
            <option value="ANCHORED">Anchored</option>
            <option value="FAILED">Failed</option>
          </select>
        </div>

        <div className="blockchain-table-caption">
          Showing {filteredLabel.toLowerCase()} · {totalBatches} records
        </div>

        <div className="blockchain-table-wrapper">
          <table className="blockchain-table">
            <thead>
              <tr>
                <th>Batch ID</th>
                <th>Merkle root</th>
                <th>Leaves</th>
                <th>Status</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>

            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6} className="blockchain-empty">
                    <Loader2 className="spin" size={20} />
                    Loading batches...
                  </td>
                </tr>
              ) : batches.length === 0 ? (
                <tr>
                  <td colSpan={6} className="blockchain-empty">
                    No batches found.
                  </td>
                </tr>
              ) : (
                batches.map((batch) => (
                  <tr
                    key={batch.id}
                    className={
                      selectedBatch?.id === batch.id
                        ? 'selected-row'
                        : ''
                    }
                  >
                    <td>
                      <button
                        className="blockchain-text-button"
                        onClick={() => void loadBatchDetails(batch.id)}
                      >
                        {shortenHash(batch.id, 14)}
                      </button>
                    </td>

                    <td title={batch.merkle_root}>
                      <code>{shortenHash(batch.merkle_root, 16)}</code>
                    </td>

                    <td>{batch.leaf_count}</td>

                    <td>
                      <StatusBadge status={batch.status} />
                    </td>

                    <td>{formatDate(batch.created_at)}</td>

                    <td>
                      <div className="blockchain-row-actions">
                        <button
                          className="blockchain-action-button"
                          onClick={() => void loadBatchDetails(batch.id)}
                          title="View details"
                        >
                          <ExternalLink size={15} />
                        </button>

                        {batch.status === 'PENDING_ANCHOR' && (
                          <button
                            className="blockchain-anchor-button"
                            onClick={() => void handleAnchor(batch)}
                            disabled={anchoringId === batch.id || !isConnected}
                            title={
                              !isConnected
                                ? 'Blockchain is disconnected'
                                : 'Anchor batch'
                            }
                          >
                            {anchoringId === batch.id ? (
                              <Loader2 className="spin" size={14} />
                            ) : (
                              <Blocks size={14} />
                            )}
                            Anchor
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* PAGINATION */}
        <div className="blockchain-pagination">
          <span>
            Page {currentPage} of {totalPages}
          </span>

          <div>
            <button
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              disabled={offset === 0 || loading}
              aria-label="Previous page"
            >
              <ChevronLeft size={17} />
            </button>

            <button
              onClick={() => setOffset(offset + PAGE_SIZE)}
              disabled={offset + PAGE_SIZE >= totalBatches || loading}
              aria-label="Next page"
            >
              <ChevronRight size={17} />
            </button>
          </div>
        </div>
      </section>

      {/* BATCH DETAILS */}
      {(detailLoading || selectedBatch) && (
        <section className="blockchain-details-panel">
          <div className="blockchain-section-header">
            <div>
              <h2>Batch details</h2>
              <p>Audit batch metadata and individual Merkle leaves.</p>
            </div>

            {selectedBatch && (
              <StatusBadge status={selectedBatch.status} />
            )}
          </div>

          {detailLoading ? (
            <div className="blockchain-loading">
              <Loader2 className="spin" size={20} />
              Loading batch details...
            </div>
          ) : selectedBatch ? (
            <>
              <div className="blockchain-details-grid">
                <div>
                  <span className="blockchain-field-label">BATCH ID</span>
                  <code>{selectedBatch.id}</code>
                </div>

                <div>
                  <span className="blockchain-field-label">MERKLE ROOT</span>
                  <code>{selectedBatch.merkle_root}</code>
                </div>

                <div>
                  <span className="blockchain-field-label">LEAF COUNT</span>
                  <strong>{selectedBatch.leaf_count}</strong>
                </div>

                <div>
                  <span className="blockchain-field-label">HASH VERSION</span>
                  <strong>{selectedBatch.hash_version}</strong>
                </div>

                <div>
                  <span className="blockchain-field-label">BLOCK NUMBER</span>
                  <strong>{selectedBatch.block_number ?? 'Not anchored'}</strong>
                </div>

                <div>
                  <span className="blockchain-field-label">CHAIN ID</span>
                  <strong>{selectedBatch.chain_id ?? 'Not available'}</strong>
                </div>

                <div>
                  <span className="blockchain-field-label">TRANSACTION HASH</span>
                  <code>{selectedBatch.transaction_hash ?? 'Not available'}</code>
                </div>

                <div>
                  <span className="blockchain-field-label">CONTRACT ADDRESS</span>
                  <code>{selectedBatch.contract_address ?? 'Not available'}</code>
                </div>

                <div>
                  <span className="blockchain-field-label">CREATED AT</span>
                  <strong>{formatDate(selectedBatch.created_at)}</strong>
                </div>

                <div>
                  <span className="blockchain-field-label">ANCHORED AT</span>
                  <strong>{formatDate(selectedBatch.anchored_at)}</strong>
                </div>
              </div>

              <div className="blockchain-detail-actions">
                <button
                  className="blockchain-verify-button"
                  onClick={() => void handleVerify(selectedBatch.id)}
                  disabled={verificationLoading}
                >
                  {verificationLoading ? (
                    <Loader2 className="spin" size={16} />
                  ) : (
                    <ShieldCheck size={16} />
                  )}
                  Verify integrity
                </button>

                {selectedBatch.status === 'PENDING_ANCHOR' && (
                  <button
                    className="blockchain-anchor-button"
                    onClick={() => void handleAnchor(selectedBatch)}
                    disabled={anchoringId === selectedBatch.id || !isConnected}
                  >
                    <Blocks size={15} />
                    Anchor batch
                  </button>
                )}
              </div>

              {/* VERIFICATION RESULT */}
              {verification && verification.batch_id === selectedBatch.id && (
                <div className="blockchain-verification">
                  <h3>
                    <ShieldCheck size={18} />
                    Verification results
                  </h3>

                  <div className="verification-result-row">
                    <span>Database integrity</span>
                    <StatusBadge
                      status={
                        verification.database_integrity.verified
                          ? 'VERIFIED'
                          : 'FAILED'
                      }
                    />
                  </div>

                  <div className="verification-result-row">
                    <span>On-chain verification</span>
                    <StatusBadge
                      status={
                        verification.on_chain.checked &&
                        verification.on_chain.anchored
                          ? 'ANCHORED'
                          : verification.on_chain.checked
                            ? 'FAILED'
                            : 'NOT CHECKED'
                      }
                    />
                  </div>

                  <div className="verification-result-row">
                    <span>Verified Merkle root</span>
                    <code>{verification.merkle_root}</code>
                  </div>

                  {verification.on_chain.chain_id !== undefined && (
                    <div className="verification-result-row">
                      <span>Verified chain</span>
                      <strong>
                        {getNetworkName(verification.on_chain.chain_id)}
                      </strong>
                    </div>
                  )}

                  {verification.on_chain.timestamp !== undefined && (
                    <div className="verification-result-row">
                      <span>On-chain timestamp</span>
                      <strong>
                        {formatTimestamp(verification.on_chain.timestamp)}
                      </strong>
                    </div>
                  )}

                  {verification.on_chain.error && (
                    <div className="blockchain-verification-error">
                      {verification.on_chain.error}
                    </div>
                  )}
                </div>
              )}

              {/* MERKLE LEAVES */}
              <div className="blockchain-leaves-section">
                <h3>
                  <FileCheck2 size={17} />
                  Merkle leaves ({selectedBatch.leaves.length})
                </h3>

                {selectedBatch.leaves.length === 0 ? (
                  <p className="blockchain-no-leaves">
                    No leaves found in this batch.
                  </p>
                ) : (
                  <div className="blockchain-table-wrapper">
                    <table className="blockchain-table">
                      <thead>
                        <tr>
                          <th>Index</th>
                          <th>Leaf ID</th>
                          <th>Audit log ID</th>
                          <th>Event hash</th>
                        </tr>
                      </thead>

                      <tbody>
                        {selectedBatch.leaves.map((leaf) => (
                          <tr key={leaf.id}>
                            <td>{leaf.leaf_index}</td>
                            <td>
                              <code>{shortenHash(leaf.id, 14)}</code>
                            </td>
                            <td>
                              <code>{shortenHash(leaf.audit_log_id, 14)}</code>
                            </td>
                            <td title={leaf.event_hash}>
                              <code>{shortenHash(leaf.event_hash, 18)}</code>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </>
          ) : null}
        </section>
      )}
    </div>
  )
}
