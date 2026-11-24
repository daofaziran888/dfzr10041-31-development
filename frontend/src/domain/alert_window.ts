/** 窗口告警与转发检测入口的纯前端数据层：与后端 /api/alert-window 对齐。 */
import { fetchJson, request } from '@/api/client'

export type WindowEvidence = {
  event_id: string
  event_type: string
  occurred_at: string
  source_id: string
  line_number: number
  original_line: string
  corrected: boolean
  corrected_from_type: string
}

export type WindowReport = {
  window_id: string
  event_type: string
  window_start: string
  window_end: string
  threshold: number
  count: number
  event_ids: string[]
  evidence: WindowEvidence[]
  triggered: boolean
  evaluated_at: string
  closed: boolean
  retransmissions: number
  alerted: boolean
  alerts: { alert_id: string; state: string; target: string; delivery_id: string | null }[]
}

export type PendingItem = {
  type: 'alert' | 'correction'
  alert_id: string
  correction_id?: string
  window_id: string
  target: string
  package_id: string
  count: number
  threshold?: number
}

export type PendingResult = {
  items: PendingItem[]
  alert_ids: string[]
  correction_ids: string[]
}

export type TriggerBasis = {
  rule: string
  threshold: number
  count: number
  window_start: string
  window_end: string
  event_type: string
  window_closed: boolean
  below_threshold?: boolean
  original_alert_id?: string
}

export type ForwardPackage = {
  package_id: string
  kind: 'alert' | 'correction'
  alert_id: string
  ref_alert_id?: string
  correction_id?: string
  original_package_id?: string
  window_id: string
  target: string
  threshold: number
  count: number
  trigger_basis: TriggerBasis
  event_ids: string[]
  event_identities: WindowEvidence[]
  withdrawn_event_ids?: string[]
  notice?: string
}

export type DispatchResult = {
  ok: boolean
  packages: ForwardPackage[]
  alert_ids: string[]
  correction_ids: string[]
}

export type RetransmissionRecord = {
  event_id: string
  event_type: string
  occurred_at: string
  received_at: string
  counted: boolean
  retransmissions: number
}

export async function loadWindows(): Promise<WindowReport[]> {
  return fetchJson<WindowReport[]>('/api/alert-window/windows')
}

export async function loadPending(): Promise<PendingResult> {
  return fetchJson<PendingResult>('/api/alert-window/pending')
}

export async function loadRetransmissions(): Promise<RetransmissionRecord[]> {
  return fetchJson<RetransmissionRecord[]>('/api/alert-window/retransmissions')
}

export async function dispatchPending(): Promise<DispatchResult> {
  const response = await request('/api/alert-window/dispatch', {
    method: 'POST',
    body: JSON.stringify({}),
  })
  if (!response.ok) throw new Error('待派发清单派发失败')
  return (await response.json()) as DispatchResult
}

export type CorrectionSummary = {
  correction_id: string
  alert_id: string
  ref_alert_id: string
  window_id: string
  target: string
  original_package_id: string
  state: string
  count: number
  withdrawn_event_ids: string[]
}

export async function correctEvent(
  eventId: string,
  reason = '原行更正为普通访问',
): Promise<{ corrections: CorrectionSummary[]; duplicate_correction: boolean }> {
  const response = await request(`/api/alert-window/events/${eventId}/correct`, {
    method: 'POST',
    body: JSON.stringify({ new_event_type: 'EVEN-0001', reason }),
  })
  if (!response.ok) throw new Error('原行更正失败')
  return (await response.json()) as {
    corrections: CorrectionSummary[]
    duplicate_correction: boolean
  }
}
