<template>
  <section class="page" data-module="alert_window">
    <header class="page-head">
      <div>
        <h2>窗口告警</h2>
        <p class="page-desc">
          按事件发生时间分窗核验阈值，只有达到门槛的窗口才进入转发；晚到事件回到它发生的那一窗，重传原行不抬高计数。
        </p>
      </div>
      <div class="page-actions">
        <button class="btn" data-testid="reload-windows" type="button" @click="reload">刷新窗口</button>
        <button
          class="btn primary"
          data-testid="dispatch-pending"
          type="button"
          :disabled="!pending.items.length || dispatching"
          @click="dispatch"
        >
          {{ dispatching ? '派发中…' : `派发待发清单（${pending.items.length}）` }}
        </button>
      </div>
    </header>

    <div class="stat-row">
      <article class="stat-card">
        <span class="stat-label">时间窗总数</span>
        <strong class="stat-value">{{ windows.length }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">达到门槛</span>
        <strong class="stat-value">{{ triggeredCount }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">待派发告警</span>
        <strong class="stat-value">{{ pending.alert_ids.length }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">待交付更正</span>
        <strong class="stat-value">{{ pending.correction_ids.length }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">重传记录</span>
        <strong class="stat-value">{{ retransmissions.length }}</strong>
      </article>
    </div>

    <h3 class="section-title">窗口核实</h3>
    <table class="data-table">
      <thead>
        <tr>
          <th>窗口</th>
          <th>起点 ~ 终点</th>
          <th>事件类型</th>
          <th>计数 / 门槛</th>
          <th>是否结束</th>
          <th>重传</th>
          <th>触发</th>
          <th>告警批次</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="item in windows"
          :key="item.window_id"
          :data-testid="`window-${item.window_id}`"
          :data-triggered="String(item.triggered)"
        >
          <td>{{ item.window_id }}</td>
          <td>{{ formatTime(item.window_start) }} ~ {{ formatTime(item.window_end) }}</td>
          <td>{{ item.event_type }}</td>
          <td>{{ item.count }} / {{ item.threshold }}</td>
          <td>{{ item.closed ? '已结束' : '未结束' }}</td>
          <td>{{ item.retransmissions }}</td>
          <td>
            <span :class="['state-chip', item.triggered ? 'ok' : 'muted']">
              {{ item.triggered ? '已触发' : '未达门槛' }}
            </span>
          </td>
          <td>
            <span v-for="alert in item.alerts" :key="alert.alert_id" class="alert-tag">
              {{ alert.alert_id }} · {{ alert.state }}
            </span>
            <span v-if="!item.alerts.length" class="muted-text">—</span>
          </td>
        </tr>
        <tr v-if="!windows.length">
          <td colspan="8" class="empty-state">暂无窗口数据，可从检测入口登记事件后再核对</td>
        </tr>
      </tbody>
    </table>

    <h3 class="section-title">待派发清单</h3>
    <table class="data-table">
      <thead>
        <tr>
          <th>类型</th>
          <th>窗口</th>
          <th>目标</th>
          <th>计数</th>
          <th>关联告警</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in pending.items" :key="`${item.type}-${item.package_id}`">
          <td>{{ item.type === 'alert' ? '窗口告警' : '更正交付' }}</td>
          <td>{{ item.window_id }}</td>
          <td>{{ item.target }}</td>
          <td>{{ item.count }}<span v-if="item.threshold"> / {{ item.threshold }}</span></td>
          <td>{{ item.type === 'alert' ? item.alert_id : `${item.correction_id} → ${item.alert_id}` }}</td>
        </tr>
        <tr v-if="!pending.items.length">
          <td colspan="5" class="empty-state">当前没有达到门槛的窗口或待交付更正</td>
        </tr>
      </tbody>
    </table>

    <h3 class="section-title">本轮实际发出的转发包</h3>
    <table class="data-table">
      <thead>
        <tr>
          <th>包编号</th>
          <th>类型</th>
          <th>窗口</th>
          <th>触发依据</th>
          <th>原事件身份</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in sent" :key="item.package_id" :data-testid="`package-${item.package_id}`">
          <td>{{ item.package_id }}</td>
          <td>{{ item.kind === 'alert' ? '告警' : '更正' }}</td>
          <td>{{ item.window_id }}</td>
          <td>
            {{ item.trigger_basis.rule }}：{{ item.trigger_basis.count }} /
            {{ item.trigger_basis.threshold }}
            <span v-if="item.trigger_basis.below_threshold" class="muted-text">（已低于门槛）</span>
          </td>
          <td class="identity-cell">
            <span v-for="event in item.event_identities" :key="event.event_id">
              {{ event.event_id }} @ {{ formatTime(event.occurred_at) }}
            </span>
          </td>
        </tr>
        <tr v-if="!sent.length">
          <td colspan="5" class="empty-state">本轮没有派发；只有达到门槛的窗口才会组包</td>
        </tr>
      </tbody>
    </table>

    <h3 class="section-title">重传记录</h3>
    <table class="data-table">
      <thead>
        <tr><th>事件身份</th><th>发生时间</th><th>接收时间</th><th>是否计入</th><th>累计重传</th></tr>
      </thead>
      <tbody>
        <tr v-for="item in retransmissions" :key="`${item.event_id}-${item.received_at}`">
          <td>{{ item.event_id }}</td>
          <td>{{ formatTime(item.occurred_at) }}</td>
          <td>{{ formatTime(item.received_at) }}</td>
          <td>{{ item.counted ? '新事件' : '重传' }}</td>
          <td>{{ item.retransmissions }}</td>
        </tr>
        <tr v-if="!retransmissions.length">
          <td colspan="5" class="empty-state">暂无重传</td>
        </tr>
      </tbody>
    </table>

    <footer class="page-foot">
      <span>{{ windows.length }} 个时间窗 · {{ pending.items.length }} 条待派发 · {{ sent.length }} 个已组包</span>
      <span v-if="errorMessage" class="error-text">{{ errorMessage }}</span>
    </footer>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import {
  dispatchPending,
  loadPending,
  loadRetransmissions,
  loadWindows,
} from '@/domain/alert_window'
import type {
  ForwardPackage,
  PendingResult,
  RetransmissionRecord,
  WindowReport,
} from '@/domain/alert_window'

const windows = ref<WindowReport[]>([])
const pending = ref<PendingResult>({ items: [], alert_ids: [], correction_ids: [] })
const retransmissions = ref<RetransmissionRecord[]>([])
const sent = ref<ForwardPackage[]>([])
const dispatching = ref(false)
const errorMessage = ref('')

const triggeredCount = computed(() => windows.value.filter((item) => item.triggered).length)

function formatTime(value: string) {
  if (!value) return '—'
  return value.replace('T', ' ').slice(0, 19)
}

async function reload() {
  errorMessage.value = ''
  try {
    const [windowRows, pendingRows, retransmissionRows] = await Promise.all([
      loadWindows(),
      loadPending(),
      loadRetransmissions(),
    ])
    windows.value = windowRows
    pending.value = pendingRows
    retransmissions.value = retransmissionRows
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '窗口数据读取失败'
  }
}

async function dispatch() {
  dispatching.value = true
  errorMessage.value = ''
  try {
    const result = await dispatchPending()
    sent.value = result.packages
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '派发失败'
  } finally {
    dispatching.value = false
  }
}

onMounted(reload)
</script>

<style scoped>
.section-title { font-size: 14px; margin: 18px 0 8px; }
.state-chip { font-size: 12px; padding: 2px 8px; border-radius: 10px; }
.state-chip.ok { background: #dcfce7; color: #166534; }
.state-chip.muted { background: #f1f5f9; color: #475569; }
.alert-tag { display: inline-block; margin-right: 6px; font-size: 12px; }
.muted-text { color: var(--muted); }
.identity-cell span { display: block; font-size: 12px; }
</style>
