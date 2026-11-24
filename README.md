# 拾音工坊 · 日志采集与事件流处理平台

面向多租户应用日志的结构化采集、事件流解析、格式标准化、敏感脱敏、采样归并、异常告警与归档回溯的日志采集与事件流处理平台。

这是一个前后端分离的管理平台：前端 Vue 3 + Vite + TypeScript，后端 FastAPI（Python）。
两边各自独立启动，前端 dev server 已关掉自动打开页面，启动后按终端打印的地址手工打开。

## 目录结构

```text
.
├── frontend/                 Vue 3 + Vite + TypeScript 前端
│   ├── src/views/WorkbenchView.vue|tsx  全部模块共享工作台
│   ├── src/data/modules.ts              18个业务模块配置
│   ├── src/api/              统一请求封装
│   └── vite.config.ts        dev server 配置（open: false）
├── backend/                  FastAPI（Python） 后端
│   ├── app/routers/resource.py  通用查询/导出/登记/动作接口
│   ├── app/services/<key>.py    每个模块独立领域逻辑
│   ├── app/services/base.py     共享服务骨架
│   └── app/store.py          内存数据仓库与示例数据
├── .gitignore
└── docker-compose.yml
```

## 启动

### 后端

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
./run.sh
```

健康检查：`curl http://127.0.0.1:8000/api/health`

### 前端

```bash
cd frontend
npm ci
npm run dev
```

前端默认监听 `http://127.0.0.1:5173/`，dev server 不会自动打开浏览器，
需要自己访问。`/api` 由 vite 代理到后端 `http://127.0.0.1:8000`。

## 业务模块

| 模块 | 目录 | 业务对象 | 主要字段 |
| --- | --- | --- | --- |
| 日志源 | `log_source` | 日志来源 | 源编号、源名称、应用标识 |
| 解析规则 | `parser_rule` | 解析方案 | 方案编号、日志来源、正则表达式 |
| 脱敏规则 | `mask_rule` | 脱敏配置 | 规则编号、目标字段、脱敏方式 |
| 事件分类 | `event_type` | 事件类型 | 类型编号、类型名称、分类标签 |
| 采集作业 | `ingest_job` | 采集任务 | 作业编号、日志来源、采集模式 |
| 批次检查点 | `batch_checkpoint` | 检查点记录 | 记录编号、采集作业、文件路径 |
| 事件存储 | `event_store` | 事件记录 | 记录编号、事件类型、原始内容 |
| 异常告警 | `anomaly_rule` | 告警规则 | 规则编号、事件类型、检测条件 |
| 采样归并 | `sample_job` | 采样计划 | 计划编号、事件类型、采样比例 |
| 字段增强 | `field_enrich` | 增强规则 | 规则编号、目标字段、增强来源 |
| 归档策略 | `archive_policy` | 归档方案 | 方案编号、事件类型、保留天数 |
| 转发路由 | `forward_rule` | 转发规则 | 规则编号、事件类型、目标地址 |
| Schema版本 | `schema_version` | 版本记录 | 版本编号、日志来源、字段变更 |
| 去重过滤 | `dedup_filter` | 去重规则 | 规则编号、事件类型、去重字段 |
| 采集指标 | `ingest_metric` | 指标记录 | 记录编号、日志来源、采集速率 |
| 事件重放 | `replay_record` | 重放任务 | 任务编号、来源事件、重放范围 |
| 质量报告 | `quality_report` | 质量评估 | 报告编号、日志来源、完整率 |
| 标签分类 | `tag_taxonomy` | 标签定义 | 标签编号、标签名称、父级标签 |
| 打包导出 | `export_bundle` | 导出包 | 包编号、事件类型、时间范围 |
| 访问审计 | `audit_event` | 审计记录 | 记录编号、操作模块、操作人 |
| 租户隔离 | `tenant_isolation` | 租户配置 | 租户编号、租户名称、日志来源 |
| 格式适配 | `format_adapt` | 适配器配置 | 适配器编号、输入格式、输出格式 |

## 窗口告警与转发

异常告警不再按"本次日志事件总数"触发，而是按**事件发生时间**分窗：

- `backend/app/core/alert_window.py`：窗口引擎。事件按 `event_time` 落进固定长度
  时间窗（默认 5 分钟，至少 3 条才触发）；重传同一原始行只累计重传次数，
  不增加计数、也不会把事件挪进别的时间窗。
- 每个时间窗最多一条告警批次；只有达到门槛的窗口才进入待派发清单，
  转发包里带 `trigger_basis`（窗口起止、阈值、计数）和 `event_identities`
  （原事件身份）。并发/重复派发同一窗口最多送达一次。
- 已送达告警因原行更正不再达门槛时，向同一目标补发 `kind=correction` 的
  更正包，`ref_alert_id` / `original_package_id` 关联原告警，`withdrawn_event_ids`
  标出被更正掉的事件；同一更正只交付一次。原告警与更正分别核销。
- 送达事实以目标回执为准：目标已收到但本端登记中断时，重开原告警会补登记
  送达，不重发旧包；此时仍不达门槛的窗口照样要交付更正。
- 检测入口：`GET /api/alert-window/snapshot|windows|pending|retransmissions|receipts`，
  `POST /api/alert-window/events|evaluate|rounds|dispatch`，
  `POST /api/alert-window/events/{id}/correct`，
  `POST /api/alert-window/alerts/{id}/reopen`。
- 前端入口：侧栏「窗口告警」（`/alert-window`），展示窗口核实、待派发清单、
  本轮转发包与重传记录。

## 约定

- 全部模块共享`frontend/src/views/WorkbenchView.vue|tsx`和一套资源路由。
- 每个模块仍保留独立`backend/app/services/<模块>.py`；纯前端保留
  `frontend/src/domain/<模块>.ts`，用于承载真实业务差异并维持36题位容量。
- 列表接口统一返回 `{ items, total, page, size }`，动作接口统一返回 `{ ok, message }`。
- 状态流转只允许在 `app/services` 里改，路由层不做业务判断。

领域：数据工程
子方向：数据采集、爬虫与RPA
