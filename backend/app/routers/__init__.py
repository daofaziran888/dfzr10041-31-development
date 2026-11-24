"""业务路由汇总：所有模块共用一套资源路由，由领域服务完成分派。"""
from __future__ import annotations

from app.routers import alert_window, resource

# 固定前缀的检测入口必须先于 /api/{module} 资源路由注册，
# 否则 /api/alert-window/windows 会被资源路由当成 entry_id 抢先匹配。
ROUTERS = [alert_window, resource]
