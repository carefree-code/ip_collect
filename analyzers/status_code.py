"""异常状态码分析器"""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from .base import BaseAnalyzer, ThreatInfo
from utils.log_parser import LogEntry


def _to_utc(dt: datetime) -> datetime:
    """
    将 datetime 统一转换为 UTC 时间（无时区标记）

    所有时间统一为 UTC，确保跨时区服务器的时间比较正确
    """
    if dt is None:
        return None

    if dt.tzinfo is not None:
        # 有时区信息，转换为 UTC
        utc_dt = dt.astimezone(timezone.utc)
        return utc_dt.replace(tzinfo=None)
    else:
        # 无时区信息，假定已经是 UTC（来自 log_parser 的转换）
        return dt


def _utc_now() -> datetime:
    """获取当前 UTC 时间（无时区标记）"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class StatusCodeAnalyzer(BaseAnalyzer):
    """异常状态码分析器 - 检测大量4xx/5xx错误"""

    def __init__(self, config: Dict = None):
        super().__init__(config)

        thresholds = self.config.get('thresholds', {}).get('error_rate', {})
        self.window_seconds = thresholds.get('window_seconds', 60)
        self.max_errors = thresholds.get('max_errors', 50)

        scores = self.config.get('threat_scores', {})
        self.threat_score = scores.get('error_flood', 2)

        # IP错误记录 {ip: [(timestamp, status_code), ...]}
        self._error_records: Dict[str, List[tuple]] = defaultdict(list)
        # 已标记的IP
        self._flagged_ips: set = set()

    @property
    def name(self) -> str:
        return 'status_code'

    def analyze(self, entry: LogEntry) -> Optional[ThreatInfo]:
        """分析状态码"""
        if not entry.ip or not entry.timestamp:
            return None

        # 只关注特定的异常错误，排除常见的正常4xx
        # 401: 未授权（正常的认证保护）
        # 404: 未找到（可能是缺失资源，不一定是攻击）
        # 405: 方法不允许（可能是正常的API调用错误）
        # 关注：403（禁止访问，WAF拦截）、500-5xx（服务器错误，可能是攻击导致）
        status = entry.status

        # 只统计这些可疑的错误码
        suspicious_codes = {403, 500, 501, 502, 503, 504, 505}

        if status not in suspicious_codes:
            return None

        ip = entry.ip
        now = _to_utc(entry.timestamp)

        # 记录错误
        self._error_records[ip].append((now, entry.status))

        # 清理过期记录
        cutoff = now - timedelta(seconds=self.window_seconds)
        self._error_records[ip] = [
            (t, s) for t, s in self._error_records[ip] if t > cutoff
        ]

        # 检查错误数量
        error_count = len(self._error_records[ip])

        if error_count > self.max_errors:
            if ip not in self._flagged_ips:
                self._flagged_ips.add(ip)

                # 统计错误类型
                status_counts = defaultdict(int)
                for _, status in self._error_records[ip]:
                    status_counts[status] += 1

                top_errors = sorted(
                    status_counts.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:3]

                error_summary = ','.join([f"{s}:{c}" for s, c in top_errors])
                reason = f"大量错误响应({error_count}次,{error_summary})"

                return self._add_threat(ip, reason, self.threat_score, entry)
            else:
                if ip in self._threats:
                    self._threats[ip].hit_count += 1
                    self._threats[ip].last_seen = now

        return None

    def clear(self):
        """清除记录"""
        super().clear()
        self._error_records.clear()
        self._flagged_ips.clear()

    def get_ip_error_count(self, ip: str, window_seconds: int = None) -> int:
        """获取IP在时间窗口内的错误数"""
        if ip not in self._error_records:
            return 0

        if window_seconds is None:
            window_seconds = self.window_seconds

        now = _utc_now()
        cutoff = now - timedelta(seconds=window_seconds)

        return len([t for t, _ in self._error_records[ip] if t > cutoff])
