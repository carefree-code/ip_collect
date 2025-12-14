"""高频访问分析器"""
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


class FrequencyAnalyzer(BaseAnalyzer):
    """高频访问分析器 - 检测短时间内大量请求"""

    def __init__(self, config: Dict = None):
        super().__init__(config)

        thresholds = self.config.get('thresholds', {}).get('frequency', {})
        self.window_seconds = thresholds.get('window_seconds', 60)
        self.max_requests = thresholds.get('max_requests', 100)

        scores = self.config.get('threat_scores', {})
        self.threat_score = scores.get('frequency_violation', 3)

        # IP访问时间记录 {ip: [timestamp1, timestamp2, ...]}
        self._access_times: Dict[str, List[datetime]] = defaultdict(list)
        # 已标记的IP（避免重复报告）
        self._flagged_ips: set = set()

    @property
    def name(self) -> str:
        return 'frequency'

    def analyze(self, entry: LogEntry) -> Optional[ThreatInfo]:
        """分析访问频率"""
        if not entry.ip or not entry.timestamp:
            return None

        ip = entry.ip
        now = _to_utc(entry.timestamp)

        # 添加访问记录
        self._access_times[ip].append(now)

        # 清理过期记录
        cutoff = now - timedelta(seconds=self.window_seconds)
        self._access_times[ip] = [
            t for t in self._access_times[ip] if t > cutoff
        ]

        # 检查频率
        request_count = len(self._access_times[ip])

        if request_count > self.max_requests:
            # 只在首次超过阈值时报告
            if ip not in self._flagged_ips:
                self._flagged_ips.add(ip)
                reason = f"高频访问({request_count}次/{self.window_seconds}秒)"
                return self._add_threat(ip, reason, self.threat_score, entry)
            else:
                # 已标记的IP只更新最后访问时间
                if ip in self._threats:
                    self._threats[ip].hit_count += 1
                    self._threats[ip].last_seen = now

        return None

    def clear(self):
        """清除记录"""
        super().clear()
        self._access_times.clear()
        self._flagged_ips.clear()

    def get_ip_request_count(self, ip: str, window_seconds: int = None) -> int:
        """获取IP在时间窗口内的请求数"""
        if ip not in self._access_times:
            return 0

        if window_seconds is None:
            window_seconds = self.window_seconds

        now = _utc_now()
        cutoff = now - timedelta(seconds=window_seconds)

        return len([t for t in self._access_times[ip] if t > cutoff])
