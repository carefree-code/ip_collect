"""分析器基类"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from utils.log_parser import LogEntry
from utils.logger import get_logger


def _utc_now() -> datetime:
    """获取当前 UTC 时间（无时区标记）"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class ThreatInfo:
    """威胁信息"""
    ip: str
    score: int = 0
    reasons: List[str] = field(default_factory=list)
    hit_count: int = 0
    first_seen: datetime = None
    last_seen: datetime = None
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = _utc_now()
        if self.last_seen is None:
            self.last_seen = _utc_now()

    def add_reason(self, reason: str, score: int = 1):
        """添加威胁原因"""
        if reason not in self.reasons:
            self.reasons.append(reason)
        self.score += score

    def merge(self, other: 'ThreatInfo'):
        """合并威胁信息"""
        self.score += other.score
        for reason in other.reasons:
            if reason not in self.reasons:
                self.reasons.append(reason)
        self.hit_count += other.hit_count
        if other.first_seen and (not self.first_seen or other.first_seen < self.first_seen):
            self.first_seen = other.first_seen
        if other.last_seen and (not self.last_seen or other.last_seen > self.last_seen):
            self.last_seen = other.last_seen
        self.details.update(other.details)

    def get_level(self, thresholds: Dict[str, int]) -> str:
        """根据分数获取威胁等级"""
        if self.score >= thresholds.get('CRITICAL', 8):
            return 'CRITICAL'
        elif self.score >= thresholds.get('HIGH', 6):
            return 'HIGH'
        elif self.score >= thresholds.get('MEDIUM', 4):
            return 'MEDIUM'
        elif self.score >= thresholds.get('LOW', 2):
            return 'LOW'
        return 'NONE'


class BaseAnalyzer(ABC):
    """分析器基类"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = get_logger()
        self._threats: Dict[str, ThreatInfo] = {}

    @property
    @abstractmethod
    def name(self) -> str:
        """分析器名称"""
        pass

    @abstractmethod
    def analyze(self, entry: LogEntry) -> Optional[ThreatInfo]:
        """
        分析单条日志记录

        Args:
            entry: 日志记录

        Returns:
            如果检测到威胁，返回ThreatInfo；否则返回None
        """
        pass

    def get_threats(self) -> Dict[str, ThreatInfo]:
        """获取所有检测到的威胁"""
        return self._threats

    def clear(self):
        """清除威胁记录"""
        self._threats.clear()

    def _add_threat(self, ip: str, reason: str, score: int, entry: LogEntry):
        """添加威胁记录"""
        if ip not in self._threats:
            self._threats[ip] = ThreatInfo(
                ip=ip,
                first_seen=entry.timestamp,
                last_seen=entry.timestamp
            )

        threat = self._threats[ip]
        threat.add_reason(reason, score)
        threat.hit_count += 1
        if entry.timestamp:
            if not threat.first_seen or entry.timestamp < threat.first_seen:
                threat.first_seen = entry.timestamp
            if not threat.last_seen or entry.timestamp > threat.last_seen:
                threat.last_seen = entry.timestamp

        return threat
