"""恶意模式分析器"""
import os
import re
from collections import defaultdict
from typing import Dict, List, Optional, Set

import yaml

from .base import BaseAnalyzer, ThreatInfo
from utils.log_parser import LogEntry


class PatternAnalyzer(BaseAnalyzer):
    """恶意模式分析器 - 检测敏感路径、恶意UA、SQL注入等"""

    def __init__(self, config: Dict = None, rules_file: str = None):
        super().__init__(config)

        # 加载规则
        if rules_file is None:
            rules_file = os.path.join(
                os.path.dirname(__file__), 'rules.yaml'
            )
        self.rules = self._load_rules(rules_file)

        # 阈值
        thresholds = self.config.get('thresholds', {}).get('path_scan', {})
        self.max_sensitive_hits = thresholds.get('max_sensitive_hits', 5)

        # 分数
        scores = self.config.get('threat_scores', {})
        self.sensitive_path_score = scores.get('sensitive_path', 4)
        self.malicious_ua_score = scores.get('malicious_ua', 4)
        self.sql_injection_score = scores.get('sql_injection', 5)
        self.waf_block_score = scores.get('waf_block', 5)
        self.ssh_bruteforce_score = scores.get('ssh_bruteforce', 5)

        # 编译正则
        self._compile_patterns()

        # IP敏感路径计数
        self._sensitive_hits: Dict[str, int] = defaultdict(int)
        # 已标记的IP
        self._flagged_ips: Dict[str, Set[str]] = defaultdict(set)  # {ip: {reason1, reason2}}

    def _load_rules(self, rules_file: str) -> Dict:
        """加载规则文件"""
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                self.logger.error(f"加载规则文件失败: {e}")
        return {}

    def _compile_patterns(self):
        """编译正则表达式"""
        # 敏感路径（转换为正则）
        sensitive_paths = self.rules.get('sensitive_paths', [])
        self.sensitive_path_patterns = []
        for p in sensitive_paths:
            try:
                self.sensitive_path_patterns.append(
                    re.compile(re.escape(p), re.IGNORECASE)
                )
            except re.error:
                pass

        # 恶意UA
        ua_patterns = self.rules.get('malicious_ua_patterns', [])
        self.malicious_ua_patterns = []
        for p in ua_patterns:
            try:
                self.malicious_ua_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                pass

        # SQL注入
        sqli_patterns = self.rules.get('sql_injection_patterns', [])
        self.sqli_patterns = []
        for p in sqli_patterns:
            try:
                self.sqli_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                pass

        # XSS
        xss_patterns = self.rules.get('xss_patterns', [])
        self.xss_patterns = []
        for p in xss_patterns:
            try:
                self.xss_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                pass

        # 路径遍历
        traversal_patterns = self.rules.get('path_traversal_patterns', [])
        self.traversal_patterns = []
        for p in traversal_patterns:
            try:
                self.traversal_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                pass

        # 命令注入
        cmd_patterns = self.rules.get('command_injection_patterns', [])
        self.cmd_patterns = []
        for p in cmd_patterns:
            try:
                self.cmd_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                pass

        # 文件包含 (LFI/RFI)
        lfi_patterns = self.rules.get('file_inclusion_patterns', [])
        self.lfi_patterns = []
        for p in lfi_patterns:
            try:
                self.lfi_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                pass

        # SSRF
        ssrf_patterns = self.rules.get('ssrf_patterns', [])
        self.ssrf_patterns = []
        for p in ssrf_patterns:
            try:
                self.ssrf_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                pass

        # XXE
        xxe_patterns = self.rules.get('xxe_patterns', [])
        self.xxe_patterns = []
        for p in xxe_patterns:
            try:
                self.xxe_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                pass

        # SSTI (模板注入)
        ssti_patterns = self.rules.get('ssti_patterns', [])
        self.ssti_patterns = []
        for p in ssti_patterns:
            try:
                self.ssti_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                pass

        # Java反序列化
        java_patterns = self.rules.get('java_deserialization_patterns', [])
        self.java_deser_patterns = []
        for p in java_patterns:
            try:
                self.java_deser_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                pass

    @property
    def name(self) -> str:
        return 'pattern'

    def analyze(self, entry: LogEntry) -> Optional[ThreatInfo]:
        """分析恶意模式"""
        if not entry.ip:
            return None

        ip = entry.ip
        threat = None

        # WAF拦截记录标记为威胁（付费版WAF准确度更高）
        if entry.source == 'waf':
            reason = 'WAF拦截'
            if entry.extra.get('attack_type'):
                reason += f"({entry.extra['attack_type']})"
            threat = self._add_threat_if_new(ip, reason, self.waf_block_score, entry)

        # 免费WAF拦截（准确度较低，可能误拦截，给予较低分数）
        elif entry.source == 'free_waf':
            # 免费WAF分数减半，避免误封
            reduced_score = max(1, self.waf_block_score // 2)
            reason = '免费WAF拦截'
            rule_type = entry.extra.get('rule_type', '')
            if rule_type:
                reason += f"({rule_type})"
            threat = self._add_threat_if_new(ip, reason, reduced_score, entry)

        # SSH暴力破解
        if entry.source == 'ssh' and entry.extra.get('failed'):
            reason = 'SSH登录失败'
            # SSH分析器会单独处理阈值，这里只记录
            threat = self._add_threat_if_new(ip, reason, self.ssh_bruteforce_score, entry)

        # 检查请求路径
        if entry.path:
            path = entry.path.lower()

            # 敏感路径
            for pattern in self.sensitive_path_patterns:
                if pattern.search(path):
                    self._sensitive_hits[ip] += 1
                    if self._sensitive_hits[ip] >= self.max_sensitive_hits:
                        reason = '敏感路径扫描'
                        t = self._add_threat_if_new(ip, reason, self.sensitive_path_score, entry)
                        if t:
                            threat = t
                    break

            # SQL注入
            for pattern in self.sqli_patterns:
                if pattern.search(path) or pattern.search(entry.raw):
                    reason = 'SQL注入特征'
                    t = self._add_threat_if_new(ip, reason, self.sql_injection_score, entry)
                    if t:
                        threat = t
                    break

            # XSS
            for pattern in self.xss_patterns:
                if pattern.search(path) or pattern.search(entry.raw):
                    reason = 'XSS攻击特征'
                    t = self._add_threat_if_new(ip, reason, self.sql_injection_score, entry)
                    if t:
                        threat = t
                    break

            # 路径遍历
            for pattern in self.traversal_patterns:
                if pattern.search(path):
                    reason = '路径遍历攻击'
                    t = self._add_threat_if_new(ip, reason, self.sql_injection_score, entry)
                    if t:
                        threat = t
                    break

            # 命令注入
            for pattern in self.cmd_patterns:
                if pattern.search(path) or pattern.search(entry.raw):
                    reason = '命令注入特征'
                    t = self._add_threat_if_new(ip, reason, self.sql_injection_score, entry)
                    if t:
                        threat = t
                    break

            # 文件包含 (LFI/RFI)
            for pattern in self.lfi_patterns:
                if pattern.search(path) or pattern.search(entry.raw):
                    reason = '文件包含攻击'
                    t = self._add_threat_if_new(ip, reason, self.sql_injection_score, entry)
                    if t:
                        threat = t
                    break

            # SSRF
            for pattern in self.ssrf_patterns:
                if pattern.search(path) or pattern.search(entry.raw):
                    reason = 'SSRF攻击特征'
                    t = self._add_threat_if_new(ip, reason, self.sql_injection_score, entry)
                    if t:
                        threat = t
                    break

            # XXE
            for pattern in self.xxe_patterns:
                if pattern.search(entry.raw):
                    reason = 'XXE攻击特征'
                    t = self._add_threat_if_new(ip, reason, self.sql_injection_score, entry)
                    if t:
                        threat = t
                    break

            # SSTI (模板注入)
            for pattern in self.ssti_patterns:
                if pattern.search(path) or pattern.search(entry.raw):
                    reason = '模板注入特征'
                    t = self._add_threat_if_new(ip, reason, self.sql_injection_score, entry)
                    if t:
                        threat = t
                    break

            # Java反序列化
            for pattern in self.java_deser_patterns:
                if pattern.search(entry.raw):
                    reason = 'Java反序列化攻击'
                    t = self._add_threat_if_new(ip, reason, self.sql_injection_score, entry)
                    if t:
                        threat = t
                    break

        # 检查User-Agent
        if entry.user_agent:
            for pattern in self.malicious_ua_patterns:
                if pattern.search(entry.user_agent):
                    reason = f'恶意UA({pattern.pattern})'
                    t = self._add_threat_if_new(ip, reason, self.malicious_ua_score, entry)
                    if t:
                        threat = t
                    break

        return threat

    def _add_threat_if_new(
        self, ip: str, reason: str, score: int, entry: LogEntry
    ) -> Optional[ThreatInfo]:
        """添加威胁（如果是新原因）"""
        # 检查是否已为该原因标记过
        if reason in self._flagged_ips[ip]:
            # 只更新计数和时间
            if ip in self._threats:
                self._threats[ip].hit_count += 1
                if entry.timestamp:
                    self._threats[ip].last_seen = entry.timestamp
            return None

        self._flagged_ips[ip].add(reason)
        return self._add_threat(ip, reason, score, entry)

    def clear(self):
        """清除记录"""
        super().clear()
        self._sensitive_hits.clear()
        self._flagged_ips.clear()
