"""威胁IP导出器"""
import os
import json
from datetime import datetime
from typing import List, Dict, Optional

from utils.logger import get_logger


class Exporter:
    """威胁IP导出到文件"""

    def __init__(
        self,
        output_file: str = '/ip.txt',
        format: str = 'detailed',
        deduplicate: bool = True
    ):
        self.output_file = output_file
        self.format = format  # simple, detailed
        self.deduplicate = deduplicate
        self.logger = get_logger()

    def export(self, threats: List[Dict], append: bool = False) -> int:
        """
        导出威胁IP到文件

        Args:
            threats: 威胁IP列表
            append: 是否追加模式

        Returns:
            导出的IP数量
        """
        if not threats:
            return 0

        # 确保目录存在
        output_dir = os.path.dirname(self.output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        # 去重处理
        existing_ips = set()
        if self.deduplicate and os.path.exists(self.output_file):
            existing_ips = self._read_existing_ips()

        # 过滤已存在的IP
        new_threats = [
            t for t in threats
            if t.get('ip') not in existing_ips
        ]

        if not new_threats and self.deduplicate:
            self.logger.info("没有新的威胁IP需要导出")
            return 0

        # 写入文件
        mode = 'a' if append else 'w'
        try:
            with open(self.output_file, mode, encoding='utf-8') as f:
                # 如果是新文件或覆盖模式，写入头部
                if mode == 'w' and self.format == 'detailed':
                    f.write(f"# IP威胁记录 - 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("# 格式: IP | 等级 | 原因 | 命中次数 | 首次发现 | 最后活动\n")
                    f.write("#" + "=" * 80 + "\n")

                for threat in (new_threats if self.deduplicate else threats):
                    line = self._format_threat(threat)
                    f.write(line + '\n')

            count = len(new_threats) if self.deduplicate else len(threats)
            self.logger.info(f"导出 {count} 个威胁IP到 {self.output_file}")
            return count

        except IOError as e:
            self.logger.error(f"导出失败: {e}")
            return 0

    def _format_threat(self, threat: Dict) -> str:
        """格式化单个威胁记录"""
        ip = threat.get('ip', '')

        if self.format == 'simple':
            return ip

        # detailed格式
        level = threat.get('threat_level', 'UNKNOWN')

        reasons = threat.get('reasons', [])
        if isinstance(reasons, str):
            try:
                reasons = json.loads(reasons)
            except json.JSONDecodeError:
                reasons = [reasons]
        reasons_str = ','.join(reasons) if reasons else '-'

        hit_count = threat.get('hit_count', 0)
        first_seen = threat.get('first_seen', '-')
        last_seen = threat.get('last_seen', '-')

        # 格式化时间
        if isinstance(first_seen, str) and 'T' in first_seen:
            first_seen = first_seen.replace('T', ' ')[:19]
        if isinstance(last_seen, str) and 'T' in last_seen:
            last_seen = last_seen.replace('T', ' ')[:19]

        return f"{ip} | {level} | {reasons_str} | {hit_count} | {first_seen} | {last_seen}"

    def _read_existing_ips(self) -> set:
        """读取文件中已存在的IP"""
        ips = set()
        try:
            with open(self.output_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # 提取IP（第一个字段）
                    ip = line.split('|')[0].strip().split()[0]
                    if ip:
                        ips.add(ip)
        except IOError:
            pass
        return ips

    def export_simple_list(self, ips: List[str]) -> int:
        """导出简单IP列表"""
        if not ips:
            return 0

        # 确保目录存在
        output_dir = os.path.dirname(self.output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        # 去重
        if self.deduplicate and os.path.exists(self.output_file):
            existing = self._read_existing_ips()
            ips = [ip for ip in ips if ip not in existing]

        if not ips:
            return 0

        try:
            with open(self.output_file, 'a', encoding='utf-8') as f:
                for ip in ips:
                    f.write(ip + '\n')

            self.logger.info(f"导出 {len(ips)} 个IP到 {self.output_file}")
            return len(ips)

        except IOError as e:
            self.logger.error(f"导出失败: {e}")
            return 0

    def get_exported_count(self) -> int:
        """获取已导出的IP数量"""
        if not os.path.exists(self.output_file):
            return 0
        return len(self._read_existing_ips())
