"""分析引擎 - 整合收集、分析、存储"""
import os
import sys
from typing import Dict, List, Optional, Any

import yaml

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors import NginxCollector, WAFCollector, FreeWAFCollector, SSHCollector
from analyzers import FrequencyAnalyzer, PatternAnalyzer, StatusCodeAnalyzer, ThreatInfo
from storage import Database, Exporter
from utils.logger import setup_logger, get_logger
from utils.ip_utils import normalize_ip, WhitelistManager


class Engine:
    """分析引擎"""

    def __init__(self, config_path: str = 'config.yaml'):
        self.config = self._load_config(config_path)
        self._setup_logger()
        self.logger = get_logger()

        # 初始化组件
        self._init_collectors()
        self._init_analyzers()
        self._init_storage()
        self._init_whitelist()

    def _load_config(self, config_path: str) -> Dict:
        """加载配置文件"""
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        return {}

    def _setup_logger(self):
        """配置日志"""
        log_config = self.config.get('logging', {})
        setup_logger(
            log_file=log_config.get('file', './logs/ipcollect.log'),
            level=log_config.get('level', 'INFO'),
            backup_count=log_config.get('backup_count', 7)
        )

    def _init_collectors(self):
        """初始化收集器"""
        self.collectors = []
        state_file = self.config.get('state_file', './data/state.json')

        sources = self.config.get('log_sources', {})

        # Nginx
        nginx_config = sources.get('nginx', {})
        if nginx_config.get('enabled', True):
            self.collectors.append(NginxCollector(
                paths=nginx_config.get('paths'),
                exclude=nginx_config.get('exclude'),
                state_file=state_file
            ))

        # WAF (付费版)
        waf_config = sources.get('waf', {})
        if waf_config.get('enabled', True):
            self.collectors.append(WAFCollector(
                paths=waf_config.get('paths'),
                exclude=waf_config.get('exclude'),
                state_file=state_file
            ))

        # Free WAF (免费版Nginx防火墙)
        free_waf_config = sources.get('free_waf', {})
        if free_waf_config.get('enabled', True):
            self.collectors.append(FreeWAFCollector(
                paths=free_waf_config.get('paths'),
                exclude=free_waf_config.get('exclude'),
                state_file=state_file
            ))

        # SSH
        ssh_config = sources.get('ssh', {})
        if ssh_config.get('enabled', True):
            self.collectors.append(SSHCollector(
                paths=ssh_config.get('paths'),
                exclude=ssh_config.get('exclude'),
                state_file=state_file
            ))

    def _init_analyzers(self):
        """初始化分析器"""
        self.analyzers = [
            FrequencyAnalyzer(self.config),
            PatternAnalyzer(self.config),
            StatusCodeAnalyzer(self.config)
        ]

    def _init_storage(self):
        """初始化存储"""
        db_config = self.config.get('database', {})
        self.database = Database(
            db_path=db_config.get('path', './data/ipcollect.db'),
            retention_days=db_config.get('retention_days', 30),
            threat_retention_days=db_config.get('threat_retention_days', 0)
        )

        output_config = self.config.get('output', {})
        self.exporter = Exporter(
            output_file=output_config.get('file', '/ip.txt'),
            format=output_config.get('format', 'detailed'),
            deduplicate=output_config.get('deduplicate', True)
        )

    def _init_whitelist(self):
        """初始化白名单"""
        # 从配置获取白名单列表
        config_whitelist = self.config.get('whitelist', [])

        # 从配置获取白名单文件路径
        whitelist_file = self.config.get('whitelist_file', '')

        # 创建白名单管理器
        self.whitelist_manager = WhitelistManager(
            config_whitelist=config_whitelist,
            whitelist_file=whitelist_file
        )

        if self.whitelist_manager.count > 0:
            self.logger.info(f"已加载 {self.whitelist_manager.count} 条白名单规则")

    def scan(self, incremental: bool = True) -> Dict[str, Any]:
        """
        执行一次扫描

        Args:
            incremental: 是否增量扫描

        Returns:
            扫描结果统计
        """
        self.logger.info("=" * 50)
        self.logger.info(f"开始{'增量' if incremental else '全量'}扫描")

        stats = {
            'entries_processed': 0,
            'threats_found': 0,
            'threats_exported': 0,
            'sources': {}
        }

        # 收集所有威胁
        all_threats: Dict[str, ThreatInfo] = {}

        # 遍历所有收集器
        for collector in self.collectors:
            source_name = collector.source_name
            source_stats = {'entries': 0, 'threats': 0}

            self.logger.info(f"[{source_name}] 开始收集日志")

            for entry in collector.collect(incremental=incremental):
                # 白名单过滤
                ip = normalize_ip(entry.ip)
                if not ip or self.whitelist_manager.is_whitelisted(ip):
                    continue

                source_stats['entries'] += 1

                # 遍历所有分析器
                for analyzer in self.analyzers:
                    threat = analyzer.analyze(entry)
                    if threat:
                        if ip in all_threats:
                            all_threats[ip].merge(threat)
                        else:
                            all_threats[ip] = threat
                        source_stats['threats'] += 1

            stats['sources'][source_name] = source_stats
            stats['entries_processed'] += source_stats['entries']

        self.logger.info(f"处理了 {stats['entries_processed']} 条日志记录")

        # 保存威胁到数据库
        level_thresholds = self.config.get('threat_levels', {})
        for ip, threat in all_threats.items():
            self.database.upsert_threat(threat, level_thresholds)

        stats['threats_found'] = len(all_threats)
        self.logger.info(f"发现 {len(all_threats)} 个威胁IP")

        # 导出到文件
        unexported = self.database.get_all_threats(unexported_only=True)
        if unexported:
            exported_count = self.exporter.export(unexported, append=True)
            stats['threats_exported'] = exported_count

            # 标记已导出
            exported_ips = [t['ip'] for t in unexported]
            self.database.mark_exported(exported_ips)

        # 清理旧数据（备份到ip.txt同目录）
        output_dir = os.path.dirname(os.path.abspath(self.exporter.output_file))
        self.database.cleanup_old_data(output_dir=output_dir)

        # 清除分析器状态
        for analyzer in self.analyzers:
            analyzer.clear()

        self.logger.info(f"扫描完成，导出 {stats['threats_exported']} 个威胁IP")
        self.logger.info("=" * 50)

        return stats

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        db_stats = self.database.get_stats()
        db_stats['exported_file'] = self.exporter.get_exported_count()
        return db_stats

    def export_all(self, min_level: str = 'LOW') -> int:
        """导出所有威胁IP（覆盖模式）"""
        threats = self.database.get_all_threats(min_level=min_level)
        count = self.exporter.export(threats, append=False)

        # 标记已导出
        ips = [t['ip'] for t in threats]
        self.database.mark_exported(ips)

        return count
