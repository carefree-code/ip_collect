"""宝塔免费Nginx防火墙日志收集器"""
from typing import Optional, List

from .base import BaseCollector
from utils.log_parser import LogEntry, parse_free_waf_log


class FreeWAFCollector(BaseCollector):
    """宝塔免费Nginx防火墙日志收集器"""

    def __init__(
        self,
        paths: List[str] = None,
        exclude: List[str] = None,
        state_file: str = './data/state.json'
    ):
        if paths is None:
            paths = [
                '/www/wwwlogs/free_waf_log/*.log',
                '/www/wwwlogs/free_waf_log/**/*.log'
            ]
        if exclude is None:
            exclude = ['*.gz']

        super().__init__(paths, exclude, state_file)

    @property
    def source_name(self) -> str:
        return 'free_waf'

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """解析免费WAF日志行"""
        return parse_free_waf_log(line)
