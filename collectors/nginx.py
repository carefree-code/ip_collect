"""Nginx日志收集器"""
from typing import Optional, List

from .base import BaseCollector
from utils.log_parser import LogEntry, parse_nginx_log


class NginxCollector(BaseCollector):
    """Nginx访问日志收集器"""

    def __init__(
        self,
        paths: List[str] = None,
        exclude: List[str] = None,
        state_file: str = './data/state.json'
    ):
        if paths is None:
            paths = ['/www/wwwlogs/*.log']
        if exclude is None:
            exclude = ['*.gz']

        super().__init__(paths, exclude, state_file)

    @property
    def source_name(self) -> str:
        return 'nginx'

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """解析Nginx日志行"""
        return parse_nginx_log(line)
