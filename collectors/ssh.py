"""SSH日志收集器"""
from typing import Optional, List

from .base import BaseCollector
from utils.log_parser import LogEntry, parse_ssh_log


class SSHCollector(BaseCollector):
    """SSH登录日志收集器"""

    def __init__(
        self,
        paths: List[str] = None,
        exclude: List[str] = None,
        state_file: str = './data/state.json'
    ):
        if paths is None:
            paths = [
                '/var/log/secure',
                '/var/log/auth.log'
            ]
        if exclude is None:
            exclude = ['*.gz']

        super().__init__(paths, exclude, state_file)

    @property
    def source_name(self) -> str:
        return 'ssh'

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """解析SSH日志行"""
        return parse_ssh_log(line)
