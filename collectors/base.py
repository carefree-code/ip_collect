"""日志收集器基类"""
import os
import glob
import json
from abc import ABC, abstractmethod
from typing import List, Iterator, Dict, Optional, Any
from pathlib import Path

from utils.log_parser import LogEntry
from utils.logger import get_logger


class BaseCollector(ABC):
    """日志收集器基类"""

    def __init__(
        self,
        paths: List[str],
        exclude: List[str] = None,
        state_file: str = './data/state.json'
    ):
        self.paths = paths
        self.exclude = exclude or []
        self.state_file = state_file
        self.logger = get_logger()
        self._state: Dict[str, Any] = {}
        self._load_state()

    @property
    @abstractmethod
    def source_name(self) -> str:
        """返回日志源名称"""
        pass

    @abstractmethod
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """解析单行日志"""
        pass

    def _load_state(self):
        """加载状态文件（记录已读取的位置）"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    all_state = json.load(f)
                    self._state = all_state.get(self.source_name, {})
            except (json.JSONDecodeError, IOError) as e:
                self.logger.warning(f"加载状态文件失败: {e}")
                self._state = {}

    def _save_state(self):
        """保存状态文件"""
        state_dir = os.path.dirname(self.state_file)
        if state_dir and not os.path.exists(state_dir):
            os.makedirs(state_dir, exist_ok=True)

        all_state = {}
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    all_state = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass

        all_state[self.source_name] = self._state

        with open(self.state_file, 'w', encoding='utf-8') as f:
            json.dump(all_state, f, indent=2)

    def _get_file_position(self, filepath: str) -> Dict:
        """获取文件读取位置"""
        return self._state.get(filepath, {'offset': 0, 'inode': 0})

    def _set_file_position(self, filepath: str, offset: int, inode: int = 0):
        """设置文件读取位置"""
        self._state[filepath] = {'offset': offset, 'inode': inode}

    def _should_exclude(self, filepath: str) -> bool:
        """检查文件是否应该排除"""
        filename = os.path.basename(filepath)
        for pattern in self.exclude:
            if glob.fnmatch.fnmatch(filename, pattern):
                return True
        return False

    def get_log_files(self) -> List[str]:
        """获取所有日志文件路径"""
        files = []
        for pattern in self.paths:
            matched = glob.glob(pattern, recursive=True)
            for f in matched:
                if os.path.isfile(f) and not self._should_exclude(f):
                    files.append(f)
        return sorted(set(files))

    def collect(self, incremental: bool = True) -> Iterator[LogEntry]:
        """
        收集日志

        Args:
            incremental: 是否增量读取（仅读取新增内容）

        Yields:
            LogEntry对象
        """
        log_files = self.get_log_files()
        self.logger.info(f"[{self.source_name}] 发现 {len(log_files)} 个日志文件")

        for filepath in log_files:
            try:
                yield from self._read_file(filepath, incremental)
            except Exception as e:
                self.logger.error(f"[{self.source_name}] 读取文件失败 {filepath}: {e}")

        # 保存状态
        self._save_state()

    def _read_file(self, filepath: str, incremental: bool) -> Iterator[LogEntry]:
        """读取单个文件"""
        if not os.path.exists(filepath):
            return

        try:
            stat = os.stat(filepath)
            current_inode = stat.st_ino
            current_size = stat.st_size
        except OSError:
            return

        position = self._get_file_position(filepath)
        start_offset = position.get('offset', 0) if incremental else 0
        saved_inode = position.get('inode', 0)

        # 如果inode变化（日志轮转），从头开始读
        if saved_inode != 0 and saved_inode != current_inode:
            self.logger.info(f"[{self.source_name}] 检测到文件轮转: {filepath}")
            start_offset = 0

        # 如果文件变小（被截断），从头开始读
        if start_offset > current_size:
            self.logger.info(f"[{self.source_name}] 检测到文件截断: {filepath}")
            start_offset = 0

        if start_offset == current_size:
            # 没有新内容
            return

        self.logger.debug(f"[{self.source_name}] 读取 {filepath} 从位置 {start_offset}")

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(start_offset)
                line_count = 0
                entry_count = 0

                for line in f:
                    line_count += 1
                    entry = self.parse_line(line)
                    if entry:
                        entry_count += 1
                        yield entry

                # 更新位置
                end_offset = f.tell()
                self._set_file_position(filepath, end_offset, current_inode)

                if entry_count > 0:
                    self.logger.info(
                        f"[{self.source_name}] {filepath}: "
                        f"读取 {line_count} 行, 解析 {entry_count} 条记录"
                    )

        except IOError as e:
            self.logger.error(f"[{self.source_name}] 读取文件失败 {filepath}: {e}")

    def tail(self, filepath: str) -> Iterator[LogEntry]:
        """
        实时跟踪文件（类似tail -f）

        Args:
            filepath: 文件路径

        Yields:
            LogEntry对象
        """
        import time

        if not os.path.exists(filepath):
            self.logger.warning(f"文件不存在: {filepath}")
            return

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            # 移到文件末尾
            f.seek(0, 2)

            while True:
                line = f.readline()
                if line:
                    entry = self.parse_line(line)
                    if entry:
                        yield entry
                else:
                    time.sleep(0.1)
