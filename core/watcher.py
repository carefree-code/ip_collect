"""实时文件监控"""
import os
import time
import signal
import threading
from typing import List, Dict, Callable, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

from utils.logger import get_logger


class LogFileHandler(FileSystemEventHandler):
    """日志文件变化处理器"""

    def __init__(self, callback: Callable[[str], None], patterns: List[str] = None):
        super().__init__()
        self.callback = callback
        self.patterns = patterns or ['*.log']
        self.logger = get_logger()

        # 文件读取位置记录
        self._file_positions: Dict[str, int] = {}
        self._lock = threading.Lock()

    def on_modified(self, event):
        """文件修改事件"""
        if event.is_directory:
            return

        filepath = event.src_path

        # 检查是否匹配模式
        if not self._match_patterns(filepath):
            return

        # 读取新增内容
        self._read_new_content(filepath)

    def _match_patterns(self, filepath: str) -> bool:
        """检查文件是否匹配模式"""
        import fnmatch
        filename = os.path.basename(filepath)
        for pattern in self.patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
        return False

    def _read_new_content(self, filepath: str):
        """读取文件新增内容"""
        with self._lock:
            try:
                current_size = os.path.getsize(filepath)
                last_pos = self._file_positions.get(filepath, 0)

                # 文件被截断，从头开始
                if current_size < last_pos:
                    last_pos = 0

                if current_size == last_pos:
                    return

                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_pos)
                    new_content = f.read()
                    self._file_positions[filepath] = f.tell()

                # 按行处理
                for line in new_content.splitlines():
                    if line.strip():
                        self.callback(line)

            except Exception as e:
                self.logger.error(f"读取文件失败 {filepath}: {e}")


class Watcher:
    """实时监控器"""

    def __init__(self, paths: List[str], callback: Callable[[str], None]):
        """
        Args:
            paths: 要监控的目录列表
            callback: 收到新日志行时的回调函数
        """
        self.paths = paths
        self.callback = callback
        self.logger = get_logger()
        self._observer: Optional[Observer] = None
        self._running = False

    def start(self, blocking: bool = True):
        """
        启动监控

        Args:
            blocking: 是否阻塞运行
        """
        self._running = True

        # 设置信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self._observer = Observer()
        handler = LogFileHandler(self.callback)

        # 监控所有配置的路径
        watched_paths = set()
        for path_pattern in self.paths:
            # 如果是通配符模式，取目录部分
            if '*' in path_pattern:
                watch_dir = os.path.dirname(path_pattern)
                if not watch_dir:
                    watch_dir = '.'
            else:
                watch_dir = path_pattern if os.path.isdir(path_pattern) else os.path.dirname(path_pattern)

            if watch_dir and os.path.exists(watch_dir) and watch_dir not in watched_paths:
                self._observer.schedule(handler, watch_dir, recursive=False)
                watched_paths.add(watch_dir)
                self.logger.info(f"监控目录: {watch_dir}")

        if not watched_paths:
            self.logger.warning("没有找到可监控的目录")
            return

        self._observer.start()
        self.logger.info(f"实时监控已启动，监控 {len(watched_paths)} 个目录")

        if blocking:
            try:
                while self._running:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            finally:
                self.stop()

    def stop(self):
        """停止监控"""
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        self.logger.info("实时监控已停止")

    def _signal_handler(self, signum, frame):
        """信号处理"""
        self.logger.info(f"收到信号 {signum}")
        self.stop()


class RealtimeEngine:
    """实时分析引擎"""

    def __init__(self, engine):
        """
        Args:
            engine: Engine实例
        """
        from core.engine import Engine
        self.engine = engine
        self.logger = get_logger()
        self._watcher: Optional[Watcher] = None

    def start(self):
        """启动实时监控"""
        # 收集所有日志路径
        paths = []
        for collector in self.engine.collectors:
            paths.extend(collector.paths)

        self.logger.info(f"启动实时监控，监控 {len(paths)} 个路径模式")

        self._watcher = Watcher(paths, self._process_line)
        self._watcher.start(blocking=True)

    def _process_line(self, line: str):
        """处理单行日志"""
        from utils.log_parser import parse_nginx_log, parse_waf_log, parse_free_waf_log, parse_ssh_log
        from utils.ip_utils import normalize_ip

        # 尝试解析
        entry = None
        for parser in [parse_nginx_log, parse_waf_log, parse_free_waf_log, parse_ssh_log]:
            entry = parser(line)
            if entry:
                break

        if not entry:
            return

        # 白名单过滤
        ip = normalize_ip(entry.ip)
        if not ip or self.engine.whitelist_manager.is_whitelisted(ip):
            return

        # 分析
        for analyzer in self.engine.analyzers:
            threat = analyzer.analyze(entry)
            if threat:
                # 保存到数据库
                level_thresholds = self.engine.config.get('threat_levels', {})
                self.engine.database.upsert_threat(threat, level_thresholds)

                # 立即导出
                threat_dict = {
                    'ip': threat.ip,
                    'threat_level': threat.get_level(level_thresholds),
                    'reasons': threat.reasons,
                    'hit_count': threat.hit_count,
                    'first_seen': threat.first_seen.isoformat() if threat.first_seen else None,
                    'last_seen': threat.last_seen.isoformat() if threat.last_seen else None
                }
                self.engine.exporter.export([threat_dict], append=True)
                self.engine.database.mark_exported([threat.ip])

                self.logger.info(f"发现威胁IP: {threat.ip} - {','.join(threat.reasons)}")

    def stop(self):
        """停止"""
        if self._watcher:
            self._watcher.stop()
