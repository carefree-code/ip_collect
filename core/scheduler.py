"""定时调度器"""
import time
import signal
import threading
from typing import Callable, Optional

import schedule

from utils.logger import get_logger


class Scheduler:
    """定时任务调度器"""

    def __init__(self, interval_seconds: int = 300):
        self.interval = interval_seconds
        self.logger = get_logger()
        self._running = False
        self._stop_event = threading.Event()
        self._job = None

    def start(self, task: Callable, run_immediately: bool = True):
        """
        启动定时任务

        Args:
            task: 要执行的任务函数
            run_immediately: 是否立即执行一次
        """
        self._running = True
        self._stop_event.clear()

        # 设置信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self.logger.info(f"定时调度器启动，间隔 {self.interval} 秒")

        # 立即执行一次
        if run_immediately:
            self.logger.info("立即执行首次扫描")
            try:
                task()
            except Exception as e:
                self.logger.error(f"任务执行失败: {e}")

        # 设置定时任务
        self._job = schedule.every(self.interval).seconds.do(self._run_task, task)

        # 运行调度循环
        while self._running and not self._stop_event.is_set():
            schedule.run_pending()
            time.sleep(1)

        self.logger.info("定时调度器已停止")

    def _run_task(self, task: Callable):
        """执行任务（带异常处理）"""
        try:
            task()
        except Exception as e:
            self.logger.error(f"任务执行失败: {e}")

    def stop(self):
        """停止调度器"""
        self.logger.info("正在停止定时调度器...")
        self._running = False
        self._stop_event.set()
        if self._job:
            schedule.cancel_job(self._job)

    def _signal_handler(self, signum, frame):
        """信号处理"""
        self.logger.info(f"收到信号 {signum}，准备停止")
        self.stop()


class SimpleScheduler:
    """简单定时器（不依赖schedule库）"""

    def __init__(self, interval_seconds: int = 300):
        self.interval = interval_seconds
        self.logger = get_logger()
        self._running = False

    def start(self, task: Callable, run_immediately: bool = True):
        """启动定时任务"""
        self._running = True

        # 设置信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self.logger.info(f"简单调度器启动，间隔 {self.interval} 秒")

        # 立即执行
        if run_immediately:
            try:
                task()
            except Exception as e:
                self.logger.error(f"任务执行失败: {e}")

        # 循环执行
        last_run = time.time()
        while self._running:
            current = time.time()
            if current - last_run >= self.interval:
                try:
                    task()
                except Exception as e:
                    self.logger.error(f"任务执行失败: {e}")
                last_run = current
            time.sleep(1)

        self.logger.info("简单调度器已停止")

    def stop(self):
        """停止"""
        self._running = False

    def _signal_handler(self, signum, frame):
        """信号处理"""
        self.logger.info(f"收到信号 {signum}")
        self.stop()
