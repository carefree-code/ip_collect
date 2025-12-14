"""日志记录模块"""
import os
import logging
from logging.handlers import RotatingFileHandler
from typing import Optional

_logger: Optional[logging.Logger] = None


def setup_logger(
    log_file: str = './logs/ipcollect.log',
    level: str = 'INFO',
    backup_count: int = 7
) -> logging.Logger:
    """配置并返回日志记录器"""
    global _logger

    # 确保日志目录存在
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    # 创建logger
    logger = logging.getLogger('ipcollect')
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # 清除已有的handlers
    logger.handlers.clear()

    # 文件handler（轮转）
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)

    # 控制台handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # 格式
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(name)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    _logger = logger
    return logger


def get_logger() -> logging.Logger:
    """获取日志记录器"""
    global _logger
    if _logger is None:
        _logger = setup_logger()
    return _logger
