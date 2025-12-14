#!/usr/bin/env python3
"""
IP威胁收集分析服务
用于收集和分析Nginx、WAF、SSH日志，识别威胁IP

作者: sinma
网站: https://www.carefreecode.com/
QQ: 42033223
版本: 1.0.0
"""
import os
import sys
import argparse

__version__ = '1.0.0'
__author__ = 'sinma'
__website__ = 'https://www.carefreecode.com/'

# 确保项目根目录在路径中
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_DIR)
os.chdir(ROOT_DIR)

from core.engine import Engine
from core.scheduler import Scheduler, SimpleScheduler
from core.watcher import RealtimeEngine
from utils.logger import get_logger


def start_web_if_enabled(config: dict, database_path: str, logger):
    """如果配置启用了 Web 界面，则启动"""
    web_config = config.get('web', {})

    if not web_config.get('enabled', False):
        return None

    try:
        from web.app import start_web_server

        host = web_config.get('host', '0.0.0.0')
        port = web_config.get('port', 5000)
        password = web_config.get('password', '')

        thread = start_web_server(
            host=host,
            port=port,
            database=database_path,
            password=password
        )

        logger.info(f"Web 管理界面已启动: http://{host}:{port}")
        if not password:
            logger.warning("Web 界面未设置密码，建议在 config.yaml 中设置 web.password")

        return thread

    except ImportError as e:
        logger.warning(f"Web 界面启动失败，缺少依赖: {e}")
        logger.warning("请安装 Flask: pip3 install flask")
        return None
    except Exception as e:
        logger.error(f"Web 界面启动失败: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description='IP威胁收集分析服务',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
示例:
  python main.py                    # 使用配置文件中的模式运行
  python main.py --once             # 执行一次扫描后退出
  python main.py --mode scheduled   # 定时扫描模式
  python main.py --mode realtime    # 实时监控模式
  python main.py --export           # 导出所有威胁IP到文件
  python main.py --stats            # 显示统计信息
  python main.py --no-web           # 禁用Web界面

作者: {__author__}
网站: {__website__}
        '''
    )

    parser.add_argument(
        '-V', '--version',
        action='version',
        version=f'%(prog)s {__version__} by {__author__} ({__website__})'
    )

    parser.add_argument(
        '-c', '--config',
        default='config.yaml',
        help='配置文件路径 (默认: config.yaml)'
    )

    parser.add_argument(
        '-m', '--mode',
        choices=['scheduled', 'realtime', 'both'],
        help='运行模式 (覆盖配置文件设置)'
    )

    parser.add_argument(
        '--once',
        action='store_true',
        help='只执行一次扫描后退出'
    )

    parser.add_argument(
        '--full',
        action='store_true',
        help='全量扫描 (不使用增量)'
    )

    parser.add_argument(
        '--export',
        action='store_true',
        help='导出所有威胁IP到文件'
    )

    parser.add_argument(
        '--min-level',
        choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        default='LOW',
        help='导出的最小威胁等级 (默认: LOW)'
    )

    parser.add_argument(
        '--stats',
        action='store_true',
        help='显示统计信息'
    )

    parser.add_argument(
        '--no-web',
        action='store_true',
        help='禁用Web管理界面'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='详细输出'
    )

    args = parser.parse_args()

    # 初始化引擎
    try:
        engine = Engine(config_path=args.config)
    except Exception as e:
        print(f"初始化失败: {e}")
        sys.exit(1)

    logger = get_logger()

    # 显示统计信息
    if args.stats:
        stats = engine.get_stats()
        print("\n=== IP威胁收集分析服务统计 ===\n")
        print(f"威胁IP总数: {stats['threats']['total']}")
        print(f"  - CRITICAL: {stats['threats']['critical']}")
        print(f"  - HIGH: {stats['threats']['high']}")
        print(f"  - MEDIUM: {stats['threats']['medium']}")
        print(f"  - LOW: {stats['threats']['low']}")
        print(f"  - 未导出: {stats['threats']['unexported']}")
        print(f"\n输出文件中: {stats['exported_file']} 个IP")
        print(f"访问日志记录: {stats['logs']['total']} 条")
        return

    # 导出所有
    if args.export:
        count = engine.export_all(min_level=args.min_level)
        print(f"已导出 {count} 个威胁IP (等级 >= {args.min_level})")
        return

    # 单次扫描
    if args.once:
        logger.info("执行单次扫描")
        stats = engine.scan(incremental=not args.full)
        print(f"\n扫描完成:")
        print(f"  - 处理日志: {stats['entries_processed']} 条")
        print(f"  - 发现威胁: {stats['threats_found']} 个IP")
        print(f"  - 已导出: {stats['threats_exported']} 个IP")
        return

    # 确定运行模式
    mode = args.mode or engine.config.get('mode', 'scheduled')
    interval = engine.config.get('scan_interval', 300)

    logger.info(f"IP威胁收集分析服务启动")
    logger.info(f"运行模式: {mode}")

    # 启动 Web 界面（如果启用）
    web_thread = None
    if not args.no_web:
        db_config = engine.config.get('database', {})
        database_path = db_config.get('path', './data/ipcollect.db')
        web_thread = start_web_if_enabled(engine.config, database_path, logger)

    if mode == 'scheduled':
        # 定时扫描模式
        scheduler = Scheduler(interval_seconds=interval)
        scheduler.start(lambda: engine.scan(incremental=True))

    elif mode == 'realtime':
        # 实时监控模式
        realtime = RealtimeEngine(engine)
        realtime.start()

    elif mode == 'both':
        # 两种模式同时运行
        import threading

        # 启动定时扫描线程
        scheduler = Scheduler(interval_seconds=interval)
        scheduled_thread = threading.Thread(
            target=scheduler.start,
            args=(lambda: engine.scan(incremental=True),),
            daemon=True
        )
        scheduled_thread.start()

        # 主线程运行实时监控
        realtime = RealtimeEngine(engine)
        try:
            realtime.start()
        finally:
            scheduler.stop()


if __name__ == '__main__':
    main()
