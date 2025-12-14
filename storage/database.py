"""SQLite数据库操作"""
import os
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from contextlib import contextmanager


def _utc_now() -> datetime:
    """获取当前 UTC 时间（无时区标记）"""
    return datetime.now(timezone.utc).replace(tzinfo=None)

from analyzers.base import ThreatInfo
from utils.logger import get_logger


class Database:
    """SQLite数据库管理"""

    def __init__(self, db_path: str = './data/ipcollect.db', retention_days: int = 30, threat_retention_days: int = 0):
        self.db_path = db_path
        self.retention_days = retention_days
        self.threat_retention_days = threat_retention_days  # 0表示永久保留
        self.logger = get_logger()
        self._init_db()

    def _init_db(self):
        """初始化数据库"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

        with self._get_conn() as conn:
            cursor = conn.cursor()

            # 威胁IP表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE NOT NULL,
                    score INTEGER DEFAULT 0,
                    threat_level TEXT DEFAULT 'LOW',
                    reasons TEXT,
                    hit_count INTEGER DEFAULT 1,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    exported INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # 访问日志表（可选，用于详细分析）
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS access_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    ip TEXT,
                    source TEXT,
                    method TEXT,
                    path TEXT,
                    status INTEGER,
                    user_agent TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # 索引
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_ip ON threat_ips(ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_level ON threat_ips(threat_level)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_ip ON access_logs(ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON access_logs(timestamp)')

            conn.commit()

    @contextmanager
    def _get_conn(self):
        """获取数据库连接"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def upsert_threat(self, threat: ThreatInfo, level_thresholds: Dict[str, int] = None):
        """插入或更新威胁IP"""
        if level_thresholds is None:
            level_thresholds = {'LOW': 2, 'MEDIUM': 4, 'HIGH': 6, 'CRITICAL': 8}

        threat_level = threat.get_level(level_thresholds)
        reasons_json = json.dumps(threat.reasons, ensure_ascii=False)

        with self._get_conn() as conn:
            cursor = conn.cursor()

            # 检查是否存在
            cursor.execute('SELECT id, score, reasons, hit_count FROM threat_ips WHERE ip = ?', (threat.ip,))
            existing = cursor.fetchone()

            if existing:
                # 更新
                old_reasons = json.loads(existing['reasons']) if existing['reasons'] else []
                merged_reasons = list(set(old_reasons + threat.reasons))
                new_score = existing['score'] + threat.score
                new_hit_count = existing['hit_count'] + threat.hit_count

                # 重新计算等级
                temp_threat = ThreatInfo(ip=threat.ip, score=new_score)
                new_level = temp_threat.get_level(level_thresholds)

                cursor.execute('''
                    UPDATE threat_ips SET
                        score = ?,
                        threat_level = ?,
                        reasons = ?,
                        hit_count = ?,
                        last_seen = ?,
                        updated_at = CURRENT_TIMESTAMP,
                        exported = 0
                    WHERE ip = ?
                ''', (
                    new_score,
                    new_level,
                    json.dumps(merged_reasons, ensure_ascii=False),
                    new_hit_count,
                    threat.last_seen.isoformat() if threat.last_seen else _utc_now().isoformat(),
                    threat.ip
                ))
            else:
                # 插入
                cursor.execute('''
                    INSERT INTO threat_ips (ip, score, threat_level, reasons, hit_count, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    threat.ip,
                    threat.score,
                    threat_level,
                    reasons_json,
                    threat.hit_count,
                    threat.first_seen.isoformat() if threat.first_seen else _utc_now().isoformat(),
                    threat.last_seen.isoformat() if threat.last_seen else _utc_now().isoformat()
                ))

            conn.commit()

    def get_threat(self, ip: str) -> Optional[Dict]:
        """获取单个威胁IP信息"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM threat_ips WHERE ip = ?', (ip,))
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def get_all_threats(
        self,
        min_level: str = None,
        unexported_only: bool = False,
        limit: int = None
    ) -> List[Dict]:
        """获取所有威胁IP"""
        level_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}

        with self._get_conn() as conn:
            cursor = conn.cursor()

            query = 'SELECT * FROM threat_ips WHERE 1=1'
            params = []

            if min_level and min_level in level_order:
                min_order = level_order[min_level]
                valid_levels = [l for l, o in level_order.items() if o >= min_order]
                placeholders = ','.join(['?' for _ in valid_levels])
                query += f' AND threat_level IN ({placeholders})'
                params.extend(valid_levels)

            if unexported_only:
                query += ' AND exported = 0'

            query += ' ORDER BY score DESC, last_seen DESC'

            if limit:
                query += f' LIMIT {int(limit)}'

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def mark_exported(self, ips: List[str]):
        """标记IP已导出

        使用分批处理避免 SQLite 'too many SQL variables' 错误
        SQLite 默认限制约 999 个变量
        """
        if not ips:
            return

        # 分批处理，每批最多 500 个
        batch_size = 500
        with self._get_conn() as conn:
            cursor = conn.cursor()
            for i in range(0, len(ips), batch_size):
                batch = ips[i:i + batch_size]
                placeholders = ','.join(['?' for _ in batch])
                cursor.execute(
                    f'UPDATE threat_ips SET exported = 1 WHERE ip IN ({placeholders})',
                    batch
                )
            conn.commit()

    def cleanup_old_data(self, output_dir: str = None):
        """清理过期数据

        Args:
            output_dir: 备份文件输出目录（用于在清理威胁IP前导出备份）
        """
        cutoff = _utc_now() - timedelta(days=self.retention_days)
        cutoff_str = cutoff.isoformat()

        with self._get_conn() as conn:
            cursor = conn.cursor()

            # 清理访问日志
            cursor.execute('DELETE FROM access_logs WHERE created_at < ?', (cutoff_str,))
            logs_deleted = cursor.rowcount

            # 清理过期威胁IP记录（如果设置了保留天数）
            threats_deleted = 0
            if self.threat_retention_days > 0:
                threat_cutoff = _utc_now() - timedelta(days=self.threat_retention_days)
                threat_cutoff_str = threat_cutoff.isoformat()

                self.logger.debug(f"威胁IP清理: 保留天数={self.threat_retention_days}, 截止时间={threat_cutoff_str}")

                # 检查是否有即将被删除的记录
                cursor.execute('SELECT COUNT(*) FROM threat_ips WHERE last_seen < ?', (threat_cutoff_str,))
                expired_count = cursor.fetchone()[0]

                # 如果有过期记录要删除，先备份所有威胁IP
                if expired_count > 0 and output_dir:
                    cursor.execute(
                        'SELECT ip, score, threat_level, reasons, hit_count, first_seen, last_seen FROM threat_ips ORDER BY score DESC'
                    )
                    all_threats = cursor.fetchall()
                    self._backup_all_threats(all_threats, output_dir)

                # 执行删除
                cursor.execute('DELETE FROM threat_ips WHERE last_seen < ?', (threat_cutoff_str,))
                threats_deleted = cursor.rowcount

            conn.commit()

            if logs_deleted > 0:
                self.logger.info(f"清理了 {logs_deleted} 条过期访问日志")
            if threats_deleted > 0:
                self.logger.info(f"清理了 {threats_deleted} 条过期威胁IP记录")

    def _backup_all_threats(self, threats: list, output_dir: str):
        """在清理前备份所有威胁IP到文件

        Args:
            threats: 威胁IP记录列表
            output_dir: 输出目录
        """
        if not threats:
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(output_dir, f'ip_{timestamp}.txt')

        try:
            os.makedirs(output_dir, exist_ok=True)

            with open(backup_file, 'w', encoding='utf-8') as f:
                for row in threats:
                    f.write(f"{row[0]}\n")

            self.logger.info(f"已备份所有威胁IP ({len(threats)} 条) 到 {backup_file}")
        except Exception as e:
            self.logger.error(f"备份威胁IP失败: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._get_conn() as conn:
            cursor = conn.cursor()

            # 威胁IP统计
            cursor.execute('''
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN threat_level = 'LOW' THEN 1 ELSE 0 END) as low,
                    SUM(CASE WHEN threat_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN threat_level = 'HIGH' THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN threat_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN exported = 0 THEN 1 ELSE 0 END) as unexported
                FROM threat_ips
            ''')
            threat_stats = dict(cursor.fetchone())

            # 访问日志统计
            cursor.execute('SELECT COUNT(*) as total FROM access_logs')
            log_stats = dict(cursor.fetchone())

            return {
                'threats': threat_stats,
                'logs': log_stats
            }
