#!/usr/bin/env python3
"""
IP威胁收集分析服务 - Web管理界面
"""
import os
import sys
import json
import sqlite3
import threading
from datetime import datetime, timedelta
from functools import wraps

# 添加项目根目录
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from flask import Flask, render_template, jsonify, request, Response

app = Flask(__name__)

# 全局配置（由 start_web_server 设置）
_config = {
    'database': '',
    'password': ''
}


def init_app(database: str, password: str = ''):
    """初始化应用配置"""
    _config['database'] = database
    _config['password'] = password


def get_db():
    """获取数据库连接"""
    conn = sqlite3.connect(_config['database'])
    conn.row_factory = sqlite3.Row
    return conn


def check_auth(password):
    """验证密码"""
    if not _config['password']:
        return True
    return password == _config['password']


def requires_auth(f):
    """认证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if _config['password']:
            auth = request.authorization
            if not auth or not check_auth(auth.password):
                return Response(
                    '需要认证', 401,
                    {'WWW-Authenticate': 'Basic realm="IPCollect"'}
                )
        return f(*args, **kwargs)
    return decorated


@app.route('/')
@requires_auth
def index():
    """首页"""
    return render_template('index.html')


@app.route('/api/stats')
@requires_auth
def api_stats():
    """统计数据"""
    conn = get_db()
    cursor = conn.cursor()

    # 威胁等级统计
    cursor.execute('''
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN threat_level = 'LOW' THEN 1 ELSE 0 END) as low,
            SUM(CASE WHEN threat_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN threat_level = 'HIGH' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN threat_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical
        FROM threat_ips
    ''')
    row = cursor.fetchone()
    stats = dict(row) if row else {}

    # 今日新增
    today = datetime.now().strftime('%Y-%m-%d')
    cursor.execute(
        "SELECT COUNT(*) as count FROM threat_ips WHERE date(first_seen) = ?",
        (today,)
    )
    stats['today'] = cursor.fetchone()['count']

    # 最近7天趋势
    trends = []
    for i in range(6, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        cursor.execute(
            "SELECT COUNT(*) as count FROM threat_ips WHERE date(first_seen) = ?",
            (date,)
        )
        trends.append({
            'date': date,
            'count': cursor.fetchone()['count']
        })
    stats['trends'] = trends

    conn.close()
    return jsonify(stats)


@app.route('/api/threats')
@requires_auth
def api_threats():
    """威胁IP列表"""
    conn = get_db()
    cursor = conn.cursor()

    # 分页参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    offset = (page - 1) * per_page

    # 筛选参数
    level = request.args.get('level', '')
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'score')
    order = request.args.get('order', 'desc')

    # 构建查询
    where_clauses = []
    params = []

    if level:
        where_clauses.append("threat_level = ?")
        params.append(level)

    if search:
        where_clauses.append("(ip LIKE ? OR reasons LIKE ?)")
        params.extend([f'%{search}%', f'%{search}%'])

    where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

    # 排序
    valid_sorts = ['score', 'hit_count', 'first_seen', 'last_seen', 'ip']
    if sort not in valid_sorts:
        sort = 'score'
    order = 'DESC' if order.lower() == 'desc' else 'ASC'

    # 总数
    cursor.execute(f"SELECT COUNT(*) as count FROM threat_ips WHERE {where_sql}", params)
    total = cursor.fetchone()['count']

    # 数据
    cursor.execute(f'''
        SELECT * FROM threat_ips
        WHERE {where_sql}
        ORDER BY {sort} {order}
        LIMIT ? OFFSET ?
    ''', params + [per_page, offset])

    threats = []
    for row in cursor.fetchall():
        threat = dict(row)
        # 解析 reasons JSON
        if threat.get('reasons'):
            try:
                threat['reasons'] = json.loads(threat['reasons'])
            except:
                threat['reasons'] = [threat['reasons']]
        threats.append(threat)

    conn.close()

    return jsonify({
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page,
        'data': threats
    })


@app.route('/api/threat/<ip>')
@requires_auth
def api_threat_detail(ip):
    """单个IP详情"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM threat_ips WHERE ip = ?", (ip,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({'error': 'IP not found'}), 404

    threat = dict(row)
    if threat.get('reasons'):
        try:
            threat['reasons'] = json.loads(threat['reasons'])
        except:
            threat['reasons'] = [threat['reasons']]

    conn.close()
    return jsonify(threat)


@app.route('/api/export')
@requires_auth
def api_export():
    """导出IP列表"""
    conn = get_db()
    cursor = conn.cursor()

    level = request.args.get('level', 'LOW')
    format = request.args.get('format', 'txt')

    level_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    min_order = level_order.get(level, 1)
    valid_levels = [l for l, o in level_order.items() if o >= min_order]

    placeholders = ','.join(['?' for _ in valid_levels])
    cursor.execute(
        f"SELECT * FROM threat_ips WHERE threat_level IN ({placeholders}) ORDER BY score DESC",
        valid_levels
    )

    rows = cursor.fetchall()
    conn.close()

    if format == 'json':
        data = []
        for row in rows:
            d = dict(row)
            if d.get('reasons'):
                try:
                    d['reasons'] = json.loads(d['reasons'])
                except:
                    pass
            data.append(d)
        return jsonify(data)
    else:
        # 纯文本格式
        lines = [row['ip'] for row in rows]
        return Response('\n'.join(lines), mimetype='text/plain')


@app.route('/api/delete/<ip>', methods=['DELETE'])
@requires_auth
def api_delete(ip):
    """删除IP记录"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM threat_ips WHERE ip = ?", (ip,))
    conn.commit()
    deleted = cursor.rowcount
    conn.close()
    return jsonify({'deleted': deleted})


def start_web_server(host: str, port: int, database: str, password: str = ''):
    """
    启动 Web 服务器（在单独线程中运行）

    Args:
        host: 监听地址
        port: 端口
        database: 数据库路径
        password: 访问密码
    """
    init_app(database, password)

    # 禁用 Flask 默认日志
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.WARNING)

    def run():
        app.run(host=host, port=port, threaded=True, use_reloader=False)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    return thread


# 独立运行
if __name__ == '__main__':
    import argparse
    import yaml

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default='config.yaml')
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    # 加载配置
    config = {}
    config_path = os.path.join(ROOT_DIR, args.config)
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f) or {}

    web_config = config.get('web', {})
    host = args.host or web_config.get('host', '0.0.0.0')
    port = args.port or web_config.get('port', 5000)
    password = web_config.get('password', '')

    db_config = config.get('database', {})
    database = db_config.get('path', os.path.join(ROOT_DIR, 'data', 'ipcollect.db'))

    init_app(database, password)

    print(f"启动 Web 服务: http://{host}:{port}")
    print(f"数据库: {database}")
    if password:
        print("已启用密码认证")
    else:
        print("警告: 未设置密码，建议在 config.yaml 中设置 web.password")

    app.run(host=host, port=port, debug=args.debug)
