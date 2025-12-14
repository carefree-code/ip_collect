"""日志解析工具"""
import re
from datetime import datetime, timezone
from typing import Dict, Optional, Any
from dataclasses import dataclass, field, asdict

# Nginx combined格式正则
# 格式: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
NGINX_COMBINED_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+'                           # IP
    r'-\s+'                                        # -
    r'(?P<user>\S+)\s+'                           # 用户
    r'\[(?P<time>[^\]]+)\]\s+'                    # 时间
    r'"(?P<request>[^"]*)"\s+'                    # 请求
    r'(?P<status>\d+)\s+'                         # 状态码
    r'(?P<bytes>\d+|-)\s+'                        # 字节数
    r'"(?P<referer>[^"]*)"\s+'                    # Referer
    r'"(?P<ua>[^"]*)"'                            # User-Agent
)

# Nginx时间格式
NGINX_TIME_FORMAT = '%d/%b/%Y:%H:%M:%S %z'
NGINX_TIME_FORMAT_NO_TZ = '%d/%b/%Y:%H:%M:%S'


@dataclass
class LogEntry:
    """统一日志记录格式"""
    timestamp: datetime
    ip: str
    source: str  # nginx, waf, ssh
    method: str = ''
    path: str = ''
    status: int = 0
    user_agent: str = ''
    raw: str = ''
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """转换为字典"""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat() if self.timestamp else None
        return result


def _utc_now() -> datetime:
    """获取当前 UTC 时间（无时区标记）"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def parse_timestamp(time_str: str, format: str = None) -> Optional[datetime]:
    """解析时间字符串"""
    if not time_str:
        return None

    formats = [
        format,
        NGINX_TIME_FORMAT,
        NGINX_TIME_FORMAT_NO_TZ,
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%SZ',
        '%b %d %H:%M:%S',
    ] if format else [
        NGINX_TIME_FORMAT,
        NGINX_TIME_FORMAT_NO_TZ,
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%SZ',
        '%b %d %H:%M:%S',
    ]

    for fmt in formats:
        if not fmt:
            continue
        try:
            dt = datetime.strptime(time_str.strip(), fmt)
            # 如果没有年份，添加当前年份（使用UTC时间的年份）
            if dt.year == 1900:
                dt = dt.replace(year=_utc_now().year)
            # 统一转换为 UTC 时间
            dt = to_utc(dt)
            return dt
        except (ValueError, TypeError):
            continue

    return None


def to_utc(dt: datetime) -> datetime:
    """
    将 datetime 统一转换为 UTC 时间（无时区标记）

    - 如果有时区信息：转换为 UTC 后去掉时区标记
    - 如果无时区信息：假定为本地时间，转换为 UTC

    这样所有时间都是 UTC，可以安全比较
    """
    if dt is None:
        return None

    if dt.tzinfo is not None:
        # 有时区信息，转换为 UTC
        utc_dt = dt.astimezone(timezone.utc)
        return utc_dt.replace(tzinfo=None)
    else:
        # 无时区信息，假定为本地时间，转换为 UTC
        # 先添加本地时区，再转 UTC
        local_dt = dt.astimezone()  # 添加本地时区
        utc_dt = local_dt.astimezone(timezone.utc)
        return utc_dt.replace(tzinfo=None)


def parse_nginx_log(line: str) -> Optional[LogEntry]:
    """解析Nginx日志行"""
    if not line or not line.strip():
        return None

    line = line.strip()
    match = NGINX_COMBINED_PATTERN.match(line)

    if not match:
        return None

    data = match.groupdict()

    # 解析请求
    request = data.get('request', '')
    method, path, protocol = '', '', ''
    if request:
        parts = request.split(' ', 2)
        if len(parts) >= 2:
            method = parts[0]
            path = parts[1]
        if len(parts) >= 3:
            protocol = parts[2]

    # 解析时间
    time_str = data.get('time', '')
    # 处理带时区的情况，如 "09/Dec/2025:10:00:00 +0800"
    timestamp = parse_timestamp(time_str)
    if not timestamp:
        timestamp = _utc_now()

    # 状态码
    try:
        status = int(data.get('status', 0))
    except (ValueError, TypeError):
        status = 0

    return LogEntry(
        timestamp=timestamp,
        ip=data.get('ip', ''),
        source='nginx',
        method=method,
        path=path,
        status=status,
        user_agent=data.get('ua', ''),
        raw=line,
        extra={
            'referer': data.get('referer', ''),
            'bytes': data.get('bytes', '0'),
            'user': data.get('user', '-'),
            'protocol': protocol
        }
    )


def parse_waf_log(line: str) -> Optional[LogEntry]:
    """解析WAF日志（JSON格式）"""
    import json

    if not line or not line.strip():
        return None

    try:
        data = json.loads(line.strip())
    except json.JSONDecodeError:
        return None

    # WAF日志格式可能因版本不同而异，这里处理常见格式
    ip = data.get('ip') or data.get('client_ip') or data.get('remote_addr', '')

    time_str = data.get('time') or data.get('timestamp') or data.get('@timestamp', '')
    timestamp = parse_timestamp(time_str) if time_str else _utc_now()

    return LogEntry(
        timestamp=timestamp,
        ip=ip,
        source='waf',
        method=data.get('method', ''),
        path=data.get('uri') or data.get('url') or data.get('path', ''),
        status=data.get('status', 0),
        user_agent=data.get('user_agent') or data.get('ua', ''),
        raw=line,
        extra={
            'rule_id': data.get('rule_id', ''),
            'rule_name': data.get('rule_name', ''),
            'action': data.get('action', 'block'),
            'attack_type': data.get('attack_type', '')
        }
    )


def parse_free_waf_log(line: str) -> Optional[LogEntry]:
    """解析宝塔免费Nginx防火墙日志

    格式为JSON数组：
    ["时间","IP","方法","路径",null,"规则类型","规则匹配详情","原始请求"]
    例如：
    ["2025-11-27 03:25:24","4.189.145.250","GET","/shell.php",null,"url","规则详情","原始请求"]
    """
    import json

    if not line or not line.strip():
        return None

    line = line.strip()

    # 跳过注释和空行
    if line.startswith('#'):
        return None

    # 尝试JSON解析
    try:
        data = json.loads(line)

        # 宝塔免费WAF日志是JSON数组格式
        # ["时间","IP","方法","路径",null,"规则类型","规则匹配详情","原始请求"]
        if isinstance(data, list) and len(data) >= 4:
            time_str = data[0] if len(data) > 0 else ''
            ip = data[1] if len(data) > 1 else ''
            method = data[2] if len(data) > 2 else 'GET'
            path = data[3] if len(data) > 3 else ''
            # data[4] 通常是 null
            rule_type = data[5] if len(data) > 5 else ''  # url, args, cookie等
            rule_detail = data[6] if len(data) > 6 else ''  # 规则匹配详情
            raw_request = data[7] if len(data) > 7 else ''  # 原始请求

            # 解析时间
            timestamp = parse_timestamp(time_str) if time_str else _utc_now()

            # 从原始请求中提取域名
            domain = ''
            if raw_request and 'host:' in raw_request.lower():
                import re as regex
                host_match = regex.search(r'host:\s*([^\s\n]+)', raw_request, regex.IGNORECASE)
                if host_match:
                    domain = host_match.group(1)

            return LogEntry(
                timestamp=timestamp,
                ip=ip,
                source='free_waf',
                method=method,
                path=path,
                status=403,  # WAF拦截返回403
                user_agent='',
                raw=line,
                extra={
                    'rule_type': str(rule_type),
                    'rule_detail': str(rule_detail),
                    'raw_request': str(raw_request)[:500],  # 限制长度
                    'action': 'block',
                    'domain': domain
                }
            )

        # 如果是JSON对象格式（兼容其他可能的格式）
        elif isinstance(data, dict):
            ip = (data.get('ip') or data.get('client_ip') or
                  data.get('remote_addr') or '')

            time_str = (data.get('time') or data.get('timestamp') or '')
            timestamp = parse_timestamp(time_str) if time_str else _utc_now()

            path = (data.get('uri') or data.get('url') or data.get('path') or '')

            return LogEntry(
                timestamp=timestamp,
                ip=ip,
                source='free_waf',
                method=data.get('method', 'GET'),
                path=path,
                status=403,
                user_agent=data.get('user_agent') or data.get('ua') or '',
                raw=line,
                extra={
                    'rule_type': data.get('rule_type') or data.get('type') or '',
                    'action': 'block',
                    'domain': data.get('domain') or data.get('host') or ''
                }
            )

    except json.JSONDecodeError:
        pass

    # 尝试提取行中的IP地址（最后的fallback）
    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
    if ip_match:
        return LogEntry(
            timestamp=_utc_now(),
            ip=ip_match.group(1),
            source='free_waf',
            method='',
            path='',
            status=403,
            user_agent='',
            raw=line,
            extra={
                'action': 'block'
            }
        )

    return None


def parse_ssh_log(line: str) -> Optional[LogEntry]:
    """解析SSH日志"""
    if not line or not line.strip():
        return None

    line = line.strip()

    # 常见SSH失败日志格式:
    # Dec  9 10:00:00 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
    # Dec  9 10:00:00 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
    # Dec  9 10:00:00 server sshd[12345]: Invalid user admin from 192.168.1.100 port 22

    failed_pattern = re.compile(
        r'^(?P<time>\w+\s+\d+\s+[\d:]+)\s+'
        r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
        r'(?P<action>Failed password|Invalid user|Accepted password|Accepted publickey)'
        r'.*?from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    match = failed_pattern.search(line)
    if not match:
        return None

    data = match.groupdict()

    timestamp = parse_timestamp(data.get('time', ''))
    if not timestamp:
        timestamp = _utc_now()

    action = data.get('action', '')
    is_failed = action.startswith('Failed') or action.startswith('Invalid')

    return LogEntry(
        timestamp=timestamp,
        ip=data.get('ip', ''),
        source='ssh',
        method='SSH',
        path='/ssh',
        status=401 if is_failed else 200,
        user_agent='',
        raw=line,
        extra={
            'action': action,
            'failed': is_failed,
            'host': data.get('host', '')
        }
    )
