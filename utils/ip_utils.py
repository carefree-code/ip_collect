"""IP地址工具函数"""
import os
import re
import ipaddress
from typing import List, Optional, Set

# IPv4正则
IPV4_PATTERN = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'
)

# IPv6正则（简化版）
IPV6_PATTERN = re.compile(
    r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$|^::1$|^::$'
)


def is_valid_ip(ip: str) -> bool:
    """检查是否为有效IP地址"""
    if not ip:
        return False

    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def normalize_ip(ip: str) -> Optional[str]:
    """
    标准化IP地址
    - 去除端口号
    - 处理IPv6格式
    """
    if not ip:
        return None

    ip = ip.strip()

    # 处理带端口的IPv4 (如 192.168.1.1:8080)
    if ':' in ip and ip.count(':') == 1:
        ip = ip.split(':')[0]

    # 处理带方括号的IPv6 (如 [::1])
    if ip.startswith('[') and ']' in ip:
        ip = ip[1:ip.index(']')]

    # 处理X-Forwarded-For多IP情况，取第一个
    if ',' in ip:
        ip = ip.split(',')[0].strip()

    # 验证
    if is_valid_ip(ip):
        return ip

    return None


def is_whitelisted(ip: str, whitelist: List[str]) -> bool:
    """检查IP是否在白名单中（支持单IP、CIDR、IP范围）"""
    if not ip or not whitelist:
        return False

    normalized = normalize_ip(ip)
    if not normalized:
        return False

    # 直接匹配
    if normalized in whitelist:
        return True

    # CIDR和IP范围匹配
    try:
        ip_obj = ipaddress.ip_address(normalized)
        for item in whitelist:
            try:
                # CIDR匹配
                if '/' in item:
                    network = ipaddress.ip_network(item, strict=False)
                    if ip_obj in network:
                        return True
                # IP范围匹配 (如 192.168.1.0-192.168.1.255)
                elif '-' in item:
                    start_ip_str, end_ip_str = item.split('-', 1)
                    start_ip = ipaddress.ip_address(start_ip_str.strip())
                    end_ip = ipaddress.ip_address(end_ip_str.strip())
                    # 检查IP是否在范围内
                    if start_ip <= ip_obj <= end_ip:
                        return True
            except ValueError:
                continue
    except ValueError:
        pass

    return False


def is_private_ip(ip: str) -> bool:
    """检查是否为私有IP"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def extract_ip_from_line(line: str) -> Optional[str]:
    """从日志行中提取IP地址"""
    # 尝试匹配IPv4
    ipv4_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
    if ipv4_match:
        ip = ipv4_match.group(1)
        if is_valid_ip(ip):
            return ip

    # 尝试匹配IPv6
    ipv6_match = re.search(r'([0-9a-fA-F:]+:+[0-9a-fA-F:]+)', line)
    if ipv6_match:
        ip = ipv6_match.group(1)
        if is_valid_ip(ip):
            return ip

    return None


def load_whitelist_file(file_path: str) -> List[str]:
    """
    从文件加载白名单

    支持的格式:
    - 单个IP: 192.168.1.1
    - CIDR格式: 192.168.1.0/24, 10.0.0.0/8
    - IPv6: ::1, fe80::/10
    - 注释行: # 这是注释
    - 空行会被忽略

    Args:
        file_path: 白名单文件路径

    Returns:
        白名单列表
    """
    whitelist = []

    if not file_path or not os.path.exists(file_path):
        return whitelist

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()

                # 跳过空行和注释
                if not line or line.startswith('#'):
                    continue

                # 去除行内注释
                if '#' in line:
                    line = line.split('#')[0].strip()

                if not line:
                    continue

                # 验证IP或CIDR格式
                if is_valid_ip_or_cidr(line):
                    whitelist.append(line)

    except Exception as e:
        # 文件读取失败，返回空列表
        pass

    return whitelist


def is_valid_ip_or_cidr(value: str) -> bool:
    """
    检查是否为有效的IP地址、CIDR网段或IP范围

    Args:
        value: IP地址、CIDR格式或IP范围字符串（如 192.168.1.0-192.168.1.255）

    Returns:
        是否有效
    """
    if not value:
        return False

    try:
        # 尝试作为单个IP
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass

    try:
        # 尝试作为CIDR网段
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass

    # 尝试作为IP范围 (如 192.168.1.0-192.168.1.255)
    if '-' in value:
        try:
            start_ip_str, end_ip_str = value.split('-', 1)
            start_ip = ipaddress.ip_address(start_ip_str.strip())
            end_ip = ipaddress.ip_address(end_ip_str.strip())
            # 验证范围是否合理（起始IP <= 结束IP）
            if start_ip <= end_ip:
                return True
        except ValueError:
            pass

    return False


class WhitelistManager:
    """
    白名单管理器

    支持:
    - 从配置文件加载白名单列表
    - 从外部文件导入白名单
    - IP段(CIDR)匹配
    - IP范围匹配（如 192.168.1.0-192.168.1.255）
    - 自动去重
    """

    def __init__(self, config_whitelist: List[str] = None, whitelist_file: str = None):
        """
        初始化白名单管理器

        Args:
            config_whitelist: 配置文件中的白名单列表
            whitelist_file: 外部白名单文件路径
        """
        self._ips: Set[str] = set()  # 单个IP
        self._networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []  # CIDR网段
        self._ranges: List[tuple] = []  # IP范围 [(start_ip, end_ip), ...]

        # 加载配置中的白名单
        if config_whitelist:
            self._load_list(config_whitelist)

        # 加载外部文件
        if whitelist_file:
            file_list = load_whitelist_file(whitelist_file)
            self._load_list(file_list)

    def _load_list(self, items: List[str]):
        """加载白名单列表（支持单IP、CIDR、IP范围）"""
        for item in items:
            if not item:
                continue

            item = item.strip()

            if '/' in item:
                # CIDR格式
                try:
                    network = ipaddress.ip_network(item, strict=False)
                    if network not in self._networks:
                        self._networks.append(network)
                except ValueError:
                    continue
            elif '-' in item:
                # IP范围格式 (如 192.168.1.0-192.168.1.255)
                try:
                    start_ip_str, end_ip_str = item.split('-', 1)
                    start_ip = ipaddress.ip_address(start_ip_str.strip())
                    end_ip = ipaddress.ip_address(end_ip_str.strip())
                    if start_ip <= end_ip:
                        range_tuple = (start_ip, end_ip)
                        if range_tuple not in self._ranges:
                            self._ranges.append(range_tuple)
                except ValueError:
                    continue
            else:
                # 单个IP
                try:
                    ipaddress.ip_address(item)
                    self._ips.add(item)
                except ValueError:
                    continue

    def is_whitelisted(self, ip: str) -> bool:
        """
        检查IP是否在白名单中

        Args:
            ip: 要检查的IP地址

        Returns:
            是否在白名单中
        """
        if not ip:
            return False

        normalized = normalize_ip(ip)
        if not normalized:
            return False

        # 直接匹配
        if normalized in self._ips:
            return True

        # CIDR和IP范围匹配
        try:
            ip_obj = ipaddress.ip_address(normalized)

            # CIDR匹配
            for network in self._networks:
                if ip_obj in network:
                    return True

            # IP范围匹配
            for start_ip, end_ip in self._ranges:
                if start_ip <= ip_obj <= end_ip:
                    return True
        except ValueError:
            pass

        return False

    def add(self, item: str) -> bool:
        """
        添加IP或网段到白名单

        Args:
            item: IP地址或CIDR格式

        Returns:
            是否添加成功
        """
        if not item:
            return False

        item = item.strip()

        if '/' in item:
            try:
                network = ipaddress.ip_network(item, strict=False)
                if network not in self._networks:
                    self._networks.append(network)
                return True
            except ValueError:
                return False
        else:
            try:
                ipaddress.ip_address(item)
                self._ips.add(item)
                return True
            except ValueError:
                return False

    def reload_file(self, file_path: str):
        """重新加载外部文件"""
        file_list = load_whitelist_file(file_path)
        self._load_list(file_list)

    @property
    def count(self) -> int:
        """白名单条目数量"""
        return len(self._ips) + len(self._networks)

    def to_list(self) -> List[str]:
        """导出为列表"""
        result = list(self._ips)
        result.extend(str(n) for n in self._networks)
        return result
