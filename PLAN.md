# IP威胁收集分析服务 - 实现计划

> **状态**: ✅ 已完成（v2.0.0）
>
> 此文档为项目初始规划文档，项目已完成开发并持续更新中。
>
> **最新文档请查看**: [README.md](README.md)

## 项目概述

开发一个运行在宝塔服务器上的日志分析服务，收集 Nginx 访问日志、WAF 拦截日志、SSH 登录日志，识别威胁IP并记录到 `/ip.txt`。

## v2.0.0 更新 (2025-12-14)

- ✅ 新增免费WAF日志支持
- ✅ 智能误封防护优化
- ✅ 内置142个搜索引擎爬虫白名单
- ✅ 内置28个AI引擎爬虫白名单
- ✅ 支持IP范围格式
- ✅ 批量处理优化
- ✅ IPv6完整支持

详见：[更新日志](docs/白名单综合更新总结.md)

---

## 一、目录结构

```
ipcollect/
├── config.yaml              # 主配置文件
├── main.py                  # 程序入口
├── requirements.txt         # Python依赖
├── install.sh               # 安装脚本
│
├── collectors/              # 日志收集模块
│   ├── __init__.py
│   ├── base.py              # 收集器基类
│   ├── nginx.py             # Nginx访问日志收集
│   ├── waf.py               # 宝塔WAF日志收集
│   └── ssh.py               # SSH登录日志收集
│
├── analyzers/               # 威胁分析模块
│   ├── __init__.py
│   ├── base.py              # 分析器基类
│   ├── frequency.py         # 高频访问分析
│   ├── pattern.py           # 恶意模式匹配
│   ├── status_code.py       # 异常状态码分析
│   └── rules.yaml           # 恶意规则库（路径、UA等）
│
├── storage/                 # 数据存储模块
│   ├── __init__.py
│   ├── database.py          # SQLite数据库操作
│   └── exporter.py          # 导出威胁IP到文件
│
├── core/                    # 核心模块
│   ├── __init__.py
│   ├── scheduler.py         # 定时任务调度
│   ├── watcher.py           # 实时监控（文件变化）
│   └── engine.py            # 分析引擎（整合收集+分析）
│
├── utils/                   # 工具模块
│   ├── __init__.py
│   ├── ip_utils.py          # IP解析、归属地查询
│   ├── log_parser.py        # 日志解析工具
│   └── logger.py            # 日志记录
│
└── services/                # 服务配置
    ├── ipcollect.service    # Systemd服务文件
    └── cron_example.txt     # Cron定时任务示例
```

---

## 二、配置文件设计 (config.yaml)

```yaml
# 运行模式: scheduled(定时扫描) | realtime(实时监控) | both(两者都开)
mode: scheduled

# 定时扫描间隔（秒）
scan_interval: 300

# 日志源配置
log_sources:
  nginx:
    enabled: true
    paths:
      - /www/wwwlogs/*.log
    # 排除的日志文件
    exclude:
      - "*access_log"

  waf:
    enabled: true
    paths:
      - /www/server/panel/plugin/btwaf/logs/*.log
      - /www/server/panel/vhost/nginx/waf/*.log

  ssh:
    enabled: true
    paths:
      - /var/log/secure
      - /var/log/auth.log

# 威胁检测阈值（可自定义）
thresholds:
  # 高频访问：X秒内超过Y次请求
  frequency:
    window_seconds: 60
    max_requests: 100

  # 异常状态码：X秒内超过Y次4xx/5xx
  error_rate:
    window_seconds: 60
    max_errors: 50

  # 路径扫描：访问敏感路径次数
  path_scan:
    max_sensitive_hits: 5

# 威胁等级权重
threat_levels:
  LOW: 1        # 单一可疑行为
  MEDIUM: 3     # 多个可疑行为
  HIGH: 5       # 明确恶意行为
  CRITICAL: 10  # WAF拦截/暴力破解

# IP白名单（不记录）
whitelist:
  - 127.0.0.1
  - ::1
  # 可添加服务器自身IP、CDN节点等

# 输出配置
output:
  file: /ip.txt
  # 输出格式: simple(仅IP) | detailed(包含详情)
  format: detailed
  # 是否去重
  deduplicate: true

# 数据库配置
database:
  path: /www/server/ipcollect/data.db
  # 日志保留天数
  retention_days: 30

# 日志配置
logging:
  level: INFO
  file: /www/server/ipcollect/ipcollect.log
```

---

## 三、核心模块设计

### 3.1 日志收集器 (collectors/)

**功能**：读取各类日志文件，解析为统一格式

```python
# 统一日志记录格式
LogEntry = {
    "timestamp": datetime,      # 时间
    "ip": str,                  # 来源IP
    "source": str,              # 来源类型: nginx/waf/ssh
    "method": str,              # 请求方法 (HTTP)
    "path": str,                # 请求路径
    "status": int,              # 状态码
    "user_agent": str,          # UA
    "raw": str,                 # 原始日志行
    "extra": dict               # 额外信息
}
```

**日志格式解析**：
- Nginx: 正则解析 combined/自定义格式
- WAF: JSON格式解析
- SSH: 解析 `Failed password`、`Accepted` 等关键字

### 3.2 威胁分析器 (analyzers/)

| 分析器 | 检测内容 | 威胁等级 |
|--------|----------|----------|
| FrequencyAnalyzer | 单IP高频请求 | MEDIUM |
| PatternAnalyzer | 敏感路径扫描、恶意UA | HIGH |
| StatusCodeAnalyzer | 大量4xx/5xx | LOW-MEDIUM |
| WAFAnalyzer | WAF拦截记录 | CRITICAL |
| SSHAnalyzer | 暴力破解尝试 | CRITICAL |

**恶意规则库 (rules.yaml)**：
```yaml
sensitive_paths:
  - .env
  - .git/config
  - wp-login.php
  - /admin
  - /phpmyadmin
  - /actuator
  - /.well-known
  - /config
  - /backup

malicious_ua_patterns:
  - sqlmap
  - nikto
  - nmap
  - masscan
  - zgrab
  - python-requests  # 可选

sql_injection_patterns:
  - "union.*select"
  - "or.*1.*=.*1"
  - "drop.*table"
```

### 3.3 存储模块 (storage/)

**SQLite表结构**：

```sql
-- 访问记录表（用于统计分析）
CREATE TABLE access_logs (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME,
    ip TEXT,
    source TEXT,
    path TEXT,
    status INTEGER,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 威胁IP表
CREATE TABLE threat_ips (
    id INTEGER PRIMARY KEY,
    ip TEXT UNIQUE,
    threat_level TEXT,
    reasons TEXT,          -- JSON数组
    hit_count INTEGER,
    first_seen DATETIME,
    last_seen DATETIME,
    exported INTEGER DEFAULT 0
);

-- 索引
CREATE INDEX idx_logs_ip ON access_logs(ip);
CREATE INDEX idx_logs_timestamp ON access_logs(timestamp);
CREATE INDEX idx_threat_ip ON threat_ips(ip);
```

### 3.4 运行模式 (core/)

**定时扫描模式**：
```
1. 记录上次扫描位置（文件偏移量）
2. 读取增量日志
3. 批量分析
4. 更新威胁IP
5. 导出到 /ip.txt
```

**实时监控模式**：
```
1. 使用 watchdog 监控日志文件变化
2. 实时读取新增内容
3. 流式分析
4. 即时更新威胁IP
```

---

## 四、输出格式

**/ip.txt 文件格式**：

简单模式 (format: simple)：
```
192.168.1.100
10.0.0.50
203.0.113.25
```

详细模式 (format: detailed)：
```
# IP威胁记录 - 更新时间: 2025-12-09 12:00:00
# 格式: IP | 等级 | 原因 | 命中次数 | 首次发现 | 最后活动
192.168.1.100 | CRITICAL | WAF拦截,SQL注入 | 15 | 2025-12-09 10:00:00 | 2025-12-09 11:50:00
10.0.0.50 | HIGH | 路径扫描,高频访问 | 230 | 2025-12-09 09:30:00 | 2025-12-09 11:45:00
203.0.113.25 | MEDIUM | 异常状态码 | 89 | 2025-12-09 11:00:00 | 2025-12-09 11:55:00
```

---

## 五、部署方式

### 5.1 安装脚本 (install.sh)

```bash
#!/bin/bash
# 创建目录
mkdir -p /www/server/ipcollect

# 复制文件
cp -r ./* /www/server/ipcollect/

# 安装依赖
pip3 install -r requirements.txt

# 安装systemd服务
cp services/ipcollect.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable ipcollect
```

### 5.2 Systemd服务

```ini
[Unit]
Description=IP Threat Collector Service
After=network.target

[Service]
Type=simple
WorkingDirectory=/www/server/ipcollect
ExecStart=/usr/bin/python3 main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 5.3 使用方式

```bash
# 启动服务（实时监控模式）
systemctl start ipcollect

# 手动执行一次扫描
python3 main.py --once

# 查看状态
systemctl status ipcollect

# 查看日志
tail -f /www/server/ipcollect/ipcollect.log
```

---

## 六、开发步骤

### 阶段一：基础框架 ✅
1. [x] 创建项目结构和配置文件
2. [x] 实现配置加载模块
3. [x] 实现日志记录工具

### 阶段二：日志收集 ✅
4. [x] 实现 Nginx 日志收集器
5. [x] 实现 WAF 日志收集器
6. [x] 实现 SSH 日志收集器
7. [x] 实现增量读取（记录文件偏移）
8. [x] **v2.0**: 实现免费WAF日志收集器

### 阶段三：威胁分析 ✅
9. [x] 实现高频访问分析器
10. [x] 实现恶意模式匹配分析器
11. [x] 实现状态码分析器
12. [x] 加载恶意规则库
13. [x] **v2.0**: 优化检测规则防止误封

### 阶段四：存储与导出 ✅
14. [x] 实现 SQLite 数据库操作
15. [x] 实现威胁IP导出到文件
16. [x] **v2.0**: 批量处理优化（修复SQL变量限制）

### 阶段五：运行模式 ✅
17. [x] 实现定时扫描调度
18. [x] 实现实时监控（watchdog）
19. [x] 实现分析引擎整合

### 阶段六：部署 ✅
20. [x] 编写安装脚本
21. [x] 编写 Systemd 服务文件
22. [x] 测试与调优

### 阶段七：白名单与文档 ✅ (v2.0)
23. [x] 搜索引擎爬虫白名单（142个IP段）
24. [x] AI引擎爬虫白名单（28个IP段）
25. [x] IP范围格式支持
26. [x] IPv6完整支持
27. [x] 完善文档体系

---

## 七、依赖清单 (requirements.txt)

```
pyyaml>=6.0        # 配置文件解析
watchdog>=3.0      # 文件监控
schedule>=1.2      # 定时任务
```

> 注：尽量使用标准库，减少外部依赖

---

## 八、后续扩展

### 已实现 ✅
- [x] Web管理界面（可视化统计、IP详情、搜索筛选）
- [x] 威胁等级分级（LOW/MEDIUM/HIGH/CRITICAL）
- [x] 白名单管理（支持多种格式）
- [x] 数据保留策略（自动清理过期数据）

### 计划中
- [ ] 自动调用宝塔API封禁IP
- [ ] IP归属地查询
- [ ] 邮件/微信告警
- [ ] 威胁情报联动
- [ ] 定期更新爬虫白名单

---

**项目已完成并投入使用。**
