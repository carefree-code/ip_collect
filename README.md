# IP威胁收集分析服务

> **版本**: 2.0.0
> **作者**: sinma
> **网站**: [https://www.carefreecode.com/](https://www.carefreecode.com/)
> **QQ**: 42033223

用于服务器环境的日志分析服务，收集和分析 Nginx 访问日志、WAF 拦截日志、SSH 登录日志，识别有威胁的 IP 地址并记录。

支持宝塔面板环境（包括免费Nginx防火墙），也支持原生 Linux 服务器。

## 最近更新 (v2.0.0 - 2025-12-14)

- ✅ **新增免费WAF支持**: 支持宝塔免费Nginx防火墙拦截日志分析
- ✅ **智能误封防护**: 优化检测逻辑，减少对正常访问的误判
- ✅ **搜索引擎白名单**: 内置142个主流搜索引擎爬虫IP段（Google、Bing、百度、Yandex等10家）
- ✅ **AI爬虫白名单**: 内置28个AI引擎爬虫IP段（OpenAI、Anthropic、Meta、Apple等11家）
- ✅ **IP范围格式**: 白名单支持IP范围格式（如 192.168.1.0-192.168.1.255）
- ✅ **批量处理优化**: 修复SQLite变量限制问题，支持大批量IP处理
- ✅ **IPv6完整支持**: 全面支持IPv6地址和网段

详见：[更新日志](docs/白名单综合更新总结.md)

## 功能特点

- **多日志源支持**：Nginx访问日志、宝塔付费WAF、宝塔免费Nginx防火墙、SSH登录日志
- **多种威胁检测**：
  - 高频访问检测
  - 敏感路径扫描检测（支持 WordPress、DedeCMS、Typecho、ThinkPHP 等 CMS）
  - 恶意 User-Agent 检测
  - SQL 注入 / XSS / 命令注入 / 路径遍历特征检测
  - LFI/RFI、SSRF、XXE、SSTI 攻击检测
  - 异常状态码分析（仅统计可疑错误：403、500-505）
  - SSH 暴力破解检测
  - WAF 拦截记录（免费WAF降低评分，减少误封）
- **智能白名单**：
  - 内置142个搜索引擎爬虫IP段（Google、Bing、百度、Yandex、360、搜狗等）
  - 内置28个AI引擎爬虫IP段（OpenAI GPTBot、ClaudeBot、Meta AI等）
  - 支持多种格式：单个IP、CIDR网段、IP范围、IPv6
  - 可自定义扩展白名单
- **灵活运行模式**：定时扫描 / 实时监控 / 两者兼顾
- **可配置阈值**：所有检测阈值均可自定义
- **增量分析**：自动记录读取位置，只分析新增日志
- **误封防护**：优化检测规则，避免误封正常访问（curl、wget等工具）
- **Web 管理界面**：可视化查看威胁 IP 统计和详情
- **跨时区支持**：正确处理不同时区服务器的时间

## 快速安装

```bash
# 上传到服务器后执行
chmod +x install.sh
./install.sh
```

安装脚本会自动：
- 检测系统类型（CentOS/Ubuntu/Debian/Alpine 等）
- 检测并使用合适的 Python 版本（>=3.7）
- 根据需要创建虚拟环境（PEP 668 兼容）
- 配置开机自启（支持 systemd/OpenRC/SysVinit）

## 使用方法

### 作为服务运行

```bash
# 启动服务
systemctl start ipcollect

# 停止服务
systemctl stop ipcollect

# 重启服务
systemctl restart ipcollect

# 查看状态
systemctl status ipcollect

# 查看日志
tail -f /www/server/ipcollect/logs/ipcollect.log
```

### 手动执行

```bash
cd /www/server/ipcollect

# 执行一次扫描
python3 main.py --once

# 全量扫描（不使用增量）
python3 main.py --once --full

# 查看统计信息
python3 main.py --stats

# 导出所有威胁IP
python3 main.py --export

# 只导出HIGH及以上等级
python3 main.py --export --min-level HIGH

# 指定运行模式
python3 main.py --mode scheduled   # 定时扫描
python3 main.py --mode realtime    # 实时监控
python3 main.py --mode both        # 两者都开

# 禁用Web界面运行
python3 main.py --no-web
```

## Web 管理界面

服务启动后自动开启 Web 管理界面：

- 默认地址：`http://服务器IP:60000`
- 功能：
  - 威胁 IP 统计概览
  - 7 天趋势图表
  - 威胁 IP 列表（支持搜索、筛选、排序）
  - IP 详情查看（威胁行为、时间线）
  - 导出功能

### 配置密码保护

```yaml
web:
  enabled: true
  host: 0.0.0.0
  port: 60000
  password: "your_password"  # 设置访问密码
```

## 配置说明

配置文件：`config.yaml`

### 运行模式

```yaml
mode: scheduled        # scheduled / realtime / both
scan_interval: 3600    # 定时扫描间隔（秒）
```

### 日志源配置

```yaml
log_sources:
  nginx:
    enabled: true
    paths:
      - /www/wwwlogs/*.log
    exclude:
      - "*.gz"
  waf:
    enabled: true
    paths:
      - /www/server/panel/plugin/btwaf/logs/*.log
      - /www/server/panel/vhost/waf/*.log
  free_waf:
    enabled: true  # 宝塔免费Nginx防火墙
    paths:
      - /www/wwwlogs/free_waf_log/*.log
      - /www/wwwlogs/free_waf_log/**/*.log
  ssh:
    enabled: true
    paths:
      - /var/log/secure
      - /var/log/auth.log
```

### 威胁检测阈值

```yaml
thresholds:
  frequency:
    window_seconds: 300   # 时间窗口（秒）
    max_requests: 100     # 最大请求数
  error_rate:
    window_seconds: 60
    max_errors: 50
  path_scan:
    max_sensitive_hits: 5
  ssh_bruteforce:
    window_seconds: 300
    max_failures: 5
```

### 白名单配置

支持两种方式配置白名单：

**方式一：直接在配置文件中定义**
```yaml
whitelist:
  - 127.0.0.1
  - ::1
  - 192.168.0.0/16    # 支持CIDR
  - 10.0.0.0/8
```

**方式二：从外部文件导入（推荐）**
```yaml
whitelist_file: ./white.txt
```

白名单文件格式（`white.txt`）：
```
# 注释行
127.0.0.1                          # 单个IP
192.168.0.0/16                     # CIDR网段
10.0.0.0/8                         # 支持大段
66.249.64.0-66.249.64.255          # IP范围格式
2600:1f28:365:80b0::/60            # IPv6网段

# CDN IP段
173.245.48.0/20                    # Cloudflare

# 搜索引擎爬虫（已内置142个IP段）
# Google、Bing、百度、Yandex、DuckDuckGo等

# AI引擎爬虫（已内置28个IP段）
# OpenAI GPTBot、ClaudeBot、Meta AI等
```

**内置白名单统计**（v2.0.0）：
- 搜索引擎爬虫: 142个IP段（10家主流搜索引擎）
- AI引擎爬虫: 28个IP段（11家AI厂商）
- 总计规则: 299条（2个单IP + 157个CIDR + 140个IP范围）

详见文档：
- [搜索引擎爬虫白名单说明](docs/搜索引擎爬虫白名单更新说明.md)
- [AI爬虫白名单说明](docs/AI爬虫白名单更新说明.md)
- [防误封建议](docs/防误封建议.md)

### 数据库配置

```yaml
database:
  path: ./data/ipcollect.db
  retention_days: 365           # 访问日志保留天数
  threat_retention_days: 180    # 威胁IP保留天数（0=永久）
```

当 `threat_retention_days > 0` 时，清理过期威胁IP前会自动备份所有IP到 `ip_时间戳.txt`。

### 输出配置

```yaml
output:
  file: ./ip.txt       # 输出文件路径
  format: detailed     # simple / detailed
  deduplicate: true    # 是否去重
```

## 输出格式

### Simple 格式
```
192.168.1.100
10.0.0.50
```

### Detailed 格式
```
# IP威胁记录 - 更新时间: 2025-12-09 12:00:00
# 格式: IP | 等级 | 原因 | 命中次数 | 首次发现 | 最后活动
192.168.1.100 | CRITICAL | waf_block,sql_injection | 15 | 2025-12-09 10:00:00 | 2025-12-09 11:50:00
10.0.0.50 | HIGH | sensitive_path,frequency_violation | 230 | 2025-12-09 09:30:00 | 2025-12-09 11:45:00
```

## 威胁等级

| 等级 | 分数阈值 | 说明 |
|------|----------|------|
| LOW | >= 2 | 轻微可疑 |
| MEDIUM | >= 4 | 中等威胁 |
| HIGH | >= 6 | 高威胁 |
| CRITICAL | >= 8 | 严重威胁 |

## 威胁类型说明

| 类型 | 说明 | 默认分数 | 备注 |
|------|------|----------|------|
| `frequency_violation` | 高频访问 | 3 | 短时间内大量请求 |
| `sensitive_path` | 敏感路径扫描 | 4 | 扫描后台、数据库等 |
| `malicious_ua` | 恶意User-Agent | 4 | 扫描器、爬虫工具 |
| `error_flood` | 大量错误请求 | 2 | 仅统计403、500-505 |
| `sql_injection` | SQL注入特征 | 5 | 数据库攻击 |
| `xss_attack` | XSS攻击特征 | 5 | 跨站脚本攻击 |
| `command_injection` | 命令注入特征 | 5 | 命令执行攻击 |
| `path_traversal` | 目录遍历攻击 | 5 | 文件访问攻击 |
| `file_inclusion` | 文件包含攻击 | 5 | LFI/RFI攻击 |
| `waf_block` | 付费WAF拦截 | 5 | 高准确度拦截 |
| `free_waf_block` | 免费WAF拦截 | 2.5 | 降低评分避免误封 |
| `ssh_bruteforce` | SSH暴力破解 | 5 | 多次登录失败 |

## 目录结构

```
/www/server/ipcollect/
├── config.yaml                      # 配置文件
├── white.txt                        # 白名单文件（299条规则）
├── crawler_ips_2025.txt             # 搜索引擎爬虫IP源文件
├── ai_crawler_ips_2025.txt          # AI爬虫IP源文件
├── main.py                          # 主程序
├── ip.txt                           # 威胁IP输出
├── data/                            # 数据目录
│   ├── ipcollect.db                 # SQLite数据库
│   └── state.json                   # 扫描状态
├── logs/                            # 日志目录
│   └── ipcollect.log                # 程序日志
├── docs/                            # 文档目录
│   ├── 白名单综合更新总结.md        # 更新日志
│   ├── 搜索引擎爬虫白名单更新说明.md # 搜索引擎爬虫文档
│   ├── AI爬虫白名单更新说明.md       # AI爬虫文档
│   └── 防误封建议.md                 # 防误封配置指南
├── venv/                            # Python虚拟环境（如有）
├── web/                             # Web界面
│   ├── app.py
│   └── templates/
├── collectors/                      # 日志收集器
│   ├── nginx.py
│   ├── waf.py
│   ├── free_waf.py                  # 免费WAF收集器
│   └── ssh.py
├── analyzers/                       # 威胁分析器
│   ├── rules.yaml                   # 检测规则（已优化）
│   ├── frequency.py
│   ├── pattern.py                   # 支持免费WAF评分
│   └── status_code.py               # 仅统计可疑错误码
├── storage/                         # 存储模块
│   └── database.py                  # 支持批量处理
├── core/                            # 核心引擎
└── utils/                           # 工具模块
    ├── ip_utils.py                  # 支持IP范围格式
    └── log_parser.py                # 支持免费WAF日志
```

## 系统要求

- **Python**: >= 3.7
- **操作系统**: Linux (CentOS/RHEL/Ubuntu/Debian/Alpine 等)
- **依赖**: PyYAML, Flask, watchdog

## 卸载

```bash
systemctl stop ipcollect
systemctl disable ipcollect
rm -rf /www/server/ipcollect
rm /etc/systemd/system/ipcollect.service
systemctl daemon-reload
```

## 常见问题

**Q: 如何添加IP白名单？**

两种方式：
1. 编辑 `config.yaml` 中的 `whitelist` 列表
2. 编辑 `white.txt` 文件（支持注释和CIDR格式）

**Q: 如何修改检测规则？**

编辑 `analyzers/rules.yaml` 文件，可以添加自定义的敏感路径和攻击特征。

**Q: 服务占用资源过高？**

- 调整 `scan_interval` 增大扫描间隔
- 使用 `scheduled` 模式代替 `realtime` 模式
- 在日志源配置中排除不需要的日志文件

**Q: Web界面无法访问？**

1. 检查防火墙是否开放端口（默认 60003）
2. 检查 `config.yaml` 中 `web.enabled` 是否为 `true`
3. 查看日志确认 Web 服务是否启动成功

**Q: 如何在美国/新加坡等海外服务器使用？**

完全支持。程序内部统一使用 UTC 时间处理，不受服务器时区影响。

**Q: 如何查看威胁IP详情？**

1. 访问 Web 管理界面，点击 IP 地址或"详情"按钮
2. 或使用命令：`python3 main.py --stats`

**Q: 白名单支持哪些格式？**

- 单个 IPv4: `192.168.1.1`
- 单个 IPv6: `::1`
- IPv4 CIDR: `192.168.0.0/24`, `10.0.0.0/8`
- IPv6 CIDR: `fe80::/10`, `2600:1f28:365:80b0::/60`
- IP范围: `66.249.64.0-66.249.64.255`
- 注释: `# 这是注释`

详见：[防误封建议](docs/防误封建议.md)

**Q: 内置白名单包含哪些IP？**

v2.0.0内置了299条白名单规则：
- **搜索引擎爬虫**（142个IP段）：Google、Bing、百度、Yandex、DuckDuckGo、360、搜狗、神马、头条、Facebook、LinkedIn、Apple
- **AI引擎爬虫**（28个IP段）：OpenAI GPTBot、Anthropic ClaudeBot、Meta AI、Apple Intelligence、Common Crawl、Amazon Amazonbot等

详见：
- [搜索引擎爬虫白名单说明](docs/搜索引擎爬虫白名单更新说明.md)
- [AI爬虫白名单说明](docs/AI爬虫白名单更新说明.md)

**Q: 如何验证爬虫真实性？**

使用反向DNS验证：
```bash
# Google
host 66.249.64.10
# 应返回: crawl-66-249-64-10.googlebot.com

# 百度
host 180.76.15.5
# 应返回: *.baidu.com 或 *.baidu.jp

# ClaudeBot
host 160.79.104.50
# 应返回: *.claude.com
```

**Q: 如何防止误封正常访问？**

v2.0.0已优化检测逻辑：
1. **状态码检测**：只统计可疑错误（403、500-505），忽略正常的404
2. **免费WAF评分**：降低为付费版的一半（2.5分），避免误封
3. **User-Agent规则**：已移除curl、wget、axios等正常工具
4. **SQL注入规则**：更严格的匹配规则，避免误伤正常查询参数
5. **内置白名单**：142个搜索引擎爬虫 + 28个AI爬虫

详见：[防误封建议](docs/防误封建议.md)

**Q: 是否应该允许AI爬虫？**

需要权衡：
- ✅ **允许的好处**：让AI产品索引你的内容，可能带来流量
- ❌ **禁止的原因**：保护原创内容，减少服务器负载

**推荐配置**：
- ✅ 允许高质量AI：OpenAI GPTBot、ClaudeBot、Google-Extended、Meta AI、Apple Intelligence、Common Crawl
- ⚠️ 谨慎处理有争议的：Perplexity（绕过robots.txt）、Bytespider（高频访问）

详见：[AI爬虫白名单说明](docs/AI爬虫白名单更新说明.md)

---

## 联系方式

- **作者**: sinma
- **网站**: [https://www.carefreecode.com/](https://www.carefreecode.com/)
- **QQ**: 42033223

如有问题或建议，欢迎通过以上方式联系。

## License

MIT License
