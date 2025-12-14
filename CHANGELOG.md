# 更新日志

## [2.0.0] - 2025-12-14

### 新增功能
- ✅ **免费WAF支持**: 新增宝塔免费Nginx防火墙拦截日志分析功能
  - 新增 `collectors/free_waf.py` 收集器
  - 支持JSON数组格式日志解析
  - 配置项：`log_sources.free_waf`

- ✅ **搜索引擎爬虫白名单**: 内置142个主流搜索引擎爬虫IP段
  - Google Googlebot（2025年2月最新）
  - Bing Bingbot
  - 百度 Baiduspider
  - Yandex YandexBot（2025年4月SPF记录）
  - DuckDuckGo DuckDuckBot（2025年6月新增JSON端点）
  - 360搜索
  - 搜狗 Sogou
  - 神马搜索（阿里UC）
  - 头条搜索
  - Facebook、LinkedIn、Apple等爬虫

- ✅ **AI引擎爬虫白名单**: 内置28个AI引擎爬虫IP段
  - OpenAI (GPTBot, ChatGPT-User, OAI-SearchBot) - 9个IP段
  - Anthropic (ClaudeBot, Claude-User) - 1个IP段
  - Google AI (Google-Extended) - 与Googlebot重叠
  - Meta AI (Meta-ExternalAgent) - 8个IP段
  - Apple (Applebot-Extended) - 3个IP段
  - Common Crawl (CCBot) - 5个IP段
  - Amazon Amazonbot
  - LinkedIn AI
  - 字节跳动 Bytespider（谨慎处理）
  - Perplexity（有争议，会绕过robots.txt）
  - Diffbot、Cohere AI等

- ✅ **IP范围格式支持**: 白名单支持IP范围格式（如 192.168.1.0-192.168.1.255）
  - 增强 `utils/ip_utils.py` 的 `is_whitelisted()` 函数
  - 增强 `WhitelistManager` 类支持 `_ranges` 列表
  - 支持混合使用单IP、CIDR、IP范围格式

- ✅ **IPv6完整支持**: 全面支持IPv6地址和网段
  - 单个IPv6: `::1`
  - IPv6 CIDR: `2600:1f28:365:80b0::/60`
  - IPv6范围验证

### 优化改进
- ✅ **智能误封防护**: 大幅优化检测逻辑，减少对正常访问的误判
  - **状态码分析器**: 仅统计可疑错误码（403、500-505），不再统计正常的404、401等
  - **免费WAF评分**: 降低为付费版的一半（5分→2.5分），避免误封
  - **User-Agent规则**: 移除curl、wget、axios等合法工具
  - **SQL注入规则**: 更严格的匹配规则，避免误伤正常查询参数

- ✅ **批量处理优化**: 修复SQLite "too many SQL variables" 错误
  - 修改 `storage/database.py` 的 `mark_exported()` 方法
  - 使用分批处理，每批最多500个IP
  - 支持大规模IP导出操作

### 文档更新
- ✅ 新增 `docs/白名单综合更新总结.md` - 完整更新日志
- ✅ 新增 `docs/搜索引擎爬虫白名单更新说明.md` - 搜索引擎爬虫详细文档
- ✅ 新增 `docs/AI爬虫白名单更新说明.md` - AI爬虫详细文档（包含争议说明）
- ✅ 新增 `docs/防误封建议.md` - 防误封配置指南
- ✅ 更新 `README.md` - 反映最新功能和配置
- ✅ 更新 `PLAN.md` - 标记项目完成状态

### 文件清单
- **白名单**: `white.txt` (585行, 299条规则)
- **源文件**: `crawler_ips_2025.txt`, `ai_crawler_ips_2025.txt`
- **收集器**: `collectors/free_waf.py`
- **工具**: `utils/ip_utils.py` (支持IP范围)
- **分析器**: `analyzers/status_code.py`, `analyzers/pattern.py` (优化)
- **规则**: `analyzers/rules.yaml` (优化)

### 统计数据
- 白名单总计: 299条规则
  - 单个IP: 2个
  - CIDR网段: 157个
  - IP范围: 140个
- 搜索引擎爬虫: 142个IP段（10家搜索引擎）
- AI爬虫: 28个IP段（11家AI厂商）

### 测试结果
✅ 所有测试均通过：
- Google Bot (66.249.64.10)
- 百度爬虫 (180.76.15.5)
- Bing Bot (40.77.167.50)
- Yandex Bot (77.88.5.10)
- 360搜索 (101.226.10.10)
- 搜狗爬虫 (123.126.113.10)
- 神马搜索 (42.156.10.10)
- OpenAI GPTBot (40.83.2.70)
- OpenAI ChatGPT-User (23.98.179.20)
- Anthropic ClaudeBot (160.79.104.50)
- Meta AI (173.252.64.100)
- Applebot (17.22.100.10)
- CCBot (18.97.14.85)
- Bytespider (110.249.201.100)

---

## [1.0.0] - 2025-12-13

### 初始版本
- ✅ 基础框架和配置系统
- ✅ Nginx访问日志收集
- ✅ 宝塔付费WAF日志收集
- ✅ SSH登录日志收集
- ✅ 高频访问检测
- ✅ 敏感路径扫描检测
- ✅ 恶意User-Agent检测
- ✅ SQL注入/XSS/命令注入检测
- ✅ 异常状态码分析
- ✅ SSH暴力破解检测
- ✅ SQLite数据存储
- ✅ 威胁IP导出（Simple/Detailed格式）
- ✅ 定时扫描模式
- ✅ 实时监控模式
- ✅ Web管理界面
- ✅ 白名单支持（CIDR格式）
- ✅ 数据保留策略
- ✅ 跨时区支持
- ✅ 安装脚本（支持多种Linux发行版）
- ✅ Systemd服务文件

---

## 版本说明

### 版本号规则
- 主版本号.次版本号.修订号 (X.Y.Z)
- 主版本号: 重大架构变更或不兼容更新
- 次版本号: 新功能添加
- 修订号: Bug修复和小优化

### 支持
- **当前版本**: 2.0.0
- **维护状态**: 积极维护中
- **Python要求**: >= 3.7
- **系统要求**: Linux (CentOS/Ubuntu/Debian/Alpine等)

---

## 计划中的功能

### v2.1.0 (未来)
- [ ] 自动调用宝塔API封禁IP
- [ ] IP归属地查询
- [ ] 邮件/微信告警
- [ ] 威胁情报联动
- [ ] 定期自动更新爬虫白名单

### 维护计划
- 每月: 检查官方JSON更新（OpenAI、Common Crawl等）
- 每季度: 全面更新搜索引擎和AI爬虫IP列表
- 按需: 发现新爬虫时及时添加
