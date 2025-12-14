# 升级指南

## v1.0.0 → v2.0.0 升级步骤

### 重要提示

v2.0.0 包含以下重大更新：
- ✅ 新增免费WAF日志支持
- ✅ 内置299条白名单规则（搜索引擎+AI爬虫）
- ✅ 优化检测逻辑，减少误封
- ✅ 支持IP范围格式
- ✅ 批量处理优化

**向后兼容**: v2.0.0 与 v1.0.0 配置文件兼容，可以直接升级。

---

## 升级步骤

### 方法一：完整覆盖（推荐）

**适用场景**: 没有自定义修改，或希望获得所有新功能

```bash
# 1. 备份当前配置和数据
cd /www/server/ipcollect
cp config.yaml config.yaml.bak
cp white.txt white.txt.bak
cp -r data data.bak
cp -r logs logs.bak

# 2. 停止服务
systemctl stop ipcollect

# 3. 下载并解压新版本
cd /tmp
# （从GitHub或其他渠道获取v2.0.0代码包）
# unzip ipcollect-v2.0.0.zip

# 4. 覆盖文件（保留数据和配置）
cd ipcollect-v2.0.0
cp -r collectors analyzers core storage utils web /www/server/ipcollect/
cp main.py /www/server/ipcollect/
cp requirements.txt /www/server/ipcollect/

# 5. 更新白名单（重要！）
cp white.txt /www/server/ipcollect/white.txt

# 6. 更新配置文件（如需启用免费WAF）
# 编辑 /www/server/ipcollect/config.yaml
# 确保包含以下内容：
#   free_waf:
#     enabled: true
#     paths:
#       - /www/wwwlogs/free_waf_log/*.log
#       - /www/wwwlogs/free_waf_log/**/*.log

# 7. 复制文档
cp -r docs /www/server/ipcollect/
cp CHANGELOG.md README.md UPGRADE.md /www/server/ipcollect/

# 8. 重启服务
systemctl restart ipcollect

# 9. 验证服务状态
systemctl status ipcollect
tail -50 /www/server/ipcollect/logs/ipcollect.log

# 10. 测试白名单加载
cd /www/server/ipcollect
python3 -c "
from utils.ip_utils import WhitelistManager
manager = WhitelistManager(whitelist_file='white.txt')
print(f'CIDR网段: {len(manager._networks)}')
print(f'IP范围: {len(manager._ranges)}')
print(f'总计: {len(manager._ips) + len(manager._networks) + len(manager._ranges)}')
"
# 预期输出: CIDR网段: 157, IP范围: 140左右
```

---

### 方法二：选择性更新

**适用场景**: 有大量自定义配置，只想更新核心功能

```bash
# 1. 备份
cd /www/server/ipcollect
cp -r . ../ipcollect.bak

# 2. 停止服务
systemctl stop ipcollect

# 3. 更新核心文件
# 3.1 更新收集器（新增免费WAF支持）
cp collectors/free_waf.py /www/server/ipcollect/collectors/
cp collectors/__init__.py /www/server/ipcollect/collectors/

# 3.2 更新分析器（优化检测规则）
cp analyzers/status_code.py /www/server/ipcollect/analyzers/
cp analyzers/pattern.py /www/server/ipcollect/analyzers/
cp analyzers/rules.yaml /www/server/ipcollect/analyzers/

# 3.3 更新工具（支持IP范围）
cp utils/ip_utils.py /www/server/ipcollect/utils/
cp utils/log_parser.py /www/server/ipcollect/utils/

# 3.4 更新存储（批量处理优化）
cp storage/database.py /www/server/ipcollect/storage/

# 3.5 更新引擎
cp core/engine.py /www/server/ipcollect/core/
cp core/watcher.py /www/server/ipcollect/core/

# 4. 合并白名单
# 如果你有自定义白名单，需要手动合并
cat white.txt >> /www/server/ipcollect/white.txt

# 5. 更新配置（如需启用免费WAF）
vim /www/server/ipcollect/config.yaml
# 添加免费WAF配置（参见方法一第6步）

# 6. 重启服务
systemctl restart ipcollect

# 7. 验证
systemctl status ipcollect
```

---

## 配置变更检查清单

### 必须添加的配置

如果你的 `config.yaml` 中没有以下配置，请添加：

```yaml
# 免费WAF日志（新增）
log_sources:
  free_waf:
    enabled: true
    paths:
      - /www/wwwlogs/free_waf_log/*.log
      - /www/wwwlogs/free_waf_log/**/*.log
```

### 可选优化的配置

```yaml
# 调整阈值（可选，避免误封）
thresholds:
  frequency:
    window_seconds: 300
    max_requests: 100      # 可提高到200-300
  error_rate:
    window_seconds: 120    # 建议从60提高到120
    max_errors: 50
```

---

## 白名单更新

### 自动导入（推荐）

直接使用新版本的 `white.txt`，已包含：
- 142个搜索引擎爬虫IP段
- 28个AI引擎爬虫IP段
- 总计299条规则

```bash
cp white.txt /www/server/ipcollect/white.txt
```

### 保留自定义白名单

如果你有自定义的白名单IP，需要合并：

```bash
# 方法1: 追加到末尾
cat /www/server/ipcollect/white.txt.bak | tail -n +91 >> white.txt

# 方法2: 手动编辑
vim /www/server/ipcollect/white.txt
# 在文件末尾添加你的自定义IP
```

---

## 验证升级

### 1. 检查服务状态

```bash
systemctl status ipcollect
```

预期输出：`Active: active (running)`

### 2. 检查日志

```bash
tail -50 /www/server/ipcollect/logs/ipcollect.log
```

应该看到：
- 白名单加载成功消息
- 免费WAF收集器初始化（如已启用）
- 无错误信息

### 3. 测试白名单

```bash
cd /www/server/ipcollect
python3 -c "
from utils.ip_utils import WhitelistManager
manager = WhitelistManager(whitelist_file='white.txt')

# 测试CIDR格式
print('Google Bot (66.249.64.10):', manager.is_whitelisted('66.249.64.10'))

# 测试IP范围格式
print('Baidu Bot (180.76.15.5):', manager.is_whitelisted('180.76.15.5'))

# 测试OpenAI
print('OpenAI GPTBot (40.83.2.70):', manager.is_whitelisted('40.83.2.70'))

# 测试ClaudeBot
print('ClaudeBot (160.79.104.50):', manager.is_whitelisted('160.79.104.50'))
"
```

预期输出：全部为 `True`

### 4. 检查Web界面

访问 `http://服务器IP:60003`，确认：
- 界面正常显示
- 威胁IP列表正常
- 搜索和筛选功能正常

---

## 回滚到v1.0.0

如果升级后遇到问题，可以回滚：

```bash
# 停止服务
systemctl stop ipcollect

# 恢复备份
cd /www/server
rm -rf ipcollect
mv ipcollect.bak ipcollect

# 重启服务
systemctl restart ipcollect

# 验证
systemctl status ipcollect
```

---

## 常见问题

### Q: 升级后出现 "too many SQL variables" 错误？

**A**: 这是v2.0.0修复的问题。确保 `storage/database.py` 已更新。如果仍然出现，手动更新：

```bash
cp storage/database.py /www/server/ipcollect/storage/
systemctl restart ipcollect
```

### Q: 白名单没有生效？

**A**: 检查以下几点：
1. 确认 `config.yaml` 中 `whitelist_file` 路径正确
2. 确认 `white.txt` 文件存在且可读
3. 检查日志中的白名单加载信息

```bash
grep -i "whitelist\|白名单" /www/server/ipcollect/logs/ipcollect.log
```

### Q: 免费WAF日志没有被分析？

**A**: 检查：
1. `config.yaml` 中 `free_waf.enabled` 是否为 `true`
2. 日志路径是否正确（默认 `/www/wwwlogs/free_waf_log/`）
3. 是否有权限读取日志文件

```bash
ls -la /www/wwwlogs/free_waf_log/
```

### Q: 升级后误封增加了？

**A**: v2.0.0已优化检测逻辑。如果仍有误封：
1. 确认 `analyzers/rules.yaml` 已更新（移除curl、wget等）
2. 确认 `analyzers/status_code.py` 已更新（只统计403、500-505）
3. 确认 `analyzers/pattern.py` 已更新（免费WAF降分）

### Q: 如何验证爬虫白名单是否正确？

**A**: 使用反向DNS查询：

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

---

## 技术支持

如果升级过程中遇到问题：

- **作者**: sinma
- **网站**: [https://www.carefreecode.com/](https://www.carefreecode.com/)
- **QQ**: 42033223

请提供以下信息：
1. 日志文件最后100行：`tail -100 /www/server/ipcollect/logs/ipcollect.log`
2. 配置文件：`config.yaml`
3. 错误信息截图

---

## 文档参考

- [README.md](README.md) - 完整使用文档
- [CHANGELOG.md](CHANGELOG.md) - 版本更新日志
- [docs/白名单综合更新总结.md](docs/白名单综合更新总结.md) - 白名单详细说明
- [docs/防误封建议.md](docs/防误封建议.md) - 防误封配置指南
- [docs/搜索引擎爬虫白名单更新说明.md](docs/搜索引擎爬虫白名单更新说明.md) - 搜索引擎爬虫文档
- [docs/AI爬虫白名单更新说明.md](docs/AI爬虫白名单更新说明.md) - AI爬虫文档

---

**升级愉快！**
