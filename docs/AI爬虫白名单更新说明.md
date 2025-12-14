# AI引擎爬虫IP白名单更新说明

## 更新时间
2025年12月14日

## 概述

本次更新添加了国内外主流AI引擎的爬虫IP到白名单，包括OpenAI、Anthropic、Google、Meta等厂商的AI训练数据抓取爬虫。

## 已添加的AI厂商

### 1. OpenAI ✅
**产品**: ChatGPT, GPT-4, DALL-E等

#### GPTBot
- **用途**: AI模型训练数据抓取
- **官方JSON**: https://openai.com/gptbot.json
- **IP段**: 40.83.2.64/28

#### OAI-SearchBot
- **用途**: 搜索功能
- **IP段**:
  - 20.42.10.176/28
  - 172.203.190.128/28
  - 51.8.102.0/24
  - 135.234.64.0/24

#### ChatGPT-User
- **用途**: 用户交互产生的网页抓取
- **IP段**:
  - 23.98.179.16/28
  - 172.183.222.128/28
  - 52.190.190.16/28
  - 51.8.155.64/28
  - 51.8.155.48/28
  - 135.237.131.208/28

**官方文档**: [OpenAI Web Crawler](https://platform.openai.com/docs/bots)

---

### 2. Anthropic (Claude) ✅
**产品**: Claude, Claude Pro

#### ClaudeBot
- **用途**: AI模型训练数据抓取
- **IP段**: 160.79.104.0/24
- **验证**: 反向DNS应返回 *.claude.com

#### Claude-User
- **用途**: 用户交互产生的网页抓取
- **注意**: IP可能动态变化

**官方文档**: [Anthropic Claude Docs](https://docs.claude.com/en/api/ip-addresses)

**相关链接**: [Support Article](https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler)

---

### 3. Google AI (Google-Extended) ⚠️
**产品**: Bard, Gemini, Vertex AI

- **识别方式**: 主要通过User-Agent识别
- **IP范围**: 与Googlebot重叠（已包含在搜索引擎白名单中）
- **User-Agent**: `Google-Extended`
- **更新**: 2025年4月重大更新

**说明**: Google-Extended专门用于AI训练，区别于搜索索引

**官方文档**: [Google-Extended Overview](https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers)

**相关链接**:
- [Google-Extended Update](https://thatware.co/google-extended-crawler-update/)
- [What is Google-Extended](https://datadome.co/bots/google-extended/)

---

### 4. Meta AI (Meta-ExternalAgent) ✅
**产品**: Llama, Meta AI

#### IP范围 (AS32934)
**IPv4**:
- 173.252.64.0/18
- 57.141.0.0/24
- 66.220.144.0/20
- 69.171.224.0/19
- 69.63.176.0/20
- 31.13.24.0/21
- 31.13.64.0/18

**IPv6**:
- 2a03:2880::/29

**特点**:
- 2024年7月新推出
- 访问频率可能较高（2-3次/秒）
- 从多个数据中心抓取

**相关链接**:
- [Meta External Agent Launch](https://fortune.com/2024/08/20/meta-external-agent-new-web-crawler-bot-scrape-data-train-ai-models-llama/)
- [What is FacebookBot](https://datadome.co/bots/facebookbot/)
- [Meta-ExternalAgent](https://datadome.co/bots/meta-externalagent/)

---

### 5. Apple (Applebot-Extended) ✅
**产品**: Apple Intelligence

#### IP范围
- 17.0.0.0/8 (Apple全局)
- 17.22.0.0/16 (Applebot专用)
- 17.58.0.0/16 (Applebot专用)

**验证**: 反向DNS应返回 *.applebot.apple.com

**User-Agent**: `Applebot-Extended`

**相关链接**: [Understanding Applebot](https://medium.com/prompt-engineering/understanding-applebot-apples-web-crawler-2a45eacfbbae)

---

### 6. Common Crawl (CCBot) ✅
**用途**: 开源网络数据集，供AI研究使用

#### 官方IP列表
**来源**: https://index.commoncrawl.org/ccbot.json
**更新**: 2024年11月29日

**IPv4**:
- 18.97.9.168/29
- 18.97.14.80/29
- 18.97.14.88/30
- 98.85.178.216/32

**IPv6**:
- 2600:1f28:365:80b0::/60

**验证**: `host <IP>` 应返回 *.crawl.commoncrawl.org

**官方网站**: [Common Crawl](https://commoncrawl.org/)

---

### 7. Perplexity AI ⚠️ (有争议)
**产品**: Perplexity搜索

**注意事项**:
- 官方文档: https://docs.perplexity.ai/guides/bots
- **争议**: 被发现会绕过robots.txt规则
- **行为**: 使用代理IP伪装身份
- **Cloudflare**: 已将其从验证爬虫列表中移除

**建议**:
- 谨慎处理，可能不适合加入白名单
- 优先通过User-Agent识别和控制

**相关链接**:
- [Perplexity Ignores Robots.txt](https://www.malwarebytes.com/blog/news/2025/08/perplexity-ai-ignores-no-crawling-rules-on-websites-crawls-them-anyway)
- [Cloudflare Blocks Perplexity](https://www.searchenginejournal.com/cloudflare-delists-and-blocks-perplexity-from-crawling-websites/552899/)
- [Perplexity Stealth Crawling](https://blog.cloudflare.com/perplexity-is-using-stealth-undeclared-crawlers-to-evade-website-no-crawl-directives/)

---

### 8. 字节跳动 (Bytespider) ⚠️
**产品**: 豆包、TikTok AI

**IP特点**:
- 使用AWS、Google Cloud等云服务
- IP范围广泛且动态变化
- 访问频率可能极高

**已知IP段** (不完整):
- 110.249.201.0/24
- 110.249.202.0/24
- 220.243.188.0/23

**问题**:
- 经常忽略robots.txt
- 来自数千个不同IP
- 可能对服务器造成压力

**建议**:
- 谨慎加入白名单
- 优先通过User-Agent控制
- 考虑限流措施

**相关链接**:
- [What is Bytespider](https://datadome.co/bots/bytespider/)
- [Blocking Bytespider](https://medium.com/@admin_85331/blocking-bytedance-and-bytespider-using-cloudflare-web-application-firewall-waf-569bbcca9b24)
- [Bytespider Attack Reports](https://wordpress.org/support/topic/psa-bytedance-and-bytespider-bots-recommend-blocking/)

---

### 9. Cohere AI ⚠️
**产品**: Cohere模型

**状态**: 未公开官方IP列表
**建议**: 通过User-Agent识别
**User-Agent**: `cohere-ai`

**相关链接**: [What is Cohere AI Bot](https://datadome.co/bots/cohere-ai/)

---

### 10. Diffbot ⚠️
**用途**: AI数据提取服务

**IP特点**:
- 使用Google Cloud、AWS、Azure等
- IP动态变化
- 主要来自35.226.0.0/16 (Google Cloud)

**建议**: 通过User-Agent识别

**相关链接**:
- [What is Diffbot](https://datadome.co/bots/diffbot/)
- [Blocking Diffbot](https://soggi.org/misc/articles/Diffbot-blocking-bad-bot-rude-content-scraper-from-websites.htm)

---

### 11. Amazon (Amazonbot) ✅
**产品**: Alexa AI

**IP范围**:
- 52.0.0.0/8
- 54.0.0.0/8

---

## 中国AI厂商

### 百度 (文心一言) 📝
- **状态**: 未公开专门的AI训练爬虫IP
- **备注**: 与百度搜索爬虫可能重叠（已在搜索引擎白名单中）

### 阿里 (通义千问) 📝
- **状态**: 未公开专门的AI训练爬虫IP
- **User-Agent**: 可能包含 `QwenBot`

### 腾讯 (混元) 📝
- **状态**: 未公开专门的AI训练爬虫IP

### 讯飞 (星火) 📝
- **状态**: 未公开专门的AI训练爬虫IP

### 智谱AI (ChatGLM) 📝
- **User-Agent**: `ChatGLM-Spider`
- **问题**: 被报告会忽略robots.txt

---

## 统计信息

### 白名单总计
- **单个IP**: 2个
- **CIDR网段**: 157个（新增28个AI爬虫段）
- **IP范围**: 140个
- **总计规则**: 299条

### 新增AI爬虫IP
- OpenAI: 9个IP段
- Anthropic: 1个IP段
- Meta: 8个IP段
- Apple: 3个IP段
- Common Crawl: 5个IP段
- 字节跳动: 3个IP段
- 其他: 若干

---

## 测试结果

所有主流AI爬虫IP均通过验证：
- ✓ OpenAI GPTBot
- ✓ OpenAI ChatGPT-User
- ✓ Anthropic ClaudeBot
- ✓ Meta AI
- ✓ Applebot
- ✓ Common Crawl CCBot
- ✓ Bytespider

---

## 建议配置策略

### 推荐白名单配置（高质量AI）
✅ **建议添加**:
- OpenAI (GPTBot, ChatGPT-User)
- Anthropic (ClaudeBot)
- Google (Google-Extended)
- Meta AI
- Apple (Applebot-Extended)
- Common Crawl (CCBot)

### 谨慎处理（有争议）
⚠️ **需要评估**:
- Perplexity AI（会绕过robots.txt）
- Bytespider（高频访问、忽略robots.txt）
- Diffbot（商业数据提取）
- ChatGLM-Spider（忽略robots.txt）

### 控制方式

#### 方式1: IP白名单（本项目）
适用于有明确IP列表的爬虫

#### 方式2: robots.txt
```
User-agent: GPTBot
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: PerplexityBot
Disallow: /

User-agent: Bytespider
Disallow: /
```

#### 方式3: User-Agent过滤
在nginx/Apache中配置：
```nginx
# 允许
if ($http_user_agent ~* "GPTBot|ClaudeBot|CCBot") {
    # 允许访问
}

# 禁止
if ($http_user_agent ~* "PerplexityBot|Bytespider|ChatGLM-Spider") {
    return 403;
}
```

---

## 验证爬虫真实性

### 方法1: 反向DNS查询
```bash
# OpenAI
host <IP>
# 应返回: *.openai.com

# Anthropic
host <IP>
# 应返回: *.claude.com

# Apple
host <IP>
# 应返回: *.applebot.apple.com
```

### 方法2: 检查官方JSON
```bash
# OpenAI GPTBot
curl https://openai.com/gptbot.json

# Common Crawl
curl https://index.commoncrawl.org/ccbot.json
```

### 方法3: ASN验证
```bash
# Meta/Facebook (AS32934)
whois <IP> | grep "AS32934"
```

---

## 部署方法

```bash
# 复制更新后的白名单到服务器
cp white.txt /www/server/ipcollect/

# 重启服务
systemctl restart ipcollect

# 验证加载
tail -100 /www/server/ipcollect/logs/ipcollect.log
```

---

## 维护建议

1. **定期更新**: AI厂商IP可能频繁变化，建议每月检查
2. **监控流量**: 关注AI爬虫的访问频率，必要时限流
3. **查看日志**: 定期检查是否有新的AI爬虫
4. **权衡利弊**:
   - ✅ 允许AI爬虫：有助于AI产品索引你的内容
   - ❌ 禁止AI爬虫：保护原创内容，减少服务器负载

---

## AI爬虫完整列表

根据2025年最新资料，已知的AI爬虫包括：

**已添加IP的**:
- GPTBot (OpenAI)
- ChatGPT-User (OpenAI)
- OAI-SearchBot (OpenAI)
- ClaudeBot (Anthropic)
- Claude-User (Anthropic)
- Google-Extended (Google)
- Meta-ExternalAgent (Meta)
- FacebookBot (Meta)
- Applebot-Extended (Apple)
- CCBot (Common Crawl)
- Amazonbot (Amazon)

**仅User-Agent识别**:
- PerplexityBot (Perplexity)
- Bytespider (ByteDance)
- Diffbot
- cohere-ai (Cohere)
- anthropic-ai
- YouBot (You.com)
- ChatGLM-Spider (智谱AI)
- QwenBot (阿里)
- Omgilibot
- ImagesiftBot

完整列表参见: [Complete AI Crawler List](https://www.searchenginejournal.com/ai-crawler-user-agents-list/558130/)

---

## 参考资料

### 官方文档
- [OpenAI Bots](https://platform.openai.com/docs/bots)
- [Anthropic Claude Docs](https://docs.claude.com/)
- [Common Crawl](https://commoncrawl.org/)
- [Google Crawlers](https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers)
- [Perplexity Bots](https://docs.perplexity.ai/guides/bots)

### 社区资源
- [GitHub - GoodBots](https://github.com/AnTheMaker/GoodBots)
- [AI Crawlers Guide](https://wpsuites.com/blog/ai-crawlers-guide/)
- [Momentic AI Crawlers List](https://momenticmarketing.com/blog/ai-search-crawlers-bots)
- [Dark Visitors - AI Bot Directory](https://darkvisitors.com/)

---

## 作者信息

- 作者: sinma
- 网站: https://www.carefreecode.com/
- QQ: 42033223
- 版本: 1.0.0
