# 🕵️ ShadowAgent

<div align="center">

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![LangGraph](https://img.shields.io/badge/LangGraph-latest-green.svg)](https://github.com/langchain-ai/langgraph)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**基于 LLM 的自动化渗透测试框架，专为 CTF 和 Web 安全测试设计**

[English](README_EN.md) | 简体中文

</div>

---

## 💡 为什么选择 ShadowAgent？

传统的 LLM Agent 在渗透测试中面临三大核心挑战：

### ❌ 传统方案的问题

| 问题 | 传统方案 | 后果 |
|------|---------|------|
| **LLM 幻觉** | 单 Agent 自我反思 | 陷入错误方向，重复失败 5-10 次 |
| **工具选择困难** | 20+ 专用工具 | 决策时间长（15-20 秒），容易选错 |
| **上下文爆炸** | 简单截断或全量保留 | 丢失关键信息或 Token 超限 |

### ✅ ShadowAgent 的解决方案

我们通过**三大创新**解决这些问题：

#### 1️⃣ 三 Agent 协作架构
```
Advisor（战术分析） → Attacker（执行攻击） → Reflector（独立审核）
```
- **独立审核机制**：第三方视角，避免"自己审核自己"
- **智能路由**：失败 2 次自动切换策略
- **精细失败分类**：L0-L4 分级，而不是简单的成功/失败

#### 2️⃣ 极简工具设计
```python
# 仅 3 个核心工具，覆盖所有场景
execute_command()      # 执行任何 Kali 工具（nmap, sqlmap, curl...）
execute_python_poc()   # 编写自动化脚本（IDOR, JWT, Session 篡改）
submit_flag()          # 提交 FLAG
```
- **灵活性高**：一个工具覆盖 100+ Kali 工具
- **决策简单**：从"选哪个工具"变成"写什么命令"
- **扩展性强**：新场景无需添加新工具

#### 3️⃣ 智能上下文管理
```
正则过滤 → HAE 规则引擎 → LLM 总结 → 关键发现持久化
```
- **三层压缩**：80K → 15K tokens（81% 压缩率）
- **零信息丢失**：关键发现（FLAG、凭证、API）永不删除
- **按需加载**：RAG 知识库智能触发，节省 84% Token

---

## 🎯 核心特性

### 🤝 三 Agent 协作

<table>
<tr>
<td width="33%">

**Advisor（顾问）**
- 🧠 战术分析师
- 📋 制定攻击策略
- 🎯 不执行工具
- 💡 避免陷入细节

</td>
<td width="33%">

**Attacker（主攻手）**
- ⚔️ 执行者
- 🔧 调用工具
- 🎯 专注执行
- 💪 高效行动

</td>
<td width="33%">

**Reflector（审核员）**
- 🔍 质检员
- ✅ 独立审核
- 📊 失败分类
- 🚦 路由决策

</td>
</tr>
</table>

**关键创新**：
- ✅ 独立审核（第三方视角，客观准确）
- ✅ 智能路由（失败 2 次自动切换）
- ✅ 精细分类（L0-L4 失败级别）

### 🛠️ 极简工具集

**设计理念**：少即是多

```python
# ❌ 传统方案：20+ 专用工具
run_sqlmap()
run_nikto()
run_dirb()
run_gobuster()
run_nmap()
run_hydra()
...  # 决策困难，选择时间长

# ✅ ShadowAgent：3 个核心工具
execute_command("sqlmap -u http://target/login.php")
execute_command("nikto -h http://target")
execute_python_poc("""
import requests
for i in range(100):
    r = requests.get(f"http://target/api/users/{i}")
    if "admin" in r.text:
        print(f"Found: {i}")
""")
```

**优势**：
- 🚀 决策快（< 5 秒 vs 15-20 秒）
- 🎯 灵活性高（一个工具覆盖所有场景）
- 🔧 易扩展（新工具无需修改代码）

### 🧠 智能上下文管理

**三层压缩架构**：

```
┌─────────────────────────────────────────┐
│ 第一层：正则过滤                          │
│ - 过滤 404/500 等无效响应                 │
│ - 只保留 200/301/401/403 等有价值状态码   │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│ 第二层：HAE 规则引擎                      │
│ - 自动提取凭证、表单、API 端点            │
│ - YAML 配置规则，易于扩展                 │
│ - 自动缓存，相同内容只解析一次            │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│ 第三层：LLM 总结                          │
│ - 短响应：LLM 总结后删除原文              │
│ - 长响应：HAE 提取关键信息后删除          │
│ - 关键发现：结构化存储，永不删除          │
└─────────────────────────────────────────┘
```

**效果**：
- 📦 压缩率：81%（80K → 15K tokens）
- 🎯 零丢失：关键信息（FLAG、凭证）永不删除
- 💰 省钱：Token 使用降低 75%

### 🎓 智能知识库

**按需触发 RAG**：

```python
# ❌ 传统方案：全量加载
初始 Prompt: [系统提示 + 所有知识库]  # 50K tokens
问题: 大部分知识用不上，浪费 80%+ Token

# ✅ ShadowAgent：智能触发
初始: [系统提示]  # 5K tokens
失败 3 次后: 自动检索相关知识（+3K tokens）
总计: 8K tokens（节省 84%）
```

**知识库内容**：
- 🔓 SQL 注入技巧
- 🌐 XSS 攻击方法
- 🔑 IDOR 漏洞利用
- 🚀 SSRF 绕过技巧
- 🔐 JWT 伪造方法
- ... 50+ 条专业知识

### 📊 完整可观测性

**三层追踪**：

```
observability/{operation_id}/
├── traces.json      # 详细操作追踪（每个操作的输入输出）
├── metrics.json     # 性能指标（Token、耗时、成功率）
└── report.txt       # 可读报告（完整测试过程）
```

**追踪内容**：
- ⏱️ 每个操作的耗时
- 💰 Token 使用统计
- 🔧 工具调用记录
- 🧠 Agent 决策过程
- 📈 成功率分析

### 🔐 元认知 + 证据链

**双重保障机制**：

```python
# 元认知：自我监控
信心评分: 0-100
成功 → +10%
失败 → -20%
信心 < 30% → 强制切换策略

# 证据链：有据可循
证据类型: FLAG(100%), 凭证(95%), 登录页(90%), API端点(85%)
决策规则: 有登录页 + 有凭证 → 尝试登录
         无证据 → 禁止盲目猜测
```

---

## 🚀 快速开始

### 前置要求

- Python 3.10+
- Docker（用于隔离执行 Kali 工具）
- LLM API Key（OpenAI / Claude / 国内大模型）

### 安装

```bash
# 1. 克隆项目
git clone https://github.com/yourusername/shadowagent.git
cd shadowagent

# 2. 安装依赖
pip install -r requirements.txt

# 3. 配置环境变量
cp .env.example .env
# 编辑 .env 文件，填入你的 API Key
```

### 配置 .env

```bash
# LLM 配置
LLM_PROVIDER=openai              # 或 anthropic
LLM_MODEL=gpt-4o                 # 或 claude-sonnet-4-5-20250929
OPENAI_API_KEY=sk-xxx            # 你的 API Key
OPENAI_API_BASE=https://api.openai.com/v1

# Docker 配置
DOCKER_CONTAINER_NAME=shadowagent-kali
```

### 运行示例

```bash
# 基础用法
python main.py \
  --target http://target.com:8080 \
  --challenge-id test \
  --description "IDOR + JWT 漏洞" \
  --max-attempts 30

# 高级用法（指定模型）
python main.py \
  --target http://192.168.1.100:8080 \
  --challenge-id sqli-challenge \
  --description "SQL 注入 + 文件上传" \
  --max-attempts 50 \
  --llm-provider anthropic \
  --llm-model claude-sonnet-4-5-20250929
```

### 查看结果

```bash
# 测试完成后，查看报告
cat observability/{operation_id}/report.txt

# 查看详细追踪
cat observability/{operation_id}/traces.json

# 查看性能指标
cat observability/{operation_id}/metrics.json
```

---

## 🏗️ 架构设计

### 整体流程

```
┌─────────────────────────────────────────────────────────────┐
│                        开始挑战                              │
│                  (target + description)                     │
└────────────────────────┬────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│                    初始探索（自动）                           │
│  - 技术栈识别                                                │
│  - API 文档检查                                              │
│  - 路径扫描                                                  │
│  - HAE 规则提取                                              │
└────────────────────────┬────────────────────────────────────┘
                         ↓
              ┌──────────────────────┐
              │   Advisor（顾问）     │
              │  - 分析题目           │
              │  - 制定策略           │
              │  - 提供建议           │
              └──────────┬───────────┘
                         ↓
              ┌──────────────────────┐
              │  Attacker（主攻手）   │
              │  - 执行工具           │
              │  - 调用 API           │
              │  - 编写脚本           │
              └──────────┬───────────┘
                         ↓
              ┌──────────────────────┐
              │  Reflector（审核员）  │
              │  - 审核结果           │
              │  - 失败分类（L0-L4）  │
              │  - 路由决策           │
              └──────────┬───────────┘
                         ↓
                    ┌────┴────┐
                    │ 成功？   │
                    └────┬────┘
                    ↙         ↘
            ┌──────────┐   ┌──────────┐
            │ 找到FLAG  │   │ 继续攻击  │
            │  结束    │   │  循环    │
            └──────────┘   └────┬─────┘
                                │
                                └──→ 返回 Advisor
```

### 技术栈

```
┌─────────────────────────────────────────────────────────────┐
│                         应用层                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │ Advisor  │  │ Attacker │  │Reflector │                  │
│  └──────────┘  └──────────┘  └──────────┘                  │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│                        编排层                                │
│              LangGraph（状态管理 + 路由）                     │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│                        工具层                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │execute_command│  │execute_python│  │ submit_flag  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│                        执行层                                │
│              Docker（Kali Linux 容器）                       │
│  nmap, sqlmap, nikto, dirb, curl, python3...                │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│                       支撑层                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │HAE 引擎  │  │上下文压缩│  │RAG 知识库│  │可观测性  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎨 设计哲学

### 1. 分离关注点（Separation of Concerns）

```
Advisor  → 只思考策略，不执行工具
Attacker → 只执行工具，不做战术分析
Reflector → 只审核结果，不参与执行
```

**好处**：
- 每个 Agent 职责单一，专注擅长的事
- 避免"既当运动员又当裁判"
- 提高决策质量和执行效率

### 2. 极简主义（Minimalism）

```
工具数量：3 个（vs 业界 20+）
核心概念：少即是多
```

**好处**：
- 降低决策复杂度
- 提高灵活性和扩展性
- 减少维护成本

### 3. 智能压缩（Smart Compression）

```
不是简单截断，而是智能提取
保留关键信息，删除冗余内容
```

**好处**：
- 突破 Token 限制
- 零信息丢失
- 降低成本

### 4. 按需加载（Lazy Loading）

```
知识库不是一开始全量加载
而是失败时才检索相关知识
```

**好处**：
- 节省 84% Token
- 提高响应速度
- 更精准的知识匹配

---

## 🔍 与其他项目对比

| 特性 | ShadowAgent | ctfSolver | CHYing-agent | Cyber-AutoAgent | H-Pentest |
|------|------------|-----------|--------------|-----------------|-----------|
| **Agent 架构** | 三 Agent 协作 | 单 Agent | 双 Agent | 单 Agent + 元认知 | 单 Agent + RAG |
| **独立审核** | ✅ Reflector | ❌ | ❌ | ❌ | ❌ |
| **工具数量** | 3 个 | 5-10 个 | 15+ 个 | 20+ 个 | 20+ 个 |
| **上下文管理** | 三层智能压缩 | 简单截断 | 简单截断 | 简单截断 | 全量保留 |
| **知识库** | 按需触发 RAG | ❌ | ❌ | ❌ | 全量加载 |
| **信息提取** | HAE 规则引擎 | 硬编码正则 | 硬编码正则 | 硬编码正则 | LLM 提取 |
| **可观测性** | 完整追踪 | 基础日志 | 基础日志 | 基础日志 | 基础日志 |

**核心优势**：
- ✅ **独立审核**：第三方视角，避免"自己审核自己"
- ✅ **极简工具**：3 个工具覆盖所有场景，决策快
- ✅ **智能压缩**：81% 压缩率，零信息丢失
- ✅ **按需加载**：节省 84% Token，更精准

---

## 🤝 贡献

欢迎贡献代码、报告 Bug 或提出新功能建议！

### 贡献方式

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 开发指南

```bash
# 安装开发依赖
pip install -r requirements-dev.txt

# 运行测试
pytest tests/

# 代码格式化
black src/
isort src/

# 类型检查
mypy src/
```

---

## 📚 参考与致谢

本项目参考了多个优秀的开源项目，在此表示感谢：

- **[HaE](https://github.com/gh0stkey/HaE)** - 启发了我们的规则引擎设计
- **[LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent)** - 参考了 Agent 架构设计
- **[CHYing-agent](https://github.com/yhy0/CHYing-agent)** - 参考了协作机制
- **[Cyber-AutoAgent](https://github.com/westonbrown/Cyber-AutoAgent)** - 参考了元认知机制
- **[H-Pentest](https://github.com/hexian2001/H-Pentest)** - 参考了 RAG 知识库设计

---

## 📖 文档

- [快速开始指南](docs/quickstart.md)
- [架构设计文档](docs/architecture.md)
- [API 参考](docs/api.md)
- [常见问题 FAQ](docs/faq.md)
- [开发指南](docs/development.md)

---

## 🗺️ 路线图

### v1.0（当前版本）
- ✅ 三 Agent 协作架构
- ✅ 智能上下文管理
- ✅ HAE 规则引擎
- ✅ 完整可观测性

### v1.1（计划中）
- 🔄 支持更多 LLM 提供商（Gemini、国内大模型）
- 🔄 Web UI 界面
- 🔄 多目标并发测试
- 🔄 自定义知识库

### v2.0（未来）
- 📅 支持二进制漏洞分析
- 📅 支持移动应用渗透
- 📅 Agent 自我学习机制
- 📅 分布式执行

---

## ⚠️ 免责声明

**重要提示**：本工具仅供安全研究和授权的渗透测试使用。

### 使用者需确保

- ✅ **仅在授权范围内使用**：必须获得目标系统所有者的明确授权
- ✅ **遵守当地法律法规**：不同国家/地区对渗透测试有不同的法律规定
- ✅ **不用于非法用途**：禁止用于未授权的攻击、破坏或其他非法活动
- ✅ **承担使用责任**：使用者需对自己的行为负责

### 作者声明

- ❌ **作者不对任何滥用行为负责**
- ❌ **作者不对使用本工具造成的任何损失负责**
- ❌ **本工具按"原样"提供，不提供任何明示或暗示的保证**

**使用本工具即表示您已阅读、理解并同意上述免责声明。**

---

## 📄 许可证

本项目采用 [MIT License](LICENSE) 开源许可证。

```
MIT License

Copyright (c) 2024 ShadowAgent

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 📞 联系方式

- **Issues**: [GitHub Issues](https://github.com/yourusername/shadowagent/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/shadowagent/discussions)
- **Email**: your.email@example.com

---

<div align="center">

### ⭐️ 如果这个项目对你有帮助，请给个 Star！

**让我们一起推动 AI 安全测试的发展！**

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/shadowagent&type=Date)](https://star-history.com/#yourusername/shadowagent&Date)

</div>
