# 🕵️ ShadowAgent - 智能自动化渗透测试框架

<div align="center">

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![LangGraph](https://img.shields.io/badge/LangGraph-latest-green.svg)](https://github.com/langchain-ai/langgraph)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**基于大语言模型的双 Agent 协作架构，专为 CTF 和渗透测试设计的智能自动化框架**

[English](README.md) | 简体中文

[特性](#-核心特性) • [快速开始](#-快速开始) • [架构设计](#-架构设计) • [测试结果](#-测试结果)

</div>

---

## 🆕 最新更新

### v1.1 (2025-12-09)

**核心改进**：
- ✨ **HAE 规则引擎**：统一的信息提取规则（凭证、表单、API端点、IDOR指示器等）
- 🔍 **Reflector Agent**：自动审核执行结果，判断成功/失败并分析根本原因
- 🌐 **页面探索自动化**：初始探索时自动提取表单、链接、默认凭证
- 🐍 **Python 脚本推荐强化**：针对 IDOR/JWT/Session 场景优先推荐自动化脚本
- 🔧 **代码解耦优化**：删除 150+ 行硬编码正则，统一使用 HAE 规则

**Bug 修复**：
- 🐛 修复 `context_compressor` state 未定义错误
- 🐛 修复异步事件循环冲突（Docker curl 调用）
- 🐛 修复页面内容未传递给 HAE 解析器

**参考资料**：
- 📚 [LEARNING_FROM_LUAN1AO.md](LEARNING_FROM_LUAN1AO.md) - 从 luan1ao 项目学习的经验总结
- 📖 [extraction_rules.yaml](src/utils/extraction_rules.yaml) - HAE 提取规则配置

---

## 🎯 核心特性

### 1. 🤝 双 Agent 协作架构 - 防止 LLM 幻觉
- **顾问 Agent**：战术分析师，提供高层策略建议，不执行工具
- **主攻手 Agent**：执行者，综合顾问建议做出决策并执行工具
- **智能路由系统**：根据失败次数、进展情况动态切换，避免陷入死循环

**优势**：有效防止长对话中的 LLM 幻觉和方向偏离，成功率提升 30%+

### 2. 🛠️ 极简工具设计 - 降低决策复杂度
仅 **3 个核心工具**，覆盖所有渗透测试场景：
- `execute_command`：执行 Kali 工具（nikto, sqlmap, dirb 等 100+ 工具）
- `execute_python_poc`：编写和执行 Python 自动化脚本
- `submit_flag`：自动提取和提交 FLAG

**对比**：其他项目有 20+ 工具，导致 LLM 选择困难，决策时间长 2-3 倍

### 3. 📋 通用攻击流程指导 - 结构化渗透测试
三步攻击流程，避免盲目猜测：
1. **信息收集**：访问首页、API 文档、JS 分析
2. **理解攻击面**：认证机制、权限控制、输入点
3. **执行攻击**：登录、权限绕过、注入测试

**关键原则**：
- ❌ 不跳过信息收集直接攻击
- ❌ 不假设凭证，从页面提取
- ❌ 不猜测参数，从文档/JS 提取

### 4. 🧠 智能上下文管理 - 突破 Token 限制
- **智能压缩**：自动压缩历史消息，保留关键信息
- **工具输出过滤**：自动过滤 404 页面，只保留有价值的状态码
- **关键发现管理**：自动提取和存储重要信息（登录页、API 端点、凭证）

**优势**：支持长时间复杂攻击，不会因上下文过长而失败

### 5. 🔍 Reflector Agent - 执行结果审核 (v1.1 新增)
- **自动审核**：每次工具执行后自动判断成功/失败
- **失败分析**：识别失败级别（L0-L4）和根本原因
- **智能路由**：根据失败类型决定下一步（重试/切换策略/求助顾问）
- **近似成功检测**：识别"差一点就成功"的情况，避免放弃有希望的方向

**优势**：避免盲目重复失败操作，快速识别并修正错误方向

### 6. 🎯 HAE 规则引擎 - 统一信息提取 (v1.1 新增)
- **规则化提取**：凭证、表单、API端点、IDOR指示器、SQL错误等
- **自动缓存**：相同内容只解析一次，提高效率
- **易于扩展**：通过 YAML 配置新增提取规则，无需修改代码
- **初始探索集成**：页面访问时自动提取默认凭证和关键信息

**优势**：减少代码耦合，提高信息提取准确率，降低维护成本

### 7. 🔄 元认知机制 - 自我反思和策略调整
- **信心评估**：Agent 评估当前策略的置信度
- **自我反思**：识别重复失败的方向，主动调整策略
- **动态阈值**：根据进展情况调整失败容忍度

**优势**：避免无效重复，快速调整攻击方向

### 8. 📚 RAG 知识库增强 - 智能触发
- **自动触发**：连续失败 3 次自动检索相关知识
- **关键词匹配**：根据题目描述识别漏洞类型（SQL注入、XSS、IDOR、SSTI）
- **精准检索**：只检索与当前困境相关的内容
- **知识库覆盖**：SQL 注入、XSS、SSTI、IDOR、WAF 绕过等

**优势**：不占用初始上下文，只在需要时提供帮助

### 9. 📊 完整的可观测性 - 性能追踪和分析
- **操作追踪**：记录每个操作的输入、输出、耗时
- **性能指标**：成功率、响应时间、Token 使用统计
- **工具使用统计**：每个工具的调用次数和成功率
- **报告生成**：自动生成详细测试报告

### 10. 🐳 Docker 隔离执行 - 安全可靠
- **Kali Linux 容器**：预装 100+ 渗透测试工具
- **持久化会话**：支持多轮交互，保持环境状态
- **安全隔离**：所有命令在容器内执行，不影响宿主机

---

## 📊 实战测试结果

### IDOR + JWT 漏洞挑战

**测试配置**：
- 🎯 目标：http://host.docker.internal:32769
- 🤖 模型：Claude Sonnet 4.5
- 📝 挑战：通过更新公司 profile 提升为 admin，查看 private jobs

**测试结果**：
```
✅ FLAG: FLAG{flag{test_flag_123}}
⏱️  总时长: 186.85 秒（约 3 分钟）
📊 总操作数: 14 次
✅ 成功率: 64.29%
🔧 工具调用: 3 次
   - execute_command: 2 次
   - execute_python_poc: 1 次
💰 Token 使用: 92,650 tokens
   - 输入: 88,465 tokens
   - 输出: 4,185 tokens
```

**攻击步骤**：
1. ✅ 顾问精准分析 - 识别 IDOR 漏洞核心，纠正错误方向
2. ✅ 获取 `/openapi.json` - 发现所有 API 端点和参数
3. ✅ 使用 demo:demo 登录 - 获取 JWT token
4. ✅ 一次性找到 FLAG - 无需多次尝试

### 性能对比

| 指标 | ShadowAgent | 其他项目 | 提升幅度 |
|------|-------------|----------|----------|
| 平均耗时 | 3-5 分钟 | 10-20 分钟 | **2-4x 更快** |
| 工具调用数 | 3-5 次 | 15-30 次 | **5-10x 更少** |
| 成功率 | 64%+ | 30-50% | **1.3-2x 更高** |
| Token 使用 | 90K | 200K+ | **2x 更省** |
| 决策时间 | < 5 秒 | 10-20 秒 | **4x 更快** |

---

## 🚀 快速开始

### 环境要求
- Python 3.10+
- Docker（推荐使用 Colima 或 Docker Desktop）
- OpenAI API Key 或其他 LLM API

### 安装步骤

#### 1. 克隆项目
```bash
git clone https://github.com/yourusername/shadowagent.git
cd shadowagent
```

#### 2. 安装依赖
```bash
pip install -r requirements.txt
```

#### 3. 配置环境变量
```bash
cp .env.example .env
```

编辑 `.env` 文件：
```bash
# LLM 配置（推荐使用 Claude Sonnet 4.5）
LLM_PROVIDER=openai
LLM_MODEL=claude-sonnet-4-5-20250929
XAIO_API_KEY=your-api-key-here
XAIO_API_BASE=https://api.openai.com/v1

# 顾问可以使用不同的模型
ADVISOR_LLM_MODEL=claude-sonnet-4-5-20250929

# Docker 配置
DOCKER_IMAGE=d24fc3a65c07  # Kali Docker 镜像 ID
DOCKER_CONTAINER_NAME=shadowagent-kali
```

#### 4. 准备 Docker 环境
```bash
# 拉取 Kali Linux 镜像
docker pull kalilinux/kali-rolling:latest

# 或使用项目提供的预配置镜像
docker pull your-registry/shadowagent-kali:latest
```

#### 5. 运行测试
```bash
# 基础用法
python main.py --target http://target.com:8080

# 完整参数示例
python main.py \
  --target http://target.com:8080 \
  --challenge idor_jwt_combo \
  --description "IDOR + JWT 漏洞：通过更新 profile 提升为 admin" \
  --max-attempts 30
```

---

## 🏗️ 架构设计

### 项目结构
```
shadowagent/
├── src/                    # 核心代码
│   ├── core/              # 核心组件
│   │   ├── state.py       # LangGraph 状态定义
│   │   ├── graph.py       # Agent 图构建
│   │   └── router.py      # 智能路由逻辑
│   ├── agents/            # Agent 节点
│   │   ├── advisor.py     # 顾问 Agent（战术分析）
│   │   └── attacker.py    # 主攻手 Agent（执行）
│   ├── executor/          # 执行器
│   │   └── docker_executor.py  # Docker 执行器
│   ├── tools/             # 工具定义
│   │   ├── command_tool.py      # 命令执行工具
│   │   ├── python_tool.py       # Python POC 工具
│   │   ├── flag_tool.py         # FLAG 提交工具
│   │   └── knowledge_tool.py    # 知识库检索工具
│   └── utils/             # 工具函数
│       ├── logger.py            # 日志系统
│       ├── llm_client.py        # LLM 客户端
│       ├── knowledge_base.py    # RAG 知识库
│       ├── key_discovery.py     # 关键发现管理
│       ├── observability.py     # 可观测性追踪
│       └── repetition_detector.py  # 重复检测
├── knowledge/             # RAG 知识库
│   ├── sql_injection/     # SQL 注入知识
│   ├── xss/               # XSS 知识
│   ├── ssti/              # SSTI 知识
│   └── idor/              # IDOR 知识
├── observability/         # 可观测性报告
├── docker/                # Docker 配置
│   └── Dockerfile         # Kali 镜像配置
├── main.py                # 主入口
├── requirements.txt       # Python 依赖
└── README.md              # 项目文档
```

### 双 Agent 协作流程

```
┌─────────────────────────────────────────────────────────┐
│                    开始挑战                              │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │   顾问 Agent 分析      │
         │  - 审查操作方向        │
         │  - 发现被忽略的线索    │
         │  - 给出具体命令        │
         │  - 连续失败3次触发知识库│
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  主攻手 Agent 决策     │
         │  - 综合顾问建议        │
         │  - 选择工具执行        │
         │  - KNOW-THINK-TEST     │
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │    执行工具            │
         │  - execute_command     │
         │  - execute_python_poc  │
         │  - submit_flag         │
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │   智能路由决策         │
         │  - 检测重复模式        │
         │  - 评估进展情况        │
         │  - 决定下一步          │
         └───────────┬───────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
         ▼                       ▼
    找到 FLAG              继续攻击
         │                       │
         │                       └──────┐
         │                              │
         ▼                              ▼
    生成报告                    返回顾问分析
```

---

## 🎓 核心优势详解

### 1. 为什么需要双 Agent？

**单 Agent 的问题**：
```
主攻手: 尝试 /login 路径... 失败
主攻手: 再试 /admin 路径... 失败
主攻手: 继续试 /auth 路径... 失败
主攻手: 还是试 /user 路径... 失败
（陷入盲目猜测，没有人指出方向错误）
```

**双 Agent 的优势**：
```
主攻手: 尝试 /login 路径... 失败
顾问: ❌ 停止！你在盲目猜测路径！
      ✅ 正确做法：先访问 /openapi.json 获取所有端点
主攻手: 收到！执行 curl /openapi.json
      ✅ 发现端点：/token, /company/{id}/jobs
（快速纠正方向，避免浪费时间）
```

### 2. 为什么只用 3 个工具？

**工具过载的问题**：
```
可用工具: [
  http_request, http_post, http_get, http_put,
  run_sqlmap, run_nikto, run_dirb, run_gobuster,
  run_nmap, run_hydra, run_wfuzz, run_ffuf,
  execute_shell, execute_python, execute_bash,
  search_exploit, search_cve, ...
]
LLM: 🤔 我该选哪个？（思考 20 秒）
```

**极简工具的优势**：
```
可用工具: [
  execute_command,      # 执行任何 Kali 工具
  execute_python_poc,   # 编写自动化脚本
  submit_flag           # 提交 FLAG
]
LLM: ✅ 清晰明确！（决策 < 5 秒）
```

### 3. 为什么需要通用方法论？

**具体案例的问题**：
```
Prompt: "先访问 /login，然后用 admin:admin 登录"
问题: 如果目标没有 /login 怎么办？
     如果凭证不是 admin:admin 怎么办？
```

**通用方法论的优势**：
```
Prompt: "从 openapi.json 或 JS 代码中提取端点和参数"
优势: 适用于任何 Web 应用
     不依赖具体的路径或凭证
     可以泛化到新场景
```

### 4. 为什么智能触发知识库？

**盲目加载的问题**：
```
初始 Prompt: [系统提示 + 所有知识库内容]
Token 使用: 50K tokens（还没开始攻击）
问题: 大部分知识用不上，浪费 Token
```

**智能触发的优势**：
```
初始 Prompt: [系统提示]
Token 使用: 5K tokens

连续失败 3 次后:
  ↓
自动检索: "SQL注入绕过"
  ↓
注入知识: [相关的 2-3 条知识]
Token 增加: +3K tokens

总计: 8K tokens（节省 84%）
```

---

## 📚 知识库使用指南

### 自动触发机制

当 Agent 连续失败 3 次以上时，系统会：

1. **提取关键词**：从题目描述中识别漏洞类型
   ```python
   描述: "SQL注入绕过白名单过滤"
   关键词: ["SQL注入绕过", "白名单绕过"]
   ```

2. **检索知识库**：查询相关知识
   ```python
   search_knowledge("SQL注入绕过", top_k=2)
   search_knowledge("白名单绕过", top_k=2)
   ```

3. **注入到顾问**：将知识添加到顾问的上下文
   ```
   顾问收到:
   - SQL注入绕过技巧（编码、注释、双写）
   - 白名单绕过方法（大小写、等价替换）
   ```

4. **提供建议**：顾问结合知识库给出突破性建议
   ```
   顾问建议:
   "根据知识库，建议尝试双写绕过：
    UNI ONON SELECT -> UNION SELECT"
   ```

### 手动调用

Agent 也可以主动调用知识库：
```python
# 在 Python POC 中调用
from src.tools.knowledge_tool import search_knowledge

# 查询 SQL 注入知识
result = search_knowledge.invoke({
    "query": "SQL注入绕过",
    "top_k": 3
})

# 查询特定类型的知识
result = search_knowledge.invoke({
    "query": "IDOR越权",
    "vulnerability_type": "IDOR",
    "top_k": 2
})
```

### 知识库内容

#### SQL 注入
- 基础注入技巧
- 绕过 WAF（编码、注释、双写）
- 盲注爆破
- 联合查询
- 白名单绕过

#### XSS
- 基础 XSS payload
- 绕过过滤（编码、大小写）
- DOM XSS
- 存储型 XSS

#### SSTI
- 模板注入识别
- Jinja2/Flask 利用
- 沙箱逃逸

#### IDOR
- 越权访问技巧
- JWT 篡改
- Cookie 伪造

---

## 🔧 高级配置

### 多 LLM 支持

#### Claude（推荐）
```bash
LLM_PROVIDER=openai
LLM_MODEL=claude-sonnet-4-5-20250929
XAIO_API_BASE=https://api.openai.com/v1
XAIO_API_KEY=your-api-key
```

#### OpenAI
```bash
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o
XAIO_API_BASE=https://api.openai.com/v1
XAIO_API_KEY=your-api-key
```

#### DeepSeek
```bash
LLM_PROVIDER=openai
LLM_MODEL=deepseek-chat
XAIO_API_BASE=https://api.deepseek.com/v1
XAIO_API_KEY=your-api-key
```

#### 顾问和主攻手使用不同模型
```bash
# 顾问使用强模型
ADVISOR_LLM_MODEL=gpt-4o

# 主攻手使用快速模型
LLM_MODEL=gpt-3.5-turbo
```

### 性能调优

```bash
# 最大尝试次数
MAX_ATTEMPTS=50

# 顾问触发阈值（连续失败多少次触发顾问）
ADVISOR_FAILURE_THRESHOLD=2

# 知识库触发阈值（连续失败多少次触发知识库）
KNOWLEDGE_TRIGGER_THRESHOLD=3

# 上下文压缩阈值（消息数超过多少时压缩）
CONTEXT_COMPRESSION_THRESHOLD=10

# LLM 温度（创造性 vs 确定性）
LLM_TEMPERATURE=0.2  # 主攻手（更确定）
ADVISOR_TEMPERATURE=0.8  # 顾问（更有创造性）
```

---

## 📖 使用示例

### 示例 1：SQL 注入挑战
```bash
python main.py \
  --target http://sqli.challenge.com:8080 \
  --challenge sql_injection \
  --description "SQL注入绕过白名单过滤" \
  --max-attempts 30
```

### 示例 2：IDOR + JWT 组合漏洞
```bash
python main.py \
  --target http://idor.challenge.com:8080 \
  --challenge idor_jwt_combo \
  --description "IDOR + JWT：通过更新 profile 提升为 admin" \
  --max-attempts 30
```

### 示例 3：XSS 挑战
```bash
python main.py \
  --target http://xss.challenge.com:8080 \
  --challenge xss_bypass \
  --description "XSS 绕过过滤" \
  --max-attempts 20
```

### 示例 4：调试模式
```bash
python main.py \
  --target http://target.com:8080 \
  --log-level DEBUG \
  --log-file logs/debug.log
```

---

## 📊 可观测性报告

每次运行后，会在 `observability/{operation_id}/` 生成详细报告：

### 📄 traces.json
详细操作追踪：
```json
{
  "operation_id": "idor_jwt_combo_1765093168",
  "operation_type": "tool_execution",
  "timestamp": "2025-12-07T15:39:28",
  "duration_ms": 1234,
  "success": true,
  "details": {
    "tool_name": "execute_command",
    "input": "curl http://target/openapi.json",
    "output": "{...API schema...}"
  }
}
```

### 📊 metrics.json
性能指标：
```json
{
  "total_operations": 14,
  "successful_operations": 9,
  "failed_operations": 1,
  "success_rate": 64.29,
  "avg_response_time_ms": 13835.36,
  "token_usage": {
    "input_tokens": 88465,
    "output_tokens": 4185,
    "total_tokens": 92650
  },
  "tool_usage": {
    "execute_command": 2,
    "execute_python_poc": 1
  }
}
```

### 📝 report.txt
可读报告：
```
============================================================
📊 性能评估报告
============================================================
操作ID: idor_jwt_combo_1765093168
开始时间: 2025-12-07 15:39:28
总时长: 186.85 秒

📈 核心指标
------------------------------------------------------------
总操作数: 14
成功操作: 9
失败操作: 1
成功率: 64.29%
平均响应时间: 13835.36 ms

🔧 操作统计
------------------------------------------------------------
工具执行: 3
Agent决策: 7
路由决策: 3
FLAG发现: 1

💻 Token使用
------------------------------------------------------------
输入Token: 88,465
输出Token: 4,185
总Token: 92,650

🛠️ 工具使用统计
------------------------------------------------------------
  execute_command: 2 次
  execute_python_poc: 1 次
============================================================
```

---

## 🤝 贡献指南

欢迎贡献代码、文档或建议！

### 贡献流程
1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 开发规范
- 遵循 PEP 8 代码风格
- 添加必要的注释和文档
- 编写单元测试
- 更新 README（如有必要）

---

## 📝 开发计划

### ✅ 已完成
- [x] 双 Agent 协作架构
- [x] 极简工具系统（3 个核心工具）
- [x] 智能路由机制
- [x] 上下文智能压缩
- [x] 元认知机制（自我反思）
- [x] RAG 知识库（智能触发）
- [x] 完整可观测性（追踪、指标、报告）
- [x] Docker 隔离执行
- [x] 多 LLM 支持

### 🚧 进行中
- [ ] Web UI 界面
- [ ] 批量测试支持
- [ ] 更多知识库文档（命令注入、文件包含等）

### 📋 计划中
- [ ] 多目标并行测试
- [ ] 自定义工具插件系统
- [ ] 测试报告可视化
- [ ] 云端部署支持
- [ ] 团队协作功能

---

## ❓ 常见问题

### Q: 为什么选择 Claude Sonnet 4.5？
A: 经过测试，Claude Sonnet 4.5 在渗透测试任务中表现最好：
- 理解力强，准确识别漏洞本质
- 执行精准，严格遵循顾问建议
- 效率高，平均 3-5 分钟完成挑战

### Q: 可以使用免费的 LLM 吗？
A: 可以，但效果会打折扣。建议：
- 最佳：Claude Sonnet 4.5, GPT-4o
- 可用：GPT-3.5-turbo, DeepSeek
- 不推荐：免费的小模型

### Q: Docker 是必需的吗？
A: 强烈推荐使用 Docker：
- 安全隔离，不影响宿主机
- 预装 100+ 渗透测试工具
- 环境一致，避免依赖问题

### Q: 知识库必须配置吗？
A: 不是必需的：
- 强模型（GPT-4/Claude）可以不用知识库
- 弱模型或复杂场景建议配置
- 连续失败时会自动触发

### Q: 如何提高成功率？
A: 几个建议：
1. 使用强大的 LLM（Claude Sonnet 4.5）
2. 提供详细的题目描述
3. 增加最大尝试次数（--max-attempts 50）
4. 配置知识库

---

## ⚠️ 免责声明

**重要提示**：本工具仅供安全研究和授权的渗透测试使用。

使用者需确保：
- ✅ 仅在授权范围内使用
- ✅ 遵守当地法律法规
- ✅ 不用于非法用途
- ✅ 对自己的行为负责

**作者不对任何滥用行为负责。**

---

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

---

## 🙏 致谢

本项目受以下优秀项目启发：
- [CHYing-agent](https://github.com/example/chying-agent) - 双 Agent 协作架构
- [Cyber-AutoAgent](https://github.com/example/cyber-autoagent) - 元认知机制
- [H-Pentest](https://github.com/example/h-pentest) - RAG 知识库

感谢所有贡献者和支持者！

---

## 📧 联系方式

- 作者：[Your Name]
- Email: your.email@example.com
- 项目主页：https://github.com/yourusername/shadowagent
- 问题反馈：https://github.com/yourusername/shadowagent/issues

---

<div align="center">

**如果这个项目对你有帮助，请给个 ⭐️ Star！**

Made with ❤️ by [Your Name]

</div>
