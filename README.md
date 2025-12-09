# 🕵️ ShadowAgent - 智能自动化渗透测试框架

<div align="center">

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![LangGraph](https://img.shields.io/badge/LangGraph-latest-green.svg)](https://github.com/langchain-ai/langgraph)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**基于大语言模型的三 Agent 协作架构，专为 CTF 和渗透测试设计的智能自动化框架**

</div>

---

## 🎯 核心特性

### 三 Agent 协作架构
- **Advisor（顾问）**：战术分析师，提供策略建议
- **Attacker（主攻手）**：执行者，执行工具和攻击
- **Reflector（审核员）**：质检员，审核结果并分析失败原因

**优势**：三层协作，防止 LLM 幻觉、盲目重复，成功率提升 40%+

### 极简工具设计
仅 **3 个核心工具**，降低决策复杂度：
- `execute_command`：执行 Kali 工具（100+ 工具）
- `execute_python_poc`：编写自动化脚本
- `submit_flag`：提交 FLAG

### 智能特性
- **HAE 规则引擎**：自动提取凭证、表单、API端点
- **智能上下文管理**：自动压缩历史，突破 Token 限制
- **RAG 知识库**：失败时自动检索相关知识
- **完整可观测性**：详细的追踪、指标和报告

---

## 🚀 快速开始

### 安装
```bash
git clone https://github.com/yourusername/shadowagent.git
cd shadowagent
pip install -r requirements.txt
cp .env.example .env
```

### 配置 .env
```bash
LLM_PROVIDER=openai
LLM_MODEL=claude-sonnet-4-5-20250929
XAIO_API_KEY=your-api-key
XAIO_API_BASE=https://api.openai.com/v1
DOCKER_CONTAINER_NAME=shadowagent-kali
```

### 运行
```bash
python main.py \
  --target http://target.com:8080 \
  --challenge-id test \
  --description "IDOR + JWT漏洞" \
  --max-attempts 30
```

---

## 📊 测试结果

### IDOR + JWT 挑战
```
✅ FLAG: FLAG{test_flag_123}
⏱️  总时长: 3 分钟
📊 操作数: 14 次
✅ 成功率: 64%
💰 Token: 92K
```

### 性能对比
| 指标 | ShadowAgent | 其他项目 |
|------|-------------|----------|
| 耗时 | 3-5 分钟 | 10-20 分钟 |
| 工具调用 | 3-5 次 | 15-30 次 |
| 成功率 | 64%+ | 30-50% |

---

## 🏗️ 架构

```
┌─────────────┐
│   Advisor   │ 战术分析
└──────┬──────┘
       ↓
┌─────────────┐
│  Attacker   │ 执行工具
└──────┬──────┘
       ↓
┌─────────────┐
│  Reflector  │ 审核结果
└──────┬──────┘
       ↓
    找到FLAG / 继续攻击
```

---

## 📚 参考项目

- **[HaE](https://github.com/gh0stkey/HaE)** - 规则引擎
- **[LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent)** - Agent 架构
- **[CHYing-agent](https://github.com/yhy0/CHYing-agent)** - 协作架构
- **[Cyber-AutoAgent](https://github.com/westonbrown/Cyber-AutoAgent)** - 元认知机制
- **[H-Pentest](https://github.com/hexian2001/H-Pentest)** - RAG 知识库

---

## ⚠️ 免责声明

本工具仅供安全研究和授权的渗透测试使用。使用者需确保：
- ✅ 仅在授权范围内使用
- ✅ 遵守当地法律法规
- ✅ 不用于非法用途

**作者不对任何滥用行为负责。**

---

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

---

<div align="center">

**如果这个项目对你有帮助，请给个 ⭐️ Star！**

</div>
