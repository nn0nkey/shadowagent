# ShadowAgent - 自动化渗透测试 Agent

基于 LangGraph 的双 Agent 协作架构，专门针对 CTF Web 挑战设计的智能渗透测试框架。

## 🎯 核心特性

### Agent 架构
- **双 Agent 协作**：顾问 Agent + 主攻手 Agent，防止长对话幻觉
- **智能路由系统**：根据失败次数和进展情况动态切换
- **Proof Pack 证据标准**：强制区分 VERIFIED 和 HYPOTHESIS，防止 AI 幻觉

### 工具与能力
- **极简工具设计**：仅 4 个核心工具（execute_command, execute_python_poc, submit_flag, search_knowledge）
- **自动化页面信息提取**：每次 HTTP 请求自动提取表单、链接、API 端点、参数、凭证
- **智能重复检测**：检测相似 payload、响应长度相同，3 次重复自动告警

### 增强功能
- **RAG 知识库**：按需检索攻击知识，连续失败自动触发
- **初始探索**：自动识别技术栈、API 文档、常见路径
- **完整可观测性**：操作追踪、性能指标、Token 统计

## 🚀 快速开始

### 1. 环境准备

```bash
# 克隆项目
git clone https://github.com/yourusername/shadowagent.git
cd shadowagent

# 安装依赖
pip install -r requirements.txt

# 启动 Docker 容器（Kali Linux 工具环境）
cd docker/kali
docker-compose up -d
```

### 2. 配置环境变量

```bash
# 复制配置模板
cp .env.example .env

# 编辑 .env，填入 LLM API 配置
# 支持 OpenAI、Gemini、魔塔社区等
```

**配置示例**：
```bash
LLM_PROVIDER=openai
LLM_MODEL=deepseek-ai/DeepSeek-V3.2
OPENAI_API_BASE=https://api-inference.modelscope.cn/v1/
OPENAI_API_KEY=your_api_key_here
```

### 3. 运行测试

```bash
# 基本用法
python main.py --target http://target.com:8080 --challenge-id test1

# 指定描述和最大尝试次数
python main.py \
  --target http://target.com:8080 \
  --challenge-id idor_test \
  --description "IDOR+JWT 组合漏洞" \
  --max-attempts 50
```

### 4. 查看结果

```bash
# 查看报告
cat observability/your_challenge_id_*/report.txt

# 查看详细追踪
cat observability/your_challenge_id_*/traces.json
```

## 📁 项目结构

```
shadowagent/
├── src/                 # 核心代码
│   ├── agents/          # Agent 节点
│   ├── tools/           # 工具定义
│   └── utils/           # 工具函数
├── knowledge/           # 知识库
├── prompts/             # Prompt 模板
└── main.py              # 主入口
```

## 🙏 致谢

参考了以下优秀项目：
- [CHYing-agent](https://github.com/Mgrsc/CHYing-agent)
- [Cyber-AutoAgent](https://github.com/Esonhugh/Cyber-AutoAgent)
- [H-Pentest](https://github.com/Esonhugh/H-Pentest)

## 📧 联系方式

QQ: 2403635670

## 📄 许可证

MIT License

## ⚠️ 免责声明

本工具仅供安全研究和授权的渗透测试使用。使用者需确保在授权范围内使用，遵守当地法律法规。作者不对任何滥用行为负责。
