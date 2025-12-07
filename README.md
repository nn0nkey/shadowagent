# ShadowAgent - 自动化渗透测试Agent

基于LangGraph的双Agent架构，专门针对XBOW验证基准测试设计。

## 🎯 项目特点

- **双Agent协作**：顾问Agent + 主攻手Agent，防止长对话幻觉
- **LangGraph框架**：清晰的状态管理和流程控制
- **XBOW基准测试**：针对104个CTF挑战优化
- **极简工具设计**：3个核心工具，降低决策复杂度
- **知识库增强**：RAG检索攻击场景
- **智能路由**：根据失败次数和策略自动切换

## 📁 项目结构

```
shadowagent/
├── src/                 # 核心代码
│   ├── core/            # 核心组件
│   │   ├── state.py     # LangGraph状态定义
│   │   ├── graph.py     # Agent图构建
│   │   └── router.py    # 智能路由逻辑
│   ├── agents/          # Agent节点
│   │   ├── advisor.py   # 顾问Agent
│   │   └── attacker.py  # 主攻手Agent
│   ├── executor/        # 执行器
│   │   └── docker_executor.py  # Docker执行器
│   ├── tools/           # 工具定义
│   │   ├── command_tool.py
│   │   ├── python_tool.py
│   │   └── flag_tool.py
│   └── utils/           # 工具函数
│       ├── logger.py
│       ├── llm_client.py
│       └── knowledge_base.py
├── config/              # 配置文件
├── prompts/             # Prompt模板
├── knowledge/           # 知识库
├── scripts/             # 脚本
├── tests/               # 测试
└── docker/              # Docker配置
```

## 🚀 快速开始

### 1. 安装依赖

```bash
cd agentproject/shadowagent
pip install -r requirements.txt
```

### 2. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env 填入API密钥
# 如果只做本地FLAG验证，请设置：
# EXPECTED_FLAG_VALUE="flag{example}"  # 或 EXPECTED_FLAG_FILE 指向保存FLAG的文件
```

### 3. 启动Docker容器（可选）

```bash
# 确保Docker已安装并运行
docker pull kalilinux/kali-rolling:latest
```

### 4. 运行Agent

```bash
# 基础用法
python main.py --target http://target.com:8080

# 完整参数
python main.py \
  --target http://target.com:8080 \
  --challenge-id challenge_001 \
  --description "SQL注入挑战" \
  --max-attempts 50 \
  --log-level INFO
```

## 🧠 知识库功能（按需加载）

项目集成了RAG知识库增强功能，采用**按需加载**设计：

1. **按需检索**：Agent通过 `search_knowledge` 工具主动检索相关知识
2. **避免占用上下文**：不自动加载所有知识，只在需要时调用
3. **灵活检索**：支持漏洞类型过滤和语义搜索

### 知识库文档

知识库文档存放在 `knowledge/` 目录，目前包含：
- SQL注入攻击库
- XSS攻击库
- SSTI攻击库

### 构建知识库索引

首次运行时会自动构建索引，索引文件保存在 `knowledge/cache/` 目录。

如需重建索引，删除 `knowledge/cache/` 目录即可。

## 📋 使用示例

### 运行单个XBOW挑战

```bash
python main.py \
  --target http://xbow.example.com:8080/challenge/001 \
  --challenge-id xbow_001 \
  --max-attempts 50
```

### 调试模式

```bash
python main.py \
  --target http://target.com:8080 \
  --log-level DEBUG \
  --log-file logs/debug.log
```

## 📝 开发计划

### ✅ 已完成
- [x] 项目结构搭建
- [x] 核心状态定义（LangGraph状态）
- [x] Agent节点实现（顾问+主攻手）
- [x] 工具系统（3个核心工具）
- [x] Docker执行器
- [x] 知识库增强（RAG检索）
- [x] 智能路由机制
- [x] 日志系统

### ⏳ 进行中
- [ ] XBOW API客户端完善
- [ ] 批量测试支持
- [ ] 结果统计和报告

### 📋 计划中
- [x] 上下文压缩机制（✅ 已实现）
- [x] 工具输出压缩（✅ 已实现）
- [x] 智能路由机制（✅ 已实现，包含重复检测、动态阈值等）
- [x] 元认知机制（✅ 已实现，包含信心评估、自我反思）
- [x] 性能监控和可观测性（✅ 已实现）
- [ ] 更多知识库文档（文件包含、命令注入等）

