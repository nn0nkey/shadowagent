# 学习 LuaN1ao Agent（第三名）

## 📊 项目概况

**LuaN1ao（鸾鸟）** - 认知驱动的 AI 黑客
- **排名**：第三名
- **核心理念**：像人类专家一样思考
- **架构**：P-E-R (Planner-Executor-Reflector)

## 🎯 核心创新（值得学习）

### 1. P-E-R 智能体协同框架 ⭐⭐⭐

**三个独立且协作的认知角色**：

#### 🧠 Planner（规划器）- 战略层
```
职责：
- 基于全局图谱进行动态规划
- 识别死胡同，自动生成备选路径
- 输出结构化的图编辑指令（而非自然语言）
- 基于拓扑依赖自动识别可并行任务

关键点：
✅ 不输出自然语言，而是图操作指令
✅ 自动识别并行路径
✅ 动态调整计划
```

#### ⚙️ Executor（执行器）- 战术层
```
职责：
- 专注于单一子任务的工具调用
- 通过 MCP 协议统一调度安全工具
- 智能管理消息历史，避免 token 溢出
- 自动处理网络错误和工具调用失败

关键点：
✅ 只关注当前任务
✅ 上下文压缩
✅ 容错重试
```

#### ⚖️ Reflector（反思器）- 审计层
```
职责：
- 复盘任务执行，验证产出物有效性
- L1-L4 级失败模式分析
- 提取攻击情报，构建知识积累
- 判断目标达成或任务陷入困境

关键点：
✅ 失败归因（4个级别）
✅ 情报生成
✅ 终止控制
```

**vs ShadowAgent**：
| 维度 | ShadowAgent | LuaN1ao |
|------|-------------|---------|
| **架构** | Advisor + Attacker | Planner + Executor + Reflector |
| **规划** | 自然语言建议 | 结构化图操作 |
| **反思** | 顾问分析 | 独立反思器 |
| **并行** | 无 | 自动识别并行任务 ⭐ |

### 2. 因果图谱推理（Causal Graph Reasoning）⭐⭐⭐

**核心原则**：
```
Evidence（证据）→ Hypothesis（假设）→ Vulnerability（漏洞）→ Exploit（利用）
```

**示例**：
```
Evidence: 端口扫描发现 3306/tcp 开放
  ↓ (置信度 0.8)
Hypothesis: 目标运行 MySQL 服务
  ↓ (验证成功)
Vulnerability: MySQL 弱口令/未授权访问
  ↓ (尝试利用)
Exploit: mysql -h target -u root -p [爆破/空密码]
```

**关键特性**：
- ✅ 证据必须先行
- ✅ 置信度量化
- ✅ 完整可追溯
- ✅ 防止幻觉

**vs ShadowAgent**：
- ShadowAgent 有 Proof Pack 证据标准
- 但没有显式的因果图谱
- **可以借鉴**：构建 Evidence → Hypothesis → Vulnerability 的图谱

### 3. Plan-on-Graph（PoG）基于图的动态任务规划 ⭐⭐⭐

**核心思想**：将渗透测试计划建模为**有向无环图（DAG）**

**图操作语言**：
```python
ADD_NODE: 添加新任务节点
UPDATE_NODE: 更新节点状态
DEPRECATE_NODE: 废弃无效路径
```

**动态自适应**：
```
发现新端口 → 自动挂载服务扫描子图
遇到 WAF → 插入绕过策略节点
路径不通 → 自动修剪或分支规划
```

**状态机**：
```
pending → in_progress → completed
                      → failed
                      → deprecated
```

**vs 传统 Task List**：
| 特性 | 传统 Task List | Plan-on-Graph |
|------|----------------|---------------|
| 结构 | 线性列表 | 有向图谱 ⭐ |
| 依赖管理 | 手动排序 | 拓扑自动排序 ⭐ |
| 并行能力 | 无 | 自动识别并行路径 ⭐ |
| 动态调整 | 重新生成 | 局部图编辑 ⭐ |
| 可视化 | 困难 | 原生支持 (Web UI) ⭐ |

**vs ShadowAgent**：
- ShadowAgent 是线性执行
- **可以借鉴**：引入任务图谱，支持并行执行

## 🛠️ 工具集成（MCP Protocol）

**Model Context Protocol（MCP）**：
```
- HTTP/HTTPS 请求
- Shell 命令执行
- Python 代码执行
- 元认知工具：think, hypothesize, reflect
- 任务控制：halt_task
```

**扩展性**：
- 通过 `mcp.json` 轻松集成新工具
- 支持 Metasploit、Nuclei、Burp Suite API

**vs ShadowAgent**：
- ShadowAgent 直接定义工具
- **可以借鉴**：使用 MCP 协议统一工具接口

## 🌐 Web 可视化

**功能**：
- 实时监控任务图谱的动态演化
- 点击节点查看执行日志、产出物、状态转换
- 可视化并行任务执行和依赖关系

**vs ShadowAgent**：
- ShadowAgent 只有文本报告
- **可以借鉴**：添加 Web UI 可视化

## 🤝 人机协同（HITL）模式

**功能**：
- 智能体在生成计划后暂停，等待人类审批
- 专家可以拒绝或直接修改计划
- 支持通过 Web UI 实时注入新的子任务

**交互方式**：
- Web UI：审批模态框自动弹出
- CLI：提示符 `HITL >`，输入 y/n/m

**vs ShadowAgent**：
- ShadowAgent 没有人机协同
- **可以借鉴**：添加审批机制

## 📂 项目结构

```
LuaN1aoAgent/
├── agent.py              # 主控入口（P-E-R 循环）
├── core/
│   ├── planner.py        # 规划器
│   ├── executor.py       # 执行器
│   ├── reflector.py      # 反思器
│   ├── graph_manager.py  # 图谱管理
│   ├── events.py         # 事件总线
│   └── prompts/          # Prompt 模板
├── tools/
│   └── mcp_client.py     # MCP 工具客户端
├── rag/                  # 知识增强
├── web/                  # Web 可视化
└── conf/                 # 配置管理
```

## 💡 可以借鉴的设计

### 1. 三角色分离 ⭐⭐⭐
```
当前：Advisor + Attacker
改进：Planner + Executor + Reflector

优势：
- 职责更清晰
- 避免"精神分裂"
- 独立的反思器
```

### 2. 任务图谱 ⭐⭐⭐
```
当前：线性执行
改进：DAG 任务图

优势：
- 支持并行执行
- 动态调整计划
- 可视化进度
```

### 3. 因果图谱 ⭐⭐
```
当前：Proof Pack（文本）
改进：显式的因果图谱

优势：
- 更强的可追溯性
- 置信度量化
- 防止幻觉
```

### 4. 失败分级 ⭐⭐
```
当前：简单的成功/失败
改进：L1-L4 失败模式

L1: 工具调用失败（网络错误）
L2: 策略选择错误（方向错误）
L3: 假设验证失败（推理错误）
L4: 目标不可达（任务终止）
```

### 5. Web 可视化 ⭐⭐
```
当前：文本报告
改进：实时 Web UI

功能：
- 任务图谱可视化
- 实时进度监控
- 节点详情查看
```

### 6. MCP 协议 ⭐
```
当前：直接定义工具
改进：MCP 统一接口

优势：
- 更好的扩展性
- 标准化接口
- 易于集成新工具
```

## 🚫 不适合借鉴的部分

### 1. 过于复杂的架构
- 三个 Agent 可能增加通信开销
- 对于简单任务可能过度设计

### 2. 图谱管理开销
- 维护 DAG 需要额外计算
- 小规模任务可能不划算

### 3. Web UI 维护成本
- 需要额外的前端开发
- 增加部署复杂度

## 📝 总结

### LuaN1ao 的优势
1. ✅ **P-E-R 架构**：职责清晰，避免混乱
2. ✅ **任务图谱**：支持并行，动态调整
3. ✅ **因果推理**：防止幻觉，可追溯
4. ✅ **Web 可视化**：实时监控，易于调试
5. ✅ **人机协同**：专家审批，安全可控

### ShadowAgent 可以借鉴
1. **高优先级**：
   - 独立的反思器（Reflector）
   - 失败分级（L1-L4）
   - 因果图谱（Evidence → Hypothesis → Vulnerability）

2. **中优先级**：
   - 任务图谱（DAG）
   - 并行执行
   - Web 可视化

3. **低优先级**：
   - MCP 协议
   - 人机协同

### 实施建议
1. **第一步**：添加独立的 Reflector Agent
2. **第二步**：实现失败分级（L1-L4）
3. **第三步**：构建简单的因果图谱
4. **第四步**：考虑任务图谱和并行执行

---

LuaN1ao 是一个非常优秀的项目，特别是 P-E-R 架构和任务图谱的设计值得深入学习！
