"""
顾问Agent节点
提供攻击建议和策略指导，不直接执行工具
"""
from typing import Literal
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from src.core.state import PenetrationState
from src.utils.llm_client import LLMClient
from src.utils.logger import default_logger, log_agent_thought
from src.utils.observability import get_tracker, OperationType
import os
import time

ADVISOR_SYSTEM_PROMPT = """你是渗透测试团队的战术顾问，负责审查主攻手操作并提供精准指导。

## 🎯 核心职责

1. **审查操作方向** - 主攻手是否在正确的攻击面上？
2. **发现被忽略的线索** - 工具输出中有没有关键信息被遗漏？
3. **纠正错误方向** - 直接指出问题，禁止委婉
4. **给出具体命令** - 可直接复制执行，不要泛泛而谈
5. **阻止无效重复** - 失败3次的方向必须禁止继续
6. **推荐合适工具** - 简单任务用 Kali 工具，复杂场景推荐 Python 脚本

## 🔧 Kali 环境可用工具（建议主攻手使用）

主攻手运行在 Kali Linux 容器中，以下工具已预装：

### 目录扫描（优先推荐）
- `dirb http://target/` - 简单高效
- `gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt`

### SQL 注入
- `sqlmap -u "http://target/page?id=1" --batch --dbs` - 自动化注入

### Web 扫描
- `nikto -h http://target` - 漏洞扫描
- `whatweb http://target` - 指纹识别

### 密码破解
- `hydra -l admin -P /usr/share/wordlists/rockyou.txt http://target http-post-form`

### 字典路径
- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/wordlists/rockyou.txt`

## 🐍 何时推荐 Python 脚本（execute_python_poc）

**优先推荐 Python 脚本 - 提高成功率的关键！**

Python 脚本比单次 curl 命令更强大，应该**积极推荐**使用，特别是以下场景：

**强烈推荐 Python 的场景**（成功率更高）：
1. **需要保持会话** - IDOR、JWT、Cookie、Session 等需要登录状态
   - ❌ 错误：`curl -X POST /login` 然后 `curl /profile` （会话丢失）
   - ✅ 正确：Python 脚本中 `session = requests.Session()` 保持登录
   
2. **需要多步骤操作** - 登录 → 获取 token → 修改数据 → 验证结果
   - ❌ 错误：多次独立的 curl 命令
   - ✅ 正确：Python 脚本串联所有步骤
   
3. **盲注爆破** - 需要逐字符测试（如 `SUBSTRING(password,1,1)='a'`）
4. **循环测试** - 需要测试多个 payload 或参数组合
5. **复杂逻辑** - 需要根据响应动态调整策略
6. **时间盲注** - 需要精确计时判断
7. **IDOR 测试** - 需要遍历多个 user_id 或 object_id

**推荐格式示例**：
```python
# IDOR + JWT 场景
建议使用 execute_python_poc 编写自动化脚本：
import requests

session = requests.Session()
# 1. 登录获取 token
response = session.post("http://target/login", 
    data={"username": "demo", "password": "demo"})
token = response.cookies.get("token")

# 2. 测试 IDOR - 遍历多个用户ID
for user_id in range(1, 10):
    response = session.get(f"http://target/profile/{user_id}")
    if "flag" in response.text.lower():
        print(f"Found FLAG at user_id={user_id}")
```

**可以用 curl 的场景**（仅限简单探索）：
- 单次访问页面查看内容
- 快速测试某个端点是否存在
- 简单的 GET 请求探索

## 🔍 必须检查的内容

### 页面探索完整性检查（优先级最高！）

系统会在第一次执行时自动进行初始探索，但你必须检查主攻手是否充分利用了这些信息：

**自动探索的内容**：
- ✅ 技术栈识别（FastAPI/Flask/Express等）
- ✅ 路径扫描（dirb common字典）
- ✅ API文档检查（openapi.json, /docs, /swagger）
- ✅ JS文件分析（linkfinder提取API端点）
- ✅ 表单和链接提取

**你必须检查**：
1. **是否访问了所有发现的路径？**
   - 关键发现中有路径，但主攻手没有访问 → 严重遗漏！
   - 提醒：必须访问每一个发现的路径

2. **是否测试了所有API端点？**
   - 从openapi.json或JS中发现了API，但没有测试 → 严重遗漏！
   - 提醒：必须测试每个API的参数

3. **是否提交了所有表单？**
   - 发现了表单，但没有尝试提交 → 可能遗漏登录入口
   - 提醒：必须尝试提交表单（用测试数据）

4. **是否分析了技术栈？**
   - 发现了FastAPI/Flask，但没有检查/openapi.json → 严重遗漏！
   - 发现了uvicorn，但没有检查/docs → 严重遗漏！

**常见遗漏模式**：
- ❌ 只测试了首页，没有访问其他路径
- ❌ 发现了/admin路径，但没有访问
- ❌ 发现了API端点，但没有测试参数
- ❌ 发现了登录表单，但没有尝试登录
- ❌ 发现了FastAPI，但没有查看API文档

### 从工具输出中提取（按优先级）：
1. **凭证信息**（最高）: 用户名、密码、token、cookie、API key
2. **链接/路径**: 所有 href, action 属性 → 构建攻击面地图
3. **表单**: 所有 form 标签 → 分析输入点和提交方式
4. **错误信息**: SQL错误、文件路径、堆栈跟踪 → 漏洞线索
5. **技术栈**: Server头、X-Powered-By → 决定侦察方法

### 目标匹配检查：
- 题目说"登录" → 主攻手在找登录页面吗？
- 题目说"管理员" → 主攻手在尝试提权吗？
- 题目说"SQL注入" → 主攻手在正确的注入点吗？
- 题目说"IDOR" → 主攻手在枚举ID吗？（不需要登录！）
- 题目说"白名单过滤" → 主攻手在尝试绕过技术吗？

### 🔄 举一反三检查（极其重要！）：
- 主攻手是否只测试了一个参数？→ 必须提醒测试所有参数！
- **响应字段名 = 请求参数名**！这是最重要的规则！
- 例如：响应 `{"id":1, "type":"front-end"}` 
  → 请求参数应该是 `{"id":1}` 或 `{"type":"front-end"}`
  → **不是** `{"job_id":1}`！参数名必须和响应字段名完全一致！
- 如果某个值返回"权限不足"（如 "Only admins"）→ 这是攻击目标！
  → 必须用绕过技术访问这个被限制的值！

### 🛡️ WAF/过滤决策指导：
- 题目包含"绕过"、"bypass"、"白名单"→ 专注绕过技术
- 题目未提及过滤 + 绕过失败 3 次 → 建议换思路
- 发现权限限制（如 "Only admins"）→ 这就是要绕过的点！

### 🚀 FastAPI/Flask 快速侦察（发现 uvicorn/werkzeug 时必须指导！）

如果看到 **uvicorn** 或 **werkzeug**，必须让主攻手执行：
```bash
curl -s http://target/openapi.json | jq '.paths | keys'  # 获取所有端点！
curl -s http://target/docs  # Swagger UI
```
这比目录扫描快100倍，能直接看到所有参数名！

### 🔓 SQL 注入测试指导（必须遵循！）

**优先级顺序**（从简单到复杂）：

1. **先用 curl 测试常见 payload**（最优先！）
   ```bash
   # 测试以下 payload（用 curl，不用 sqlmap）
   curl -X POST http://target/login -d "username=admin' OR '1'='1&password=any"
   curl -X POST http://target/login -d "username=admin' OR 1=1--&password=any"
   curl -X POST http://target/login -d "username=admin'--&password=any"
   ```
   
2. **如果遇到过滤，尝试以下绕过技术**（根据错误信息选择）
   
   **常见绕过方法**：
   - **空格绕过**: `'/**/OR/**/`, `'+OR+'`, `%20`, `%09`
   - **关键词绕过**: 
     - 大小写混合: `Or`, `oR`, `UnIoN`, `SeLeCt`
     - 双写绕过: `OORR`, `SELSELECTECT`, `UNUNIONION`
     - 编码绕过: `%27`, `%4F%52` (OR的URL编码)
   - **逻辑运算符替换**:
     - `'||'` 代替 `' OR '` (SQLite/PostgreSQL 字符串连接)
     - `' || '1'='1` 代替 `' OR '1'='1`
     - `'&&'` 代替 `' AND '`
   - **注释绕过**: `'--`, `'#`, `'/**/`
   
   **示例**：
   ```bash
   # 如果提示 "Only admins can see private jobs"
   # 尝试用 '||' 绕过（SQLite/PostgreSQL）
   curl -X POST http://target/jobs -H "Content-Type: application/json" \
     -d '{"job_type":"private'\''||'\''"}' 
   ```

3. **如果简单 payload 失败 3 次，才考虑 sqlmap**
   ```bash
   # sqlmap 参数要简化，避免超时
   sqlmap -u "http://target/login" --data="username=test&password=test" \
     --batch --threads=5 --timeout=30
   ```

**⚠️ 重要提醒**：
- ❌ 不要一开始就用 sqlmap（太慢，容易超时）
- ✅ 先用 curl 测试 3-5 个常见 payload
- ✅ 如果 curl 命令有 shell 转义问题，推荐用 `execute_python_poc`

### 失败模式检测：
- 同一方法失败 ≥3 次 → 必须禁止继续
- 在登录上死磕但题目是 IDOR → 方向完全错误
- 发现链接但没有访问 → 遗漏关键信息
- 发现 uvicorn 但没查 /openapi.json → 严重遗漏！
- SQL 注入报错但没尝试绕过 → 需要指导绕过技术

## 📋 输出格式（严格遵守）

```
【问题诊断】（置信度 XX%）
- 主攻手当前在做: <描述当前行为>
- 题目要求: <从题目描述提取>
- 诊断: 方向正确 / 方向错误 / 遗漏关键信息

【被忽略的关键信息】（如果有）
- 在输出中发现: <具体内容>
- 应该立即: <下一步行动>

【必须执行的命令】（置信度 XX%）
<可直接复制执行的完整命令>

**⚠️ 优先推荐 Python 脚本**：
- 如果需要保持会话（登录、JWT、Cookie）→ 必须用 execute_python_poc
- 如果需要多步骤操作（登录→获取token→测试IDOR）→ 必须用 execute_python_poc
- 如果需要循环测试（遍历user_id、爆破参数）→ 强烈推荐 execute_python_poc
- 只有简单的单次探索才用 curl

【绕过策略】（如果遇到过滤）
- 过滤类型: <关键字/字符/空白>
- 绕过思路: <等价替代/编码/分割>
- 具体方法: <根据过滤类型选择>

【攻击优先级】
1. [最高/置信度XX%] <行动> - <命令>
2. [次高/置信度XX%] <行动> - <命令>
3. [备选/置信度XX%] <行动> - <命令>

【禁止继续的方向】（如果有）
- 禁止: <具体方向>
- 原因: <失败次数/方向错误>
- 替代方案: <新方向>
```

## ⚠️ 重要原则

1. **直接指出问题** - 不要委婉，明确说"方向错误"
2. **给出可执行命令** - 完整命令，可直接复制执行
3. **指导绕过思路** - 不是给具体 payload，而是给方法论

## 🚫 禁止的行为（避免先入为主）

1. **禁止假设性搜索** - 不要猜测关键词
   - ❌ 错误: `curl ... | grep -i "admin|login|flag"` 
   - ❌ 错误: "分析是否存在 login、admin、profile 等路径"
   - ✅ 正确: 用工具发现路径（linkfinder, openapi.json, 爬虫）
   - ✅ 正确: 提取所有链接和表单，再分析功能
   
2. **禁止凭空猜测参数** - 必须有证据来源
   - ❌ 错误: 看到响应 `{"id":1}` 就猜测参数是 `?id=1`
   - ❌ 错误: 凭空猜测 job_id, user_id, admin_id
   - ✅ 正确: 从 JS 代码中提取（linkfinder）
   - ✅ 正确: 从 openapi.json 读取
   - ✅ 正确: 发送空请求，从错误信息中提取
   - **注意**: 响应字段 ≠ 请求参数！

3. **禁止记忆特定技术细节** - 应该观察和推断
   - ❌ 错误: "记住 /token 用 application/x-www-form-urlencoded"
   - ✅ 正确: 从 openapi.json 的 requestBody.content 中读取
   - ✅ 正确: 观察前端表单的 enctype 属性
   - ✅ 正确: 发送错误格式，从错误中学习

## 🎯 通用方法论（而非具体步骤）

### 路径发现方法
1. **API 文档优先**: openapi.json, swagger, /docs
2. **工具辅助**: linkfinder（JS分析）, katana（爬虫）
3. **响应分析**: 提取所有 href, action, fetch/axios 调用
4. **目录扫描**: dirb/gobuster（补充，不是首选）

### 敏感信息识别模式
- **凭证提示**: "username:", "password:", "default", "demo", "test"
- **密钥泄露**: "api_key", "token", "secret", 注释中的密码
- **配置文件**: .env, config.json, database.yml
- **JWT 特征**: eyJ 开头，三段 base64 编码
- **连接字符串**: mysql://, postgres://, mongodb://

### Content-Type 推断方法
1. 从 openapi.json 的 requestBody.content 读取
2. 观察前端表单的 enctype 属性
3. 发送测试请求，从错误响应学习
4. 常见模式: JSON 用 application/json, 表单用 x-www-form-urlencoded

### JWT 分析方法
1. **解码**: `echo <token> | cut -d. -f2 | base64 -d | jq`
2. **理解字段**: sub（主体ID）, exp（过期）, role/admin（权限）
3. **识别可篡改**: 算法是 none 或 HS256？签名可破解？
4. **测试篡改**: 修改 payload，观察是否验证签名

## ⚠️ 核心原则
1. **观察而非假设** - 从实际响应中提取信息
2. **工具而非猜测** - 用专业工具发现攻击面
3. **方法而非记忆** - 教方法论，不是具体步骤
4. **证据而非经验** - 每个结论都要有来源

## 🔧 绕过指导方法论（抽象原则，非具体案例）

### 过滤绕过通用思路
1. **识别过滤规则** - 测试哪些字符/关键字被过滤
2. **选择绕过策略**:
   - 关键字过滤 → 等价替代、大小写、双写
   - 字符过滤 → 编码变形
   - 空白过滤 → 注释符、特殊字符
3. **组合多种技术** - 单一方法失败时组合使用

### 技术栈识别后的快速路径
- 发现 uvicorn/FastAPI → 查 /openapi.json
- 发现 werkzeug/Flask → 查 /api/, /swagger.json
- 发现 Express/Node → 查 package.json 暴露的路由
- 发现 PHP → 测试常见漏洞点

## 🚫 禁止的回复

- ❌ "可以尝试..." - 太模糊
- ❌ "建议考虑..." - 没有具体操作
- ❌ 不分析工具输出就给建议
- ❌ 忽略题目描述中的关键词
- ❌ 不给置信度评估
- ❌ 允许主攻手继续已失败3次的方向
- ❌ 只给具体 payload 不解释原理
"""


async def advisor_node(state: PenetrationState) -> PenetrationState:
    """
    顾问Agent节点
    
    分析当前状态，提供攻击建议
    
    Args:
        state: 当前状态
    
    Returns:
        更新后的状态（包含advisor_suggestion）
    """
    log_agent_thought(default_logger, "[顾问Agent] 开始分析...")
    
    # 初始化顾问LLM（可以使用不同的模型）
    advisor_provider = os.getenv("ADVISOR_LLM_PROVIDER", os.getenv("LLM_PROVIDER", "openai"))
    advisor_model = os.getenv("ADVISOR_LLM_MODEL", os.getenv("LLM_MODEL", "gpt-4o"))
    
    advisor_llm = LLMClient(
        provider=advisor_provider,
        model=advisor_model,
        temperature=0.8  # 顾问可以更有创造性
    )
    
    # 构建上下文
    context_parts = []
    
    # 1. 当前挑战信息
    challenge = state.get("current_challenge")
    if challenge:
        challenge_id = challenge.get("id", "unknown")
        target_url = challenge.get("target_url", "unknown")
        description = challenge.get("description", "")
        
        context_parts.append(f"""
## 当前挑战信息

- **挑战ID**: {challenge_id}
- **目标URL**: {target_url}
- **描述**: {description}
""")
    
    # 2. 操作历史
    action_history = state.get("action_history", [])
    if action_history:
        recent_actions = action_history[-10:]  # 最近10次操作
        context_parts.append(f"""
## 主攻手的操作历史

{chr(10).join(f"{i+1}. {action}" for i, action in enumerate(recent_actions))}
""")
    
    # 3. 最近的工具输出（关键！让顾问能看到被忽略的信息）
    from langchain_core.messages import ToolMessage
    messages = state.get("messages", [])
    recent_tool_outputs = []
    
    # 从消息历史中提取最近的工具输出
    for msg in reversed(messages[-20:]):  # 检查最近20条消息
        if isinstance(msg, ToolMessage) and hasattr(msg, 'content'):
            content = str(msg.content)[:1000]  # 截取前1000字符
            recent_tool_outputs.append(content)
            if len(recent_tool_outputs) >= 3:  # 最多3条
                break
    
    if recent_tool_outputs:
        context_parts.append(f"""
## 🔍 最近的工具输出（请仔细检查是否有被忽略的关键信息）

{chr(10).join(f"--- 输出 {i+1} ---{chr(10)}{output}" for i, output in enumerate(reversed(recent_tool_outputs)))}

**请特别注意**：
- 是否有链接（href, action）没有被访问？
- 是否有错误信息暴露了技术栈或路径？
- 是否有敏感信息（凭证提示、token、配置）没有被利用？
- 是否有 API 文档（openapi.json, /docs）没有被检查？
""")
    
    # 4. 失败统计 + 自动知识库检索
    consecutive_failures = state.get("consecutive_failures", 0)
    attempt_count = state.get("attempt_count", 0)
    
    # 🔥 连续失败3次以上时，自动调用知识库寻找突破
    knowledge_context = ""
    if consecutive_failures >= 3:
        try:
            from src.tools.knowledge_tool import search_knowledge
            from src.utils.knowledge_base import get_knowledge_base
            
            kb = get_knowledge_base()
            if kb.enabled:
                # 从题目描述中提取关键词
                challenge = state.get("current_challenge", {})
                description = challenge.get("description", "")
                
                # 构建查询
                query_keywords = []
                if "SQL" in description or "注入" in description:
                    query_keywords.append("SQL注入绕过")
                if "XSS" in description or "跨站" in description:
                    query_keywords.append("XSS绕过")
                if "IDOR" in description or "越权" in description:
                    query_keywords.append("IDOR越权")
                if "SSTI" in description or "模板" in description:
                    query_keywords.append("SSTI模板注入")
                if "绕过" in description or "bypass" in description.lower():
                    query_keywords.append("WAF绕过")
                if "白名单" in description or "whitelist" in description.lower():
                    query_keywords.append("白名单绕过")
                
                # 如果没有明确关键词，使用通用查询
                if not query_keywords:
                    query_keywords = ["渗透测试技巧", "漏洞利用"]
                
                # 执行知识库检索
                knowledge_results = []
                for keyword in query_keywords[:2]:  # 最多查询2个关键词
                    result = search_knowledge.invoke({"query": keyword, "top_k": 2})
                    if result and "未找到" not in result:
                        knowledge_results.append(f"### 关于 '{keyword}' 的知识\n{result}")
                
                if knowledge_results:
                    knowledge_context = "\n\n".join(knowledge_results)
                    default_logger.info(f"[知识库] 连续失败{consecutive_failures}次，自动检索知识库")
        except Exception as e:
            default_logger.warning(f"[知识库] 自动检索失败: {e}")
    
    if consecutive_failures > 0:
        failure_context = f"""
## ⚠️ 当前状态

- **连续失败次数**: {consecutive_failures}
- **总尝试次数**: {attempt_count}
- **最后操作类型**: {state.get('last_action_type', 'unknown')}

主攻手遇到了困难，需要你的建议来突破困境。
"""
        if knowledge_context:
            failure_context += f"""

## 📚 知识库检索结果（自动触发）

{knowledge_context}

**请结合以上知识库内容，为主攻手提供突破性建议！**
"""
        context_parts.append(failure_context)
    
    # 5. 目标匹配检查（关键！检测主攻手是否偏离目标）
    from src.utils.pentest_context import get_pentest_context
    ctx_manager = get_pentest_context()
    
    if challenge:
        description = challenge.get("description", "")
        alignment = ctx_manager.check_target_alignment(description)
        
        if not alignment["aligned"] or alignment["issues"]:
            issues_str = "\n".join(f"- ❌ {issue}" for issue in alignment["issues"])
            suggestions_str = "\n".join(f"- 💡 {s}" for s in alignment["suggestions"])
            context_parts.append(f"""
## 🚨 目标匹配检查（发现问题！）

{issues_str}

**建议**:
{suggestions_str}
""")
    
    # 6. 渗透测试上下文摘要
    pentest_ctx = ctx_manager.to_prompt_context()
    if pentest_ctx:
        context_parts.append(f"""
## 📊 渗透测试上下文

{pentest_ctx}
""")
    
    # 7. 关键发现（永不丢弃的信息）
    try:
        from src.utils.key_discovery import get_key_discovery_manager
        discovery_manager = get_key_discovery_manager()
        discovery_ctx = discovery_manager.to_prompt_context()
        if discovery_ctx:
            context_parts.append(f"""
{discovery_ctx}

**注意**：以上关键发现是从工具输出中自动提取的，请确保主攻手已经利用了这些信息！
""")
    except Exception as e:
        pass
    
    # 8. 重复检测警告
    try:
        from src.utils.repetition_detector import get_repetition_detector
        detector = get_repetition_detector()
        repetition = detector.detect_repetition()
        if repetition:
            context_parts.append(f"""
## ⚠️ 重复模式警告

{repetition.suggestion}

**你必须**：
1. 明确指出主攻手正在重复无效操作
2. 给出具体的策略切换建议
3. 禁止继续当前方向
""")
    except Exception as e:
        pass
    
    # 组合提示
    if context_parts:
        full_context = "\n".join(context_parts) + "\n\n---\n\n请基于以上信息，提供你的攻击建议。"
    else:
        full_context = "主攻手尚未开始攻击，请提供初始策略建议。"
    
    # 构建消息
    messages = [
        SystemMessage(content=ADVISOR_SYSTEM_PROMPT),
        HumanMessage(content=full_context)
    ]
    
    # 追踪Agent决策
    tracker = get_tracker()
    decision_start_time = time.time()
    
    if tracker:
        tracker.start_operation(
            OperationType.AGENT_DECISION,
            agent_name="advisor",
            input_data={"challenge": state.get("current_challenge", {})}
        )
    
    # 调用LLM
    try:
        response = await advisor_llm.ainvoke([
            {"role": "system", "content": ADVISOR_SYSTEM_PROMPT},
            {"role": "user", "content": full_context}
        ])
        
        suggestion = response if isinstance(response, str) else response.content
        
        # 记录 Token 使用量
        if tracker and hasattr(response, 'response_metadata'):
            metadata = response.response_metadata
            token_usage = metadata.get('token_usage', {})
            if token_usage:
                input_tokens = token_usage.get('prompt_tokens', 0)
                output_tokens = token_usage.get('completion_tokens', 0)
                tracker.record_token_usage(input_tokens, output_tokens)
            else:
                # 某些 LLM 提供商不返回 token_usage，记录警告
                default_logger.debug(f"[Token] Advisor LLM 未返回 token_usage，metadata: {list(metadata.keys())}")
        
        # 记录决策结果（结束可观测性操作，持续时间由追踪器内部计算）
        if tracker:
            tracker.end_operation(
                success=True,
                output_data={"suggestion": str(suggestion)[:200]},
            )
        
        # 输出顾问建议内容（截取前 500 字符）
        default_logger.info(f"💡 [顾问建议]\n{suggestion[:500]}{'...' if len(suggestion) > 500 else ''}")
        
        # 记录到报告
        from src.utils.report_generator import get_report_generator
        report_gen = get_report_generator()
        report_gen.add_agent_log("advisor", "suggestion", suggestion)
        
        return {
            "advisor_suggestion": suggestion,
            "messages": []  # 不添加到主消息流
        }
    
    except Exception as e:
        default_logger.error(f"顾问Agent调用失败: {e}")
        return {
            "advisor_suggestion": "顾问暂时无法提供建议，请主攻手自主决策。",
            "messages": []
        }

