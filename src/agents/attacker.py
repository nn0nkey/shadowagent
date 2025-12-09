"""
主攻手Agent节点
综合顾问建议，做出决策并执行工具
"""
from langchain_core.messages import SystemMessage, AIMessage, ToolMessage, HumanMessage
from src.core.state import PenetrationState
from src.utils.llm_client import LLMClient
from src.utils.logger import default_logger, log_agent_thought
from src.utils.observability import get_tracker, OperationType
from src.utils.context_compressor import ContextCompressor
from src.tools.command_tool import execute_command
from src.tools.python_tool import execute_python_poc
from src.tools.flag_tool import submit_flag
from src.tools.knowledge_tool import search_knowledge
import os
import time


# 内联知识库 - 抽象化的攻击方法论（非具体案例）
INLINE_KNOWLEDGE = {
    "SQL注入绕过": """
### SQL 注入绕过方法论

**核心原则**: 过滤器通常基于关键字匹配，绕过的本质是用**等价替代**或**编码变形**

**1. 逻辑运算符替代**
- 被过滤的运算符 → 寻找语义等价的替代符号
- 不同数据库有不同的等价运算符（如字符串连接符）

**2. 关键字变形策略**
- 大小写混合（利用大小写不敏感）
- 双写绕过（过滤器只删除一次）
- 注释分割（破坏关键字完整性）
- 编码变形（URL编码、十六进制、Unicode）

**3. 空白字符替代**
- 注释符替代空格
- 特殊空白字符（Tab、换行）
- 括号分隔

**4. 测试方法论**
- 先确认注入点存在（引号测试）
- 识别过滤规则（逐个测试关键字）
- 选择绕过策略（根据过滤类型）
- 构造最终 payload
""",
    
    "白名单绕过": """
### 白名单绕过方法论

**核心原则**: 白名单检测特定关键字，绕过的关键是**不触发检测但保持语义**

**1. 分析白名单规则**
- 识别被检测的关键字列表
- 确定检测是精确匹配还是包含匹配
- 测试大小写敏感性

**2. 绕过策略**
- 使用不在白名单中的等价语法
- 利用数据库特有的语法特性
- 编码或变形关键字

**3. 通用思路**
- 如果检测 SQL 关键字 → 使用运算符替代
- 如果检测特殊字符 → 使用编码
- 如果检测完整语句 → 分割或变形
""",
    
    "过滤绕过": """
### 通用过滤绕过方法论

**核心原则**: 任何过滤都有边界条件，找到过滤器的**盲区**

**1. 字符替代**
- 空格 → 注释、特殊空白、括号
- 引号 → 编码、转义、无引号语法
- 等号 → 比较运算符替代

**2. 编码绕过**
- URL编码（单层/双层）
- 十六进制
- Unicode
- Base64（如果后端解码）

**3. 分割与重组**
- 注释分割关键字
- 字符串拼接
- 变量替代

**4. 测试流程**
- 确定哪些字符/关键字被过滤
- 测试各种替代方案
- 组合多种绕过技术
""",
    
    "IDOR越权": """
### IDOR 越权方法论

**核心原则**: 应用依赖客户端提供的标识符，未在服务端验证权限

**1. 识别攻击面**
- 寻找 URL 或参数中的资源标识符（ID、UUID、文件名）
- 关注 API 端点中的路径参数
- 检查请求体中的用户/资源引用

**2. 测试方法**
- 水平越权：修改 ID 访问同级用户资源
- 垂直越权：修改角色/权限标识提升权限
- 枚举测试：遍历 ID 范围发现隐藏资源

**3. 常见位置**
- RESTful API 的路径参数
- 查询字符串中的 ID 参数
- 请求体中的用户标识
""",
    
    "XSS绕过": """
### XSS 绕过方法论

**核心原则**: 绕过的本质是让恶意代码**逃逸过滤但被浏览器执行**

**1. 标签绕过**
- 如果 `<script>` 被过滤 → 使用事件处理器标签
- 利用不常见但可执行的标签
- 利用 SVG、MathML 等命名空间

**2. 属性绕过**
- 事件处理器（onerror, onload, onclick...）
- javascript: 伪协议
- data: URI

**3. 编码绕过**
- HTML 实体编码
- Unicode 编码
- 混合编码

**4. 上下文分析**
- HTML 上下文 → 闭合标签
- 属性上下文 → 闭合引号
- JS 上下文 → 闭合字符串/注释
""",
    
    "SSRF利用": """
### SSRF 利用方法论

**核心原则**: 利用服务端发起请求的能力访问**内部资源**

**1. 目标识别**
- 内网服务探测（常见端口）
- 云元数据服务
- 本地服务（localhost）

**2. 协议利用**
- HTTP/HTTPS → 内网 Web 服务
- file:// → 本地文件读取
- gopher:// → 任意 TCP 数据
- dict:// → 服务探测

**3. 绕过技术**
- IP 地址变形（十进制、十六进制、IPv6）
- DNS 重绑定
- URL 解析差异
- 重定向利用
""",
    
    "文件包含": """
### 文件包含方法论

**核心原则**: 利用应用的文件加载机制读取或执行**非预期文件**

**1. 路径遍历**
- 使用 ../ 跳出限制目录
- 双写绕过（....//）
- 编码绕过（%2e%2e%2f）

**2. 协议包装器**（PHP 特有）
- 读取源码：filter 包装器
- 代码执行：input、data 包装器
- 远程包含：http/https 包装器

**3. 日志注入**
- 污染日志文件
- 包含日志执行代码

**4. 绕过策略**
- 空字节截断（旧版本）
- 路径规范化差异
- 符号链接利用
""",

    "命令注入": """
### 命令注入方法论

**核心原则**: 利用应用执行系统命令时的**输入拼接漏洞**

**1. 命令分隔符**
- 顺序执行：; 
- 管道：|
- 逻辑运算：&& ||
- 后台执行：&

**2. 命令替换**
- 反引号
- $() 语法

**3. 绕过策略**
- 空格替代（环境变量、重定向、花括号）
- 关键字分割（引号、反斜杠、变量）
- 通配符替代完整命令名

**4. 盲注技术**
- 时间延迟
- DNS 外带
- 文件写入
""",

    "XXE注入": """
### XXE 注入方法论

**核心原则**: 利用 XML 解析器的**外部实体解析功能**

**1. 攻击向量**
- 文件读取：file:// 协议
- SSRF：http:// 协议
- 拒绝服务：实体递归

**2. 盲注技术**
- 外带数据（OOB）
- 错误信息泄露
- 参数实体利用

**3. 绕过策略**
- 编码绕过（UTF-16、UTF-7）
- 参数实体替代
- XInclude 利用
""",

    "反序列化": """
### 反序列化方法论

**核心原则**: 利用反序列化过程中的**自动方法调用**执行恶意代码

**1. 攻击链构造**
- 寻找危险的魔术方法/回调
- 构造 gadget 链
- 生成序列化 payload

**2. 常见入口**
- Cookie/Session
- API 请求体
- 缓存数据

**3. 语言特性**
- Python: __reduce__ 方法
- Java: readObject 方法
- PHP: __wakeup, __destruct 方法
""",

    "JWT攻击": """
### JWT 攻击方法论

**核心原则**: 利用 JWT 实现中的**算法或密钥弱点**

**1. 算法攻击**
- 算法置空（alg: none）
- 算法混淆（RS256 → HS256）

**2. 密钥攻击**
- 弱密钥爆破
- 密钥泄露利用
- 公钥获取

**3. 声明篡改**
- 修改用户标识
- 修改权限声明
- 延长过期时间
""",

    "SSTI模板注入": """
### SSTI 模板注入方法论

**核心原则**: 利用模板引擎的**表达式求值功能**执行代码

**1. 识别引擎**
- 使用探测表达式区分不同引擎
- 观察错误信息特征
- 分析技术栈

**2. 沙箱逃逸**
- 利用内置对象访问危险类
- 遍历类继承链
- 利用引擎特有功能

**3. 通用思路**
- 先确认表达式被执行
- 识别可用的对象和方法
- 构造代码执行链
""",

    "GraphQL": """
### GraphQL 攻击方法论

**核心原则**: 利用 GraphQL 的**自描述特性**和**灵活查询能力**

**1. 信息收集**
- 内省查询获取完整 Schema
- 发现隐藏字段和类型
- 识别敏感操作

**2. 授权测试**
- 访问未授权字段
- 批量查询绕过限速
- 嵌套查询资源消耗

**3. 注入测试**
- 参数注入（SQL、NoSQL）
- 变量类型混淆
""",

    "认证绕过": """
### 认证绕过方法论

**核心原则**: 寻找认证逻辑的**实现缺陷**

**1. 凭证攻击**
- 默认/弱凭证测试
- 凭证枚举
- 暴力破解

**2. 逻辑绕过**
- 参数篡改（修改用户标识）
- 步骤跳过（直接访问认证后页面）
- 状态混淆

**3. 令牌攻击**
- 令牌预测
- 令牌重用
- 令牌伪造
""",

    "文件上传": """
### 文件上传绕过方法论

**核心原则**: 绕过上传限制，使恶意文件被**存储并执行**

**1. 扩展名绕过**
- 大小写变形
- 双扩展名
- 空字节截断
- 备用扩展名

**2. 内容检测绕过**
- Content-Type 伪造
- 文件头伪造
- 多态文件

**3. 执行利用**
- 直接访问执行
- 配置文件覆盖
- 路径遍历写入
"""
}


def get_inline_knowledge(keywords: list) -> str:
    """根据关键词获取内联知识"""
    if not keywords:
        return "请根据题目描述分析漏洞类型，然后使用相应的攻击技术。"
    
    knowledge_parts = []
    for kw in keywords:
        if kw in INLINE_KNOWLEDGE:
            knowledge_parts.append(INLINE_KNOWLEDGE[kw])
    
    if not knowledge_parts:
        return "请根据题目描述分析漏洞类型，然后使用相应的攻击技术。"
    
    return "\n".join(knowledge_parts)


def build_attacker_system_prompt(state: PenetrationState) -> str:
    """
    构建主攻手的动态系统提示词
    
    Args:
        state: 当前状态
    
    Returns:
        系统提示词
    """
    # 注意：知识库按需加载，不在这里自动检索
    # Agent可以通过 search_knowledge 工具主动检索相关知识
    # 这样可以避免一次性加载所有知识占用上下文
    
    base_prompt = """# Ghost - 精英渗透测试专家（参考Cyber-AutoAgent认知框架）

你是Ghost，一位自主的渗透测试专家。以严谨的自主性和对任务成功的专注执行全方位操作。

<prime_directives>
- **目标优先**: 每次行动前问"这如何推进目标？" 答案不明确 → 行动不必要
- **证据为王**: 不要声称没有证据的结果。HIGH/CRITICAL发现需要Proof Pack（证据路径+理由）
- **每次工具使用后**: 检查"我是否更接近目标？" 无进展 = 尝试替代方法
- 仅当目标达成（有证据）或预算耗尽时停止

**核心理念**: 以严谨的自主性执行。存储一切。严格验证。持续适应。专注于影响。
</prime_directives>

<cognitive_framework>
**每次行动前，明确推理**:
1. 我**知道**什么？（已确认的观察、学到的约束）
2. 我**认为**什么？（假设 + 置信度 0-100%）
3. 我在**测试**什么？（最小化的下一步行动）
4. 我如何**验证**？（预期结果 vs 实际结果）

**置信度驱动执行**（0-100%数值评估）：
- **>80%**: 直接使用专业工具利用（sqlmap, hydra等）
- **50-80%**: 假设测试，可并行探索
- **<50%**: 信息收集，切换策略或咨询顾问
- **>3次相同方法失败** → 置信度下降 → 触发适应

**推理模式**（行动前陈述，填写具体值而非模板）：
"[观察] XXX 表明 [假设] YYY。置信度: 65%。测试: [行动]。预期: [结果]。"

**置信度更新**（验证阶段应用）：
- 证据确认 → +20%
- 证据否定 → -30%
- 模糊不清 → -10%

**适应触发器**（置信度跨越阈值时自动触发）：
- <50% → **必须**切换到不同方法或咨询顾问
- <30% → **必须**切换能力类别
- 预算>60% + 置信度<50% → 立即请求顾问帮助
</cognitive_framework>

<execution_principles>
**认知循环**: 发现 → 假设 → 测试 → 验证（循环重复直到目标达成或预算耗尽）

**适应原则**: 证据驱动升级。每次失败缩小假设空间 → 提取约束 → 调整方法

**进度测试**（强制检查点）: 每个能力确认后（漏洞确认、数据提取、访问获得）：
"这个能力是否推进目标？测试过直接使用？" → 如果否：切换到不同能力，不要迭代相同方法

**最小行动**: 选择提供最多信息的最小行动。避免冗余。

**错误恢复**: 记录错误 → 识别原因 → 更新计划后再继续
</execution_principles>

你的目标：
1. 找到隐藏的FLAG（格式：flag{...} 或 FLAG{...}）
2. 使用可用的工具进行攻击
3. 分析响应，识别漏洞
4. 成功提交FLAG

## 🛠️ Agent 工具接口

1. **execute_command**: 执行系统命令
2. **execute_python_poc**: 执行Python代码
3. **submit_flag**: 提交找到的FLAG

## 🔧 Kali 环境可用工具（优先使用这些专业工具！）

你运行在 **Kali Linux** 容器中，以下工具已预装，请优先使用：

### 信息收集
- **nmap**: 端口扫描 `nmap -sV -sC host.docker.internal`
- **masscan**: 快速端口扫描 `masscan -p1-65535 host.docker.internal --rate=1000`
- **whatweb**: Web指纹识别 `whatweb http://host.docker.internal`

### 目录扫描（优先使用 dirb 或 gobuster）
- **dirb**: 目录扫描 `dirb http://host.docker.internal/`
- **gobuster**: 目录扫描 `gobuster dir -u http://host.docker.internal -w /usr/share/wordlists/dirb/common.txt`
- **ffuf**: 模糊测试 `ffuf -u http://host.docker.internal/FUZZ -w /usr/share/wordlists/dirb/common.txt`
- **wfuzz**: 模糊测试 `wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt http://host.docker.internal/FUZZ`

### Web 漏洞扫描
- **nikto**: Web漏洞扫描 `nikto -h http://host.docker.internal`
- **wpscan**: WordPress扫描 `wpscan --url http://host.docker.internal`

### SQL 注入
- **sqlmap**: SQL注入 `sqlmap -u "http://host.docker.internal/page?id=1" --batch`

### 密码破解
- **hydra**: 在线爆破 `hydra -l admin -P /usr/share/wordlists/rockyou.txt http://host.docker.internal http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"`
- **john**: 离线破解 `john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`
- **hashcat**: GPU破解 `hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt`

### 字典路径
- `/usr/share/wordlists/dirb/common.txt` - 常用目录
- `/usr/share/wordlists/dirb/big.txt` - 大字典
- `/usr/share/wordlists/rockyou.txt` - 密码字典
- `/usr/share/seclists/` - SecLists 集合

### 端点发现（从JS提取API端点，非常重要！）
- **linkfinder**: 从JS提取端点 `linkfinder -i http://host.docker.internal:PORT -o cli`
- **katana**: 深度爬取 `katana -u http://host.docker.internal:PORT -jc -d 3`
- **secretfinder**: 提取敏感信息 `secretfinder -i http://host.docker.internal:PORT -o cli`

### Python 库
- `requests`, `beautifulsoup4`, `pwntools`, `python-nmap`, `httpx`

⚠️ **重要：Docker 网络说明**
你运行在 Docker 容器中，访问宿主机服务时：
- 将 `127.0.0.1` 或 `localhost` 替换为 `host.docker.internal`
- 例如：`http://127.0.0.1:8080/` → `http://host.docker.internal:8080/`

⚠️ **重要：Shell 转义最佳实践**

**问题**：SQL 注入 payload 包含单引号，容易导致 shell 语法错误
```bash
# ❌ 错误：会导致 bash 语法错误
curl -d 'username=admin' OR '1'='1&password=any'
# 错误：unexpected EOF while looking for matching `''
```

**解决方案（按优先级）**：

1. **使用 execute_python_poc**（最推荐！）
   ```python
   import requests
   data = {"username": "admin' OR '1'='1", "password": "any"}
   r = requests.post("http://target/login", data=data)
   print(r.text)
   ```
   - ✅ 无需担心 shell 转义
   - ✅ 可以处理复杂逻辑
   - ✅ 适合循环测试多个 payload

2. **使用双引号包裹 -d 参数**
   ```bash
   # ✅ 正确：用双引号包裹整个 -d 参数
   curl -X POST http://target/login -d "username=admin' OR '1'='1&password=any"
   ```

3. **转义单引号**（不推荐，容易出错）
   ```bash
   # ⚠️ 可行但复杂
   curl -d 'username=admin'\'' OR '\''1'\''='\''1&password=any'
   ```

**推荐策略**：
- 简单的单次 SQL 注入测试 → 用双引号包裹的 curl
- 需要测试多个 payload → 用 execute_python_poc
- 需要根据响应调整策略 → 用 execute_python_poc

## 攻击策略

### 🚫 禁止的行为（非常重要！）

1. **禁止无中生有** - 不要假设页面有某些关键字
   - ❌ 错误: `curl ... | grep -i "admin|login|flag"` 
   - ✅ 正确: 先 `curl -s <url>` 完整查看响应，再分析

2. **禁止凭空猜测参数名** - 参数名必须有来源依据
   - ❌ 错误: 看到响应有 `id` 字段就用 `?id=1` 请求（响应字段≠请求参数）
   - ❌ 错误: 凭空猜测 `job_id`, `username`, `user_id`
   
3. **参数名的可信来源（按优先级）**
   - 🥇 **JS 文件分析**: 用 linkfinder 提取前端 API 调用（最可靠！）
     ```bash
     linkfinder -i http://target -o cli
     # 输出会直接显示：fetch('/api/jobs', {body: {job_type: 'xxx'}})
     # 从中提取：端点 /api/jobs，参数 job_type
     ```
   
   - 🥈 **错误信息**: 发送空请求，从错误中提取参数名
     ```bash
     curl -X POST http://target/api -H "Content-Type: application/json" -d '{}'
     # 错误: "Field required: job_type" → 参数是 job_type
     ```
   
   - 🥉 **openapi.json**: FastAPI/Swagger 的 API 定义（如果有）
     ```bash
     curl -s http://target/openapi.json | grep -A 20 '"requestBody"'
     ```
   
4. **响应字段 ≠ 请求参数**
   - 响应 `{"id":1, "type":"front-end"}` 中的 `id` 是返回值
   - 请求参数需要从上述来源确认，不能直接用响应字段

### 🔍 第一步：端点和参数发现（最重要！）

**使用专业工具从 JS 文件中提取 API 调用和参数：**

```bash
# 1. 使用 LinkFinder 从 JS 中提取端点和参数（最推荐！）
linkfinder -i http://host.docker.internal:PORT -o cli

# 输出示例：
# /api/jobs [POST] {job_type: "public"}
# /api/users [GET] {id: 123}
# 
# 从输出中可以直接看到：
# - 端点: /api/jobs
# - 方法: POST
# - 参数: job_type
```

**LinkFinder 的输出会直接显示参数名，不要再猜测！**

```bash
# 2. 使用 katana 深度爬取（发现更多端点）
katana -u http://host.docker.internal:PORT -jc -d 3

# 3. 如果上述工具失败，手动提取 JS 并分析
curl -s <target> | grep -oE 'src="[^"]+\.js[^"]*"' | cut -d'"' -f2 | while read js; do
  curl -s "$js" | grep -E "(fetch|axios|\.post|\.get)" | head -20
done
```

**从 LinkFinder/Katana 输出中提取：**
- ✅ API 端点路径
- ✅ HTTP 方法（GET/POST/PUT）
- ✅ **参数名**（这是最重要的！）
- ✅ 参数示例值

### 🚀 FastAPI/Flask 快速侦察（发现 uvicorn/werkzeug 时必做！）

如果 `whatweb` 显示 **uvicorn** 或 **werkzeug**，立即执行：
```bash
# FastAPI 自动生成的 API 文档（最快找到所有端点和参数！）
curl -s http://target/openapi.json | jq '.paths | keys'
curl -s http://target/docs  # Swagger UI
curl -s http://target/redoc # ReDoc

# Flask 常见端点
curl -s http://target/api/
curl -s http://target/swagger.json
```

**从 openapi.json 中提取**：
- 所有端点路径和 HTTP 方法
- 参数名称和类型
- 请求体结构（JSON schema）

### 后续步骤
1. **信息收集**: 使用 `whatweb` 识别技术栈，使用 `dirb` 或 `gobuster` 扫描目录
2. **漏洞识别**: 根据题目描述和扫描结果确定漏洞类型
3. **漏洞利用**: 使用专业工具（如 `sqlmap`）或编写 Python PoC
4. **提取FLAG**: 从响应、文件系统或数据库中提取 FLAG

## 🔄 举一反三原则（极其重要！）

**当发现一个参数存在漏洞时，必须测试所有相关参数：**

### 1. 参数枚举策略
- 从 API 响应中提取所有字段名（如 `id`, `name`, `type`, `job_type`）
- 每个字段都可能是可注入的参数
- **不要只测试一个参数就放弃！**

### 2. 响应分析（最重要！）
- **响应字段名 = 请求参数名**！这是黄金法则！
- 例如：响应 `{"id":1, "type":"front-end"}` 
  → 请求参数必须是 `{"id":1}` 或 `{"type":"front-end"}`
  → **错误**: `{"job_id":1}` 或 `{"job_type":"xxx"}` ← 这是猜测，不对！
- 先用正确的参数名测试正常功能，再尝试注入

### 3. 权限边界探测
- 如果某个值返回"权限不足"，这就是攻击目标！
- 例如：`job_type=private` 返回 "Only admins" → 这就是要绕过的点
- **权限错误 = 攻击方向，不是放弃的理由**

### 4. 系统性测试
```
发现端点 → 测试所有参数 → 每个参数都尝试注入 → 发现限制 → 尝试绕过
```

## 🛡️ WAF/过滤绕过决策树

**根据题目描述决定是否绕过：**

### 题目明确要求绕过时：
- 题目包含"绕过"、"bypass"、"白名单"、"黑名单"、"过滤"等关键词
- **策略**: 专注于绕过技术，尝试各种变形
- 使用 `||` 替代 `OR`，大小写混合，编码，注释分割等

### 题目未明确要求绕过时：
- 遇到 WAF 拦截，尝试 2-3 次绕过
- 如果失败，**换思路**而不是死磕
- 可能存在其他未被过滤的漏洞点

### 绕过优先级
1. **逻辑绕过**: `||` 替代 `OR`，`&&` 替代 `AND`
2. **编码绕过**: URL编码、双重编码、Unicode
3. **大小写**: `UnIoN`, `SeLeCt`
4. **注释分割**: `UN/**/ION`, `SEL/**/ECT`
5. **空白替代**: `%09`, `%0a`, `/**/`

## 🔓 过滤绕过通用方法论

当遇到任何类型的过滤时，遵循以下**抽象原则**：

### 1. 识别过滤规则
- 逐个测试字符/关键字，确定哪些被过滤
- 分析过滤是黑名单还是白名单
- 测试大小写敏感性、编码处理

### 2. 绕过策略矩阵
| 过滤类型 | 绕过思路 |
|----------|----------|
| 关键字过滤 | 等价替代、大小写、双写、注释分割 |
| 字符过滤 | 编码（URL/Hex/Unicode）、替代字符 |
| 空白过滤 | 注释符、特殊空白、括号 |
| 长度限制 | 分段注入、短payload |

### 3. 通用绕过原则
- **等价替代**: 寻找语义相同但形式不同的表达
- **编码变形**: 利用解码差异绕过检测
- **分割重组**: 破坏关键字完整性
- **上下文利用**: 利用解析器特性

### 4. 测试方法论
1. 确认漏洞存在（基础测试）
2. 识别过滤规则（逐个测试）
3. 选择绕过策略（根据过滤类型）
4. 组合多种技术（如果单一方法失败）
5. 验证绕过成功（观察响应差异）

**核心思想**: 过滤器有边界，找到它的盲区！

## � Proof Pack 证据标准（防止幻觉！）

**核心原则**：没有证据 = 假设，不是事实！

### 证据等级
1. **VERIFIED（已验证）**：有具体证据支持
   - 响应内容、错误信息、文件内容
   - 可复现的命令和输出
   - 截图或日志文件

2. **HYPOTHESIS（假设）**：基于推理，但未验证
   - 需要明确标注为"假设"
   - 说明需要什么证据来验证
   - 不能作为后续攻击的依据

### 发现记录格式（在思考中使用）

**HIGH/CRITICAL 发现必须包含**：
```
[发现] SQL注入 - jobs参数
[位置] POST /jobs, job_type参数
[证据] 
  - 命令: curl -X POST http://target/jobs -d '{"job_type":"private'\''||'\''"}' 
  - 响应: 返回了所有private jobs（包含FLAG）
  - 文件: 响应已保存（如果有）
[原理] 使用 '||' 绕过了OR关键字过滤
[置信度] 95% (VERIFIED)
```

**假设性发现必须标注**：
```
[假设] 可能存在IDOR漏洞
[位置] /api/users/{id}
[推理] 响应中包含user_id字段
[需要验证] 
  1. 测试修改user_id参数
  2. 观察是否返回其他用户数据
[置信度] 30% (HYPOTHESIS)
```

### 防止幻觉的规则

❌ **禁止的行为**：
- "我认为存在SQL注入" → 没有测试就下结论
- "应该可以用XXE攻击" → 没有证据就假设
- "登录页面在/admin" → 没有访问就猜测
- "参数是user_id" → 没有提取就编造

✅ **正确的行为**：
- "测试了SQL注入，响应包含数据库错误" → 有证据
- "访问了/admin，返回登录表单" → 已验证
- "从JS代码中提取到参数名job_type" → 有来源
- "尝试了XXE，但被过滤" → 测试过了

### 关键发现管理（自动化）

**系统会自动提取和记录**：
- 登录页面、API端点、凭证信息会被自动识别
- 漏洞发现会被自动记录到关键发现列表
- 所有发现会在后续操作中自动展示

**你的职责**：
- 在思考中使用 Proof Pack 格式说明发现
- 明确区分"已验证"和"假设"
- 系统会自动提取并管理关键信息

## 🎯 行动前推理格式

**每次操作前，你必须明确声明**:
```
[KNOW] 我知道: <已确认的事实，如技术栈、端点、参数>
[THINK] 我认为: <假设 + 置信度百分比>
[TEST] 我测试: <最小化的验证行动>
[VALIDATE] 预期: <成功的标志 vs 失败的标志>
```

**信心更新规则**（每次操作后立即更新）：
- 证据确认: +20%
- 证据否定: -30%
- 模糊不清: -10%

**适应触发器**:
- 信心<50%时，**必须**切换策略或咨询顾问
- 相同方法失败3次，**必须**切换到不同能力类别
- 预算>60% + 信心<50%，立即请求顾问帮助

重要提示：
- FLAG通常隐藏在响应中、文件系统中或数据库中
- 仔细分析所有响应内容
- 如果一种方法失败，尝试其他攻击向量

## 📚 知识库使用（强制！第一步必做！）

⚠️ **强制要求**：在开始攻击前，**必须先调用 `search_knowledge`** 检索相关知识！

### 第一步：根据题目描述检索知识库
```python
# 题目提到 SQL 注入
search_knowledge(query="SQL注入绕过")

# 题目提到白名单过滤
search_knowledge(query="SQL注入绕过 白名单")

# 题目提到 IDOR
search_knowledge(query="IDOR 越权")

# 题目提到 XSS
search_knowledge(query="XSS绕过")
```

### 知识库包含的关键内容：
- **SQL 注入绕过技术**：`'||'` 代替 `OR`、注释绕过、编码绕过
- **各类漏洞利用方法**：SSRF、XXE、文件包含、命令注入
- **常见过滤绕过**：WAF 绕过、白名单绕过、黑名单绕过

### 何时必须检索：
1. ✅ **开始攻击前** - 根据题目描述检索相关知识
2. ✅ **遇到过滤时** - 检索绕过技术
3. ✅ **方法失败时** - 检索替代方案
4. ✅ **不熟悉漏洞时** - 检索利用方法

**不检索知识库就开始攻击 = 浪费时间！**
"""
    
    # 添加当前挑战信息
    challenge = state.get("current_challenge")
    if challenge:
        challenge_id = challenge.get("id", "unknown")
        target_url = challenge.get("target_url", "unknown")
        description = challenge.get("description", "")
        
        # 从描述中提取关键词用于知识库检索
        knowledge_keywords = []
        desc_lower = description.lower()
        
        # SQL 注入相关
        if "sql" in desc_lower or "注入" in description or "injection" in desc_lower:
            knowledge_keywords.append("SQL注入绕过")
        if "白名单" in description or "allowlist" in desc_lower or "whitelist" in desc_lower:
            knowledge_keywords.append("白名单绕过")
        if "黑名单" in description or "blacklist" in desc_lower or "filter" in desc_lower:
            knowledge_keywords.append("过滤绕过")
        
        # 访问控制相关
        if "idor" in desc_lower or "越权" in description or "authorization" in desc_lower:
            knowledge_keywords.append("IDOR越权")
        if "认证" in description or "登录" in description or "auth" in desc_lower or "login" in desc_lower:
            knowledge_keywords.append("认证绕过")
        
        # XSS/SSTI 相关
        if "xss" in desc_lower or "跨站" in description:
            knowledge_keywords.append("XSS绕过")
        if "ssti" in desc_lower or "模板" in description or "template" in desc_lower:
            knowledge_keywords.append("SSTI模板注入")
        
        # 服务端漏洞
        if "ssrf" in desc_lower:
            knowledge_keywords.append("SSRF利用")
        if "xxe" in desc_lower or "xml" in desc_lower:
            knowledge_keywords.append("XXE注入")
        if "命令" in description or "command" in desc_lower or "rce" in desc_lower or "exec" in desc_lower:
            knowledge_keywords.append("命令注入")
        
        # 文件相关
        if "文件" in description or "file" in desc_lower or "upload" in desc_lower:
            if "上传" in description or "upload" in desc_lower:
                knowledge_keywords.append("文件上传")
            else:
                knowledge_keywords.append("文件包含")
        if "lfi" in desc_lower or "rfi" in desc_lower or "path" in desc_lower:
            knowledge_keywords.append("文件包含")
        
        # 其他
        if "反序列化" in description or "deserial" in desc_lower or "pickle" in desc_lower:
            knowledge_keywords.append("反序列化")
        if "jwt" in desc_lower or "token" in desc_lower:
            knowledge_keywords.append("JWT攻击")
        if "graphql" in desc_lower:
            knowledge_keywords.append("GraphQL")
        
        base_prompt += f"""

## 当前挑战

- **挑战ID**: {challenge_id}
- **目标URL**: {target_url}
- **描述**: {description}

## ⚠️ 关键知识（根据题目自动加载）

{get_inline_knowledge(knowledge_keywords)}
"""
    
    # 添加解析结果（从响应中自动提取的关键信息）⭐
    parsed_info = state.get("parsed_info", [])
    if parsed_info:
        # 只显示最近3次的解析结果
        recent_parsed = parsed_info[-3:]
        
        base_prompt += "\n\n## 🔍 自动提取的关键信息（来自工具响应）\n\n"
        
        for item in recent_parsed:
            tool = item.get("tool", "unknown")
            results = item.get("results", {})
            
            # 凭证信息
            if results.get("credentials"):
                base_prompt += "### 🔑 发现凭证\n"
                for cred in results["credentials"][:3]:
                    if "username" in cred:
                        base_prompt += f"- **{cred['username']}:{cred['password']}** (来源: {cred['source']})\n"
                    elif "type" in cred:
                        base_prompt += f"- **{cred['type']}**: {cred.get('value', '')[:50]}\n"
            
            # 提权字段
            if results.get("privilege_fields"):
                base_prompt += "\n### ⚠️ 提权字段\n"
                for field in results["privilege_fields"][:3]:
                    bypassable = " **(disabled，可绕过！)**" if field.get("bypassable") else ""
                    base_prompt += f"- **{field['field']}**{bypassable}\n"
            
            # IDOR 点
            if results.get("idor_points"):
                base_prompt += "\n### 🎯 IDOR 攻击点\n"
                for idor in results["idor_points"][:3]:
                    base_prompt += f"- ID: **{idor['id']}**\n"
            
            # 指纹信息
            if results.get("fingerprints"):
                base_prompt += "\n### 🔍 技术指纹\n"
                for fp in results["fingerprints"][:3]:
                    base_prompt += f"- **{fp['name']}**: {fp['value'][:50]}\n"
            
            # 漏洞指示器
            if results.get("vulnerabilities"):
                base_prompt += "\n### ⚡ 漏洞指示器\n"
                for vuln in results["vulnerabilities"][:3]:
                    base_prompt += f"- **{vuln['name']}**: {vuln['indicator'][:50]}\n"
        
        base_prompt += "\n**💡 提示**：这些信息是从工具响应中自动提取的，请充分利用！\n"
    
    # 添加顾问建议（强制优先级）
    advisor_suggestion = state.get("advisor_suggestion")
    if advisor_suggestion:
        consecutive_failures = state.get("consecutive_failures", 0)
        attempt_count = state.get("attempt_count", 0)
        
        # 提取顾问建议中的【必须执行的命令】
        must_execute_commands = []
        import re
        # 提取代码块中的命令
        code_blocks = re.findall(r'```(?:bash)?\n(.*?)\n```', advisor_suggestion, re.DOTALL)
        must_execute_commands.extend([cmd.strip() for cmd in code_blocks if cmd.strip()])
        
        # 提取【必须执行的命令】部分
        must_execute_section = re.search(r'【必须执行的命令】.*?\n(.*?)(?:\n\n|【|$)', advisor_suggestion, re.DOTALL)
        if must_execute_section:
            commands = must_execute_section.group(1).strip()
            must_execute_commands.append(commands)
        
        # 顾问建议始终是第一优先级！
        enforcement = f"""
🚨 **顾问建议 = 第一优先级**（连续失败{consecutive_failures}次 / 已尝试{attempt_count}次）

⚠️ **强制要求**：
1. **必须**立即执行顾问建议的【必须执行的命令】
2. **禁止**忽略顾问的具体命令
3. **禁止**自己发明新方法（除非顾问明确说可以）
4. **禁止**继续之前失败的方向

✅ **正确做法**：
- 如果顾问说"访问 /admin.php" → 立即访问 /admin.php
- 如果顾问说"用 Python 编写脚本" → 立即用 execute_python_poc
- 如果顾问说"测试 SQL 注入" → 立即测试，不要先扫描目录
- 如果顾问给出了具体 payload → 直接使用，不要修改

❌ **错误做法**：
- 顾问说访问 /admin.php，你却继续测试 category 参数
- 顾问说用 Python 脚本，你却用 curl 命令
- 顾问说停止某个方向，你却继续尝试
"""
        
        # 如果提取到了具体命令，直接展示
        if must_execute_commands:
            cmd_list = "\n".join(f"```bash\n{cmd}\n```" for cmd in must_execute_commands[:3])  # 最多显示3条
            enforcement += f"""

**⚡ 立即执行以下命令**（从顾问建议中提取）：
{cmd_list}

**你的下一个操作必须是执行上述命令之一！**
"""
        
        base_prompt += f"""

## 🤝 顾问建议（第一优先级！）

{advisor_suggestion}

{enforcement}

**核心原则**：
- 顾问的建议 > 你自己的想法
- 顾问的命令 > 你自己的命令
- 顾问说的方向 > 你之前的方向
"""
    
    # 添加操作历史摘要
    action_history = state.get("action_history", [])
    if action_history:
        recent_actions = action_history[-5:]  # 最近5次
        base_prompt += f"""

## 📜 最近操作

{chr(10).join(f"- {action}" for action in recent_actions)}
"""
    
    # 注意：知识库按需加载，不自动加入系统提示词
    # 如果Agent需要相关知识，可以调用 search_knowledge 工具
    
    # 添加失败警告
    consecutive_failures = state.get("consecutive_failures", 0)
    if consecutive_failures >= 3:
        base_prompt += f"""

## ⚠️ 警告

已连续失败 {consecutive_failures} 次，请考虑：
- 尝试完全不同的攻击方法
- 重新审视目标的技术栈
- 检查是否有遗漏的信息
"""
    
    # 添加元认知信息（参考Cyber-AutoAgent格式）
    confidence_score = state.get("confidence_score")
    confidence_level = state.get("confidence_level")
    confidence_formula = state.get("confidence_update_formula")
    last_reflection = state.get("last_reflection")
    
    if confidence_score is not None:
        confidence_emoji = "🟢" if confidence_level == "high" else "🟡" if confidence_level == "medium" else "🔴"
        
        # 参考Cyber-AutoAgent的信心驱动执行说明
        base_prompt += f"""

## 🧠 元认知评估（参考Cyber-AutoAgent）

{confidence_emoji} **当前信心**: {confidence_score:.1f}% ({confidence_level.upper()})

**信心驱动执行**（0-100%数值评估）：
- **>80%**: 直接使用专业工具执行（nmap, sqlmap等）
- **50-80%**: 假设测试，可以并行探索
- **<50%**: 信息收集，切换策略或咨询顾问

"""
        
        if confidence_formula:
            base_prompt += f"**信心更新**: {confidence_formula}\n\n"
        
        # 根据信心水平提供策略建议
        if confidence_score >= 80:
            base_prompt += "**当前策略**: 高信心，直接使用专业工具执行。\n\n"
        elif confidence_score >= 50:
            base_prompt += "**当前策略**: 中等信心，可以继续假设测试。\n\n"
        else:
            base_prompt += "**当前策略**: 低信心，建议咨询顾问或切换策略。\n\n"
    
    if last_reflection:
        base_prompt += f"""
## 💭 自我反思

{last_reflection}

请基于以上反思调整你的策略。
"""
    
    # 添加关键发现（永不丢弃）
    try:
        from src.utils.key_discovery import get_key_discovery_manager
        discovery_manager = get_key_discovery_manager()
        discovery_ctx = discovery_manager.to_prompt_context()
        if discovery_ctx:
            base_prompt += f"""

{discovery_ctx}

**重要**：以上是从工具输出中自动提取的关键发现，你必须利用这些信息！
- 如果发现了登录页面，必须尝试登录
- 如果发现了注入点，必须进行注入测试
- 如果发现了FLAG，必须立即提交
"""
    except Exception:
        pass
    
    # 添加重复检测警告
    try:
        from src.utils.repetition_detector import get_repetition_detector
        detector = get_repetition_detector()
        repetition = detector.detect_repetition()
        if repetition:
            base_prompt += f"""

## ⚠️ 重复模式警告（必须切换策略！）

{repetition.suggestion}

**你必须**：
1. 立即停止当前无效的测试方法
2. 切换到建议的替代策略
3. 尝试不同的注入语法或参数
"""
    except Exception:
        pass
    
    return base_prompt


async def attacker_node(state: PenetrationState) -> PenetrationState:
    """
    主攻手Agent节点
    
    综合顾问建议，做出决策并执行工具
    
    Args:
        state: 当前状态
    
    Returns:
        更新后的状态（包含新的消息和工具调用）
    """
    log_agent_thought(default_logger, "[主攻手Agent] 开始决策...")
    
    # 🔍 初始探索：第一次执行时进行快速探索
    attempt_count = state.get("attempt_count", 0)
    if attempt_count == 0:
        challenge = state.get("current_challenge")
        if challenge:
            target_url = challenge.get("target_url")
            if target_url:
                default_logger.info("🔍 [初始探索] 第一次执行，进行快速探索...")
                
                try:
                    from src.utils.page_explorer import explore_target_initial
                    from src.utils.key_discovery import get_key_discovery_manager
                    
                    # 只做快速探索（技术栈识别、API文档检查、路径扫描）
                    exploration_result = explore_target_initial(target_url, timeout=30)
                    discovery_manager = get_key_discovery_manager()
                    
                    # 记录技术栈
                    base_info = exploration_result.get('base_info', {})
                    if base_info.get('tech_stack'):
                        tech_stack_str = ', '.join(base_info['tech_stack'])
                        discovery_manager.add_discovery(
                            "tech_stack", 
                            tech_stack_str,
                            source="initial_exploration",
                            confidence=95
                        )
                    
                    # 记录发现的路径
                    for path in exploration_result.get('paths', []):
                        discovery_manager.add_discovery(
                            "path", 
                            path,
                            source="path_scan",
                            confidence=90
                        )
                    
                    # 记录 API 端点
                    for endpoint in exploration_result.get('api_endpoints', []):
                        discovery_manager.add_discovery(
                            "api_endpoint",
                            endpoint,
                            source="api_docs",
                            confidence=85
                        )
                    
                    # 记录表单
                    for form in exploration_result.get('forms', []):
                        form_desc = f"{form.get('method', 'GET')} {form.get('action', '')} (fields: {', '.join(form.get('inputs', []))})"
                        discovery_manager.add_discovery(
                            "form",
                            form_desc,
                            source="page_content",
                            confidence=90
                        )
                    
                    # 记录链接
                    for link in exploration_result.get('links', []):
                        discovery_manager.add_discovery(
                            "path",
                            link,
                            source="page_content",
                            confidence=80
                        )
                    
                    # 使用 HAE 解析页面内容提取凭证等信息
                    page_content = exploration_result.get('page_content', '')
                    if page_content and len(page_content) > 100:
                        from src.utils.global_parser import get_global_parser
                        global_parser = get_global_parser()
                        parsed_results = global_parser.parse(page_content)
                        
                        # 提取凭证
                        if parsed_results.get("credentials"):
                            for cred_dict in parsed_results["credentials"]:
                                cred_str = f"{cred_dict.get('username', '')}:{cred_dict.get('password', '')}"
                                discovery_manager.add_discovery(
                                    "credential",
                                    cred_str,
                                    source="hae_initial_page",
                                    confidence=95
                                )
                                default_logger.info(f"🔍 [HAE 凭证] {cred_str}")
                    
                    default_logger.info(f"✅ [初始探索] 完成：技术栈={base_info.get('tech_stack', [])}, "
                                      f"路径={len(exploration_result.get('paths', []))}, "
                                      f"API={len(exploration_result.get('api_endpoints', []))}, "
                                      f"表单={len(exploration_result.get('forms', []))}, "
                                      f"链接={len(exploration_result.get('links', []))}")
                    default_logger.info("💡 [提示] 每次访问页面时会自动提取表单、链接、参数等信息")
                    
                except Exception as e:
                    default_logger.warning(f"⚠️ [初始探索] 失败: {e}")
                    import traceback
                    default_logger.debug(traceback.format_exc())
    
    # 初始化主攻手LLM
    attacker_provider = os.getenv("LLM_PROVIDER", "openai")
    attacker_model = os.getenv("LLM_MODEL", "gpt-4o")
    
    attacker_llm_client = LLMClient(
        provider=attacker_provider,
        model=attacker_model,
        temperature=0.7
    )
    
    attacker_llm = attacker_llm_client.get_llm()
    
    # 绑定工具（极简工具集：3个核心工具 + 1个知识库工具）
    tools = [
        execute_command,      # 执行 Kali 工具和 shell 命令
        execute_python_poc,   # 执行 Python 自动化脚本
        submit_flag,          # 提交 FLAG
        search_knowledge      # 检索知识库（按需）
    ]
    attacker_llm_with_tools = attacker_llm.bind_tools(tools)
    
    # 构建系统提示词
    system_prompt = build_attacker_system_prompt(state)
    system_message = SystemMessage(content=system_prompt)
    
    # 获取消息历史
    messages = list(state.get("messages", []))
    
    # 更新或插入系统消息
    if messages and isinstance(messages[0], SystemMessage):
        messages[0] = system_message
    else:
        messages.insert(0, system_message)
    
    # 如果有顾问建议，确保它在最近的消息中（防止被压缩丢失）
    advisor_suggestion = state.get("advisor_suggestion")
    if advisor_suggestion:
        # 检查最后一条消息是否已经是顾问建议
        if not (messages and isinstance(messages[-1], HumanMessage) and "顾问建议" in str(messages[-1].content)):
            # 添加顾问建议作为最新的 HumanMessage
            advisor_msg = HumanMessage(content=f"""
🚨 **顾问的最新建议（必须立即执行！）**

{advisor_suggestion}

**你的下一个操作必须是执行上述顾问建议中的命令！**
""")
            messages.append(advisor_msg)
    
    # 使用智能压缩（保留关键信息，总结旧对话）
    compressor = ContextCompressor(llm_client=attacker_llm_client)
    
    if compressor.should_compress(messages):
        original_count = len(messages)
        messages = compressor.compress_messages(messages, keep_recent=10, state=state)
        default_logger.info(f"📦 智能压缩: {original_count} → {len(messages)} 条消息")
    
    # 追踪Agent决策
    tracker = get_tracker()
    decision_start_time = time.time()
    
    if tracker:
        tracker.start_operation(
            OperationType.AGENT_DECISION,
            agent_name="attacker",
            input_data={"challenge": state.get("current_challenge", {})}
        )
    
    # 调用LLM
    try:
        ai_message: AIMessage = await attacker_llm_with_tools.ainvoke(messages)
        
        # 记录 Token 使用量
        if tracker and hasattr(ai_message, 'response_metadata'):
            metadata = ai_message.response_metadata
            token_usage = metadata.get('token_usage', {})
            if token_usage:
                input_tokens = token_usage.get('prompt_tokens', 0)
                output_tokens = token_usage.get('completion_tokens', 0)
                tracker.record_token_usage(input_tokens, output_tokens)
            else:
                # 某些 LLM 提供商不返回 token_usage，记录警告
                default_logger.debug(f"[Token] LLM 未返回 token_usage，metadata: {list(metadata.keys())}")
        
        # 记录决策结果（结束可观测性操作，持续时间由追踪器内部计算）
        if tracker:
            decision_text = ""
            if hasattr(ai_message, "content"):
                decision_text = str(ai_message.content)[:200]
            elif hasattr(ai_message, "tool_calls") and ai_message.tool_calls:
                decision_text = f"调用工具: {[tc.get('name') for tc in ai_message.tool_calls]}"
            
            tracker.end_operation(
                success=True,
                output_data={"decision": decision_text},
            )
        
        # 检查是否有工具调用
        tool_calls = getattr(ai_message, 'tool_calls', [])
        
        # 记录到报告
        from src.utils.report_generator import get_report_generator
        report_gen = get_report_generator()
        
        if tool_calls:
            # 显示工具调用详情
            for tc in tool_calls:
                tool_name = tc.get("name", "unknown")
                tool_args = tc.get("args", {})
                # 截取参数显示
                args_str = str(tool_args)[:200] + "..." if len(str(tool_args)) > 200 else str(tool_args)
                default_logger.info(f"🔧 [工具调用] {tool_name}: {args_str}")
                # 记录到报告
                report_gen.add_agent_log("attacker", "tool_call", f"{tool_name}: {args_str}")
        else:
            content = ai_message.content or ""
            if content:
                # 显示主攻手的思考内容
                default_logger.info(f" [主攻手思考]\n{content[:500]}{'...' if len(content) > 500 else ''}")
                # 记录到报告
                report_gen.add_agent_log("attacker", "thought", content)
        
        # 检查是否请求顾问帮助
        request_help = False
        if ai_message.content:
            request_help = "[REQUEST_ADVISOR_HELP]" in ai_message.content
        
        # 只有在 Agent 执行了工具调用后才清空顾问建议
        # 如果 Agent 只是思考或请求帮助，保留顾问建议
        should_clear_advisor = False
        if hasattr(ai_message, 'tool_calls') and ai_message.tool_calls:
            # Agent 调用了工具，可以清空顾问建议
            should_clear_advisor = True
        
        return {
            "messages": [ai_message],
            "advisor_suggestion": "" if should_clear_advisor else state.get("advisor_suggestion", ""),
            "request_advisor_help": request_help
        }
    
    except Exception as e:
        default_logger.error(f"主攻手Agent调用失败: {e}")
        # 返回错误消息
        error_message = AIMessage(
            content=f"LLM调用失败: {str(e)}。请稍后重试或咨询顾问。"
        )
        return {
            "messages": [error_message],
            "request_advisor_help": True
        }

