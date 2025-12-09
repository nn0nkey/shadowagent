"""
Reflector Agent - 反思器

职责：
1. 审核 Attacker 的执行结果，验证真实性
2. 失败分级（L1-L4）
3. 提取攻击情报
4. 提供恢复建议

作者: ShadowAgent Team
"""

import json
import re
from typing import Dict, List, Any, Optional
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, AIMessage

from src.core.state import PenetrationState
from src.utils.logger import default_logger


# Reflector 系统提示词
REFLECTOR_SYSTEM_PROMPT = """你是一个严格的安全审核员（Reflector），负责验证渗透测试结果的真实性。

## 核心职责（按优先级）

### 1. 结果真实性验证 [CRITICAL]
- **防止 LLM 幻觉**：Attacker 可能声称"成功"，但实际失败
- **证据驱动**：只有明确的证据才能判定为 VERIFIED
- **严格标准**：宁可保守判断，也不要误判成功

### 2. 失败分级（L0-L5）[CRITICAL]
- **严格的递进归因**：只有在排除低层级原因后，才能归因到高层级
- **精确定位**：快速找到问题根源
- **可操作建议**：每个级别都有对应的恢复策略

### 3. 效率审计 [HIGH PRIORITY]
- **检测拖延**：在已确认漏洞上花费 >3 步骤未提取产物 → 判定为"拖延"
- **结果导向**：分析是手段，不是目的。目标是获取决定性证据
- **时间/产出比**：评估当前行动的 ROI

### 4. 未遂机会识别 [HIGH PRIORITY]
- **部分成功信号**：延时波动、报错变化、响应长度变化
- **不放弃**：建议微调而非直接放弃
- **教练视角**：关注"异常反应"而非二元成败

## 失败分级标准（L0-L5）

### L0: 原始观察（Observation）
- 来自工具的原始、未解释的输出
- 纯粹的观察数据，不包含任何解释
- **示例**：`curl: (7) Failed to connect`

### L1: 工具执行失败（Tool Failure）
- 网络超时、连接失败、DNS 解析失败
- 命令不存在、语法错误、权限不足
- **特征**：技术性错误，与策略无关
- **处理**：重试、调整参数、检查环境

### L2: 前提条件失败（Prerequisite Failure）
- 会话过期、认证失败、Cookie/Token 失效
- 依赖资源不可用
- **特征**：前提条件不满足（如 401 Unauthorized）
- **处理**：重新登录、刷新 Token、检查会话

### L3: 环境干扰（Environment）
- WAF 拦截、防火墙阻断、速率限制
- IP 封禁、目标服务无响应
- **特征**：环境阻断（如 403 Forbidden、WAF 拦截）
- **处理**：切换 IP、调整请求频率、绕过 WAF

### L4: 假设被证伪（Hypothesis）
- 参数不存在 SQL 注入、过滤器无法绕过
- 漏洞不存在、推理链条断裂
- **特征**：基础假设错误（排除 L0-L3 后）
- **处理**：重新评估、切换攻击向量、调整假设

### L5: 战略失败（Strategy）
- 攻击路径选择错误、策略僵局、目标漂移
- 连续 L4 失败形成模式
- **特征**：整体战略存在缺陷
- **处理**：终止任务、生成报告、建议人工介入

## 归因原则（严格递进）

**必须按顺序检查，不可跳级**：

1. **L0 → L1**：首先检查工具是否正常执行
2. **L1 → L2**：检查前提条件是否满足（认证、会话）
3. **L2 → L3**：检查环境是否阻断（WAF、防火墙）
4. **L3 → L4**：排除 L0-L3 后，才能归因为假设被证伪
5. **L4 → L5**：多个 L4 失败形成模式时，归因为战略失败

**示例**：
```
错误输出：401 Unauthorized
❌ 错误归因：L4（假设被证伪）
✅ 正确归因：L2（前提条件失败 - 认证失败）

错误输出：WAF blocked
❌ 错误归因：L4（假设被证伪）
✅ 正确归因：L3（环境干扰 - WAF 拦截）
```

## 效率审计原则

### 1. 检测拖延行为
- **标准**：已确认漏洞但 >3 步骤未尝试利用
- **判定**：STALLING（拖延）
- **建议**：立即停止分析，开始利用

### 2. 结果导向
- **目标**：获取决定性证据（FLAG、数据、Shell）
- **拒绝**：完美分析报告但无证据 = 失败
- **原则**：如果知道漏洞在哪里，不要盯着它看，动手验证其影响

### 3. 时间/产出比
- **评估**：当前步骤是否产生实质性进展
- **标准**：每个步骤都应该接近目标
- **警告**：重复分析相同的点 → 拖延

## 未遂机会识别

### 信号类型

1. **延时波动**
   - Payload 引发延时（但不是预期的延时）
   - **示例**：`SLEEP(5)` 导致 0.5 秒延时（不是 5 秒）
   - **判断**：未遂机会！说明有注入但被过滤
   - **建议**：尝试编码绕过、调整延时时间

2. **报错变化**
   - Payload 触发了不同于基线的错误
   - **示例**：正常请求无错误，Payload 触发 SQL 语法错误
   - **判断**：高价值信号！
   - **建议**：分析错误信息，调整 Payload 结构

3. **响应长度变化**
   - 响应长度有微小变化（10-1000 字节）
   - **示例**：基线 1234 字节，Payload 1250 字节
   - **判断**：可能触发了不同的代码路径
   - **建议**：继续微调，严禁直接放弃

## 审核原则

1. **严格验证**：不要被 LLM 的"我觉得成功了"欺骗
2. **证据驱动**：只有明确的证据才能判定为 VERIFIED
3. **精确分级**：准确判断失败级别，避免误判
4. **提取情报**：即使失败，也要提取有价值的信息

## 输出格式（JSON）

```json
{
  "audit_result": {
    "status": "VERIFIED" | "FAILED" | "PARTIAL",
    "confidence": 0.0-1.0,
    "reasoning": "详细说明判断依据，引用具体证据"
  },
  "failure_analysis": {
    "level": "L1" | "L2" | "L3" | "L4" | null,
    "root_cause": "失败的根本原因",
    "recommendations": ["具体的恢复建议"]
  },
  "intelligence": {
    "key_findings": ["关键发现"],
    "attack_vectors": ["可用的攻击向量"],
    "discovered_info": {
      "endpoints": [],
      "parameters": [],
      "technologies": [],
      "credentials": []
    }
  }
}
```

## 判断标准

### VERIFIED（验证成功）
- 找到了 FLAG（格式：FLAG{...} 或 flag{...}）
- 成功执行了关键操作（登录、权限提升、数据读取）
- 有明确的成功证据（响应码、返回内容）

### FAILED（失败）
- 错误信息明确
- 操作未达成目标
- 需要分级（L1-L4）

### PARTIAL（部分成功）
- 取得了进展但未完成目标
- 绕过了某个防护但还需要进一步操作
- 发现了有价值的信息但未利用

## 注意事项

1. **不要过度乐观**：宁可保守判断，也不要误判成功
2. **关注细节**：仔细分析输出内容，寻找成功/失败的证据
3. **上下文感知**：结合任务目标和历史记录判断
4. **提供价值**：即使失败，也要提取有用的情报和建议
"""


async def reflector_node(state: PenetrationState) -> PenetrationState:
    """
    Reflector Agent 节点
    
    核心职责：
    1. 验证结果真实性（防止 LLM 幻觉）
    2. 失败分级（L0-L5）
    3. 效率审计（检测拖延）
    4. 未遂机会识别（部分成功）
    
    整合现有工具：
    - RepetitionDetector：重复模式检测
    - MetacognitiveAssessor：信心评估
    - KeyDiscoveryManager：关键发现
    
    Args:
        state: 当前状态
    
    Returns:
        更新后的状态（包含审核结果）
    """
    from langchain_openai import ChatOpenAI
    import os
    from src.utils.observability import get_tracker, OperationType
    
    default_logger.info("⚖️ [Reflector] 开始审核执行结果...")
    
    # 开始追踪
    tracker = get_tracker()
    if tracker:
        tracker.start_operation(
            OperationType.AGENT_DECISION,
            agent_name="reflector",
            input_data={"challenge": state.get("current_challenge", {})}
        )
    
    # 获取 LLM（支持单独配置 Reflector 模型）
    reflector_model = os.getenv("REFLECTOR_LLM_MODEL") or os.getenv("LLM_MODEL", "deepseek-ai/DeepSeek-V3.2")
    
    default_logger.info(f"⚖️ [Reflector] 使用模型: {reflector_model}")
    
    llm = ChatOpenAI(
        model=reflector_model,
        api_key=os.getenv("OPENAI_API_KEY"),
        base_url=os.getenv("OPENAI_API_BASE", "https://api-inference.modelscope.cn/v1/"),
        temperature=0.7,
        max_tokens=4096,
        timeout=120
    )
    
    # 整合现有工具
    # 1. 获取重复检测结果
    repetition_info = ""
    try:
        from src.utils.repetition_detector import get_repetition_detector
        detector = get_repetition_detector()
        repetition = detector.detect_repetition()
        if repetition:
            repetition_info = f"""
## 重复模式检测（RepetitionDetector）

{repetition.suggestion}

**注意**：如果连续失败且模式相同，可能需要判断为 L4（假设被证伪）或 L5（战略失败）
"""
    except Exception as e:
        default_logger.debug(f"[Reflector] 获取重复检测结果失败: {e}")
    
    # 2. 获取信心评估结果
    confidence_info = ""
    confidence_score = state.get("confidence_score", 50.0)
    if confidence_score:
        confidence_level = "high" if confidence_score >= 70 else "medium" if confidence_score >= 40 else "low"
        confidence_info = f"""
## 信心评估（MetacognitiveAssessor）

- 当前信心：{confidence_score:.1f}% ({confidence_level})
- **参考**：信心低可能表明策略有问题
"""
    
    # 获取最后一次执行的结果
    messages = state.get("messages", [])
    if not messages:
        default_logger.warning("[Reflector] 没有消息历史，跳过审核")
        return state
    
    # 找到最后一次 tool 消息
    last_tool_message = None
    last_attacker_message = None
    
    for msg in reversed(messages):
        if hasattr(msg, 'type'):
            if msg.type == "tool" and last_tool_message is None:
                last_tool_message = msg
            elif msg.type == "ai" and last_attacker_message is None:
                last_attacker_message = msg
        
        if last_tool_message and last_attacker_message:
            break
    
    if not last_tool_message:
        default_logger.warning("[Reflector] 没有找到工具执行结果，跳过审核")
        return state
    
    # 构建审核 Prompt
    challenge = state.get("current_challenge", {})
    task_goal = challenge.get("description", "找到 FLAG")
    
    tool_output = last_tool_message.content if hasattr(last_tool_message, 'content') else str(last_tool_message)
    attacker_thought = ""
    if last_attacker_message and hasattr(last_attacker_message, 'content'):
        attacker_thought = last_attacker_message.content
    
    # 获取失败历史（用于 L3 判断）
    failure_history = state.get("failure_history", [])
    consecutive_failures = state.get("consecutive_failures", 0)
    attempt_count = state.get("attempt_count", 0)
    
    # 构建上下文
    failure_context = ""
    if consecutive_failures > 0:
        failure_context = f"""
## 失败历史

- 连续失败次数: {consecutive_failures}
- 总尝试次数: {attempt_count}
- 最近失败记录: {len(failure_history)} 条

**注意**：如果连续失败多次且方向相同，可能需要判断为 L3（假设验证失败）
"""
    
    prompt = f"""
## 任务目标

{task_goal}

## Attacker 的思考过程

{attacker_thought[:1000] if attacker_thought else "（无）"}

## 工具执行结果

```
{tool_output[:2000]}
```

{repetition_info}

{confidence_info}

{failure_context}

## 你的任务

请严格审核上述执行结果，按以下优先级执行：

### 1. 结果真实性验证 [CRITICAL]
- 是否找到了 FLAG？（格式：FLAG{{...}} 或 flag{{...}}）
- Attacker 声称的"成功"是否有明确证据支持？
- 不要被 LLM 幻觉欺骗！

### 2. 失败分级（L0-L5）[CRITICAL]
- **严格递进归因**：L0 → L1 → L2 → L3 → L4 → L5
- 不可跳级！必须排除低层级原因后才能归因高层级
- 参考上述重复模式检测和信心评估结果

### 3. 效率审计 [HIGH PRIORITY]
- 是否在已确认漏洞上拖延（>3 步骤未利用）？
- 是否重复分析相同的点？
- 当前步骤是否产生实质性进展？

### 4. 未遂机会识别 [HIGH PRIORITY]
- 是否有延时波动、报错变化、响应长度变化？
- 这些信号可能表明部分成功，不要直接放弃

**输出 JSON 格式**（必须严格遵守）：
```json
{{
  "audit_result": {{
    "status": "VERIFIED" | "FAILED" | "PARTIAL",
    "confidence": 0.0-1.0,
    "reasoning": "详细说明判断依据，引用具体证据"
  }},
  "failure_analysis": {{
    "level": "L0" | "L1" | "L2" | "L3" | "L4" | "L5" | null,
    "root_cause": "失败的根本原因（严格递进归因）",
    "recommendations": ["具体的恢复建议"],
    "is_stalling": false,
    "is_near_miss": false
  }},
  "intelligence": {{
    "key_findings": ["关键发现"],
    "attack_vectors": ["可用的攻击向量"],
    "discovered_info": {{
      "endpoints": [],
      "parameters": [],
      "technologies": [],
      "credentials": []
    }}
  }},
  "efficiency_audit": {{
    "is_stalling": false,
    "stalling_reason": "",
    "time_wasted_steps": 0,
    "recommendation": ""
  }},
  "near_miss": {{
    "is_near_miss": false,
    "signal_type": "",
    "description": "",
    "recommendation": ""
  }}
}}
```
"""
    
    try:
        # 调用 LLM（带重试机制）
        max_retries = 3
        retry_delay = 60  # 秒
        
        for attempt in range(max_retries):
            try:
                response = await llm.ainvoke([
                    HumanMessage(content=REFLECTOR_SYSTEM_PROMPT),
                    HumanMessage(content=prompt)
                ])
                break  # 成功则跳出重试循环
            except Exception as e:
                error_msg = str(e)
                if ("429" in error_msg or "rate limit" in error_msg.lower()) and attempt < max_retries - 1:
                    default_logger.warning(
                        f"⚖️ [Reflector] 遇到速率限制 (尝试 {attempt + 1}/{max_retries})，等待 {retry_delay} 秒..."
                    )
                    import asyncio
                    await asyncio.sleep(retry_delay)
                else:
                    raise  # 非速率限制错误或最后一次尝试，直接抛出
        
        # 解析响应
        response_text = response.content
        
        # 提取 JSON
        reflection_data = _extract_json_from_response(response_text)
        
        if not reflection_data:
            default_logger.error("[Reflector] 无法解析 LLM 响应")
            # 返回默认的失败结果
            reflection_data = {
                "audit_result": {
                    "status": "FAILED",
                    "confidence": 0.5,
                    "reasoning": "Reflector 解析失败"
                },
                "failure_analysis": {
                    "level": "L1",
                    "root_cause": "Reflector 内部错误",
                    "recommendations": ["重试"]
                },
                "intelligence": {
                    "key_findings": [],
                    "attack_vectors": [],
                    "discovered_info": {}
                }
            }
        
        # 记录审核结果
        status = reflection_data["audit_result"]["status"]
        confidence = reflection_data["audit_result"]["confidence"]
        reasoning = reflection_data["audit_result"]["reasoning"]
        
        default_logger.info(f"⚖️ [Reflector] 审核结果: {status} (置信度: {confidence:.2f})")
        default_logger.info(f"⚖️ [Reflector] 判断依据: {reasoning[:200]}...")
        
        # 如果失败，记录失败级别
        if status == "FAILED":
            failure_level = reflection_data["failure_analysis"]["level"]
            root_cause = reflection_data["failure_analysis"]["root_cause"]
            default_logger.warning(f"⚖️ [Reflector] 失败级别: {failure_level}")
            default_logger.warning(f"⚖️ [Reflector] 根本原因: {root_cause}")
            
            # 记录到失败历史
            if "failure_history" not in state:
                state["failure_history"] = []
            
            state["failure_history"].append({
                "attempt": attempt_count,
                "level": failure_level,
                "root_cause": root_cause,
                "output": tool_output[:500]
            })
            
            # 只保留最近 10 条
            if len(state["failure_history"]) > 10:
                state["failure_history"] = state["failure_history"][-10:]
        
        # 提取情报
        intelligence = reflection_data.get("intelligence", {})
        key_findings = intelligence.get("key_findings", [])
        if key_findings:
            default_logger.info(f"💡 [Reflector] 关键发现: {', '.join(key_findings[:3])}")
        
        # 将审核结果添加到状态
        state["last_reflection"] = reflection_data
        
        # 添加到消息历史
        reflection_summary = f"""## ⚖️ Reflector 审核结果

**状态**: {status} (置信度: {confidence:.2f})

**判断依据**: {reasoning}

"""
        
        if status == "FAILED":
            failure_level = reflection_data["failure_analysis"]["level"]
            recommendations = reflection_data["failure_analysis"]["recommendations"]
            reflection_summary += f"""**失败级别**: {failure_level}

**根本原因**: {root_cause}

**恢复建议**:
{chr(10).join(f'- {r}' for r in recommendations)}
"""
        
        if key_findings:
            reflection_summary += f"""
**关键发现**:
{chr(10).join(f'- {f}' for f in key_findings)}
"""
        
        state["messages"].append(
            AIMessage(content=reflection_summary, name="reflector")
        )
        
        default_logger.info("✅ [Reflector] 审核完成")
        
        # 结束追踪 - 成功
        if tracker:
            tracker.end_operation(
                success=True,
                output_data={"reflection": reflection_data}
            )
        
    except Exception as e:
        default_logger.error(f"❌ [Reflector] 审核失败: {e}")
        # 添加错误消息
        state["messages"].append(
            AIMessage(
                content=f"## ⚠️ Reflector 审核失败\n\n错误: {str(e)}",
                name="reflector"
            )
        )
        # 设置默认的失败结果
        state["last_reflection"] = {
            "audit_result": {
                "status": "FAILED",
                "confidence": 0.5,
                "reasoning": f"Reflector 内部错误: {str(e)}"
            },
            "failure_analysis": {
                "level": "L1",
                "root_cause": "Reflector 内部错误",
                "recommendations": ["重试"]
            },
            "intelligence": {
                "key_findings": [],
                "attack_vectors": [],
                "discovered_info": {}
            }
        }
        
        # 结束追踪 - 失败
        if tracker:
            tracker.end_operation(
                success=False,
                output_data={"error": str(e)}
            )
    
    return state


def _extract_json_from_response(text: str) -> Optional[Dict]:
    """
    从 LLM 响应中提取 JSON
    
    Args:
        text: LLM 响应文本
    
    Returns:
        解析后的 JSON 字典，如果失败返回 None
    """
    # 尝试直接解析
    try:
        return json.loads(text)
    except:
        pass
    
    # 尝试提取 JSON 代码块
    json_pattern = r'```(?:json)?\s*(\{.*?\})\s*```'
    matches = re.findall(json_pattern, text, re.DOTALL)
    
    if matches:
        try:
            return json.loads(matches[0])
        except:
            pass
    
    # 尝试查找 JSON 对象
    json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
    matches = re.findall(json_pattern, text, re.DOTALL)
    
    for match in matches:
        try:
            data = json.loads(match)
            # 验证是否包含必需字段
            if "audit_result" in data:
                return data
        except:
            continue
    
    return None
