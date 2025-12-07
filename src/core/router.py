"""
智能路由逻辑
决定Agent流程的下一步

智能路由策略：
1. 重复操作检测：相同工具连续失败 → 咨询顾问
2. 重复错误检测：相同错误类型重复 → 咨询顾问
3. 动态阈值：失败越多，咨询越频繁
4. 进展检测：长时间无进展 → 咨询顾问
5. 主动求助：主攻手主动请求 → 立即咨询
"""
from typing import Literal, Dict, Any
from src.core.state import PenetrationState
from src.utils.logger import default_logger
from src.utils.observability import get_tracker
import os


def should_continue(state: PenetrationState) -> Literal["advisor", "tools", "attacker", "end"]:
    """
    主路由函数
    决定下一步应该执行哪个节点
    
    Args:
        state: 当前状态
    
    Returns:
        下一个节点名称
    """
    messages = state.get("messages", [])
    tracker = get_tracker()
    
    # 0. 最高优先级：检查是否已完成（FLAG 或 is_finished）
    if state.get("flag"):
        default_logger.info(f"[Router] ✅ 已找到FLAG: {state.get('flag')}，任务完成")
        return "end"
    
    if state.get("is_finished"):
        default_logger.info("[Router] ✅ 任务已完成")
        return "end"
    
    # 0.1 检查消息中是否包含 **已验证** 的 FLAG（防止幻觉）
    from src.tools.flag_tool import extract_and_verify_flag
    for msg in messages[-5:]:  # 检查最近5条消息
        if hasattr(msg, "content") and msg.content:
            verified_flag = extract_and_verify_flag(str(msg.content))
            if verified_flag:
                default_logger.info(f"[Router] ✅ 在消息中检测到已验证的FLAG: {verified_flag}，任务完成")
                return "end"
            # 如果检测到 FLAG 格式但未验证通过，记录警告
            from src.tools.flag_tool import extract_flag_from_text
            unverified_flags = extract_flag_from_text(str(msg.content))
            if unverified_flags:
                default_logger.warning(f"[Router] ⚠️ 检测到未验证的FLAG: {unverified_flags}，继续执行（可能是幻觉）")
    
    # 初始状态：先咨询顾问
    if not messages:
        default_logger.info("[Router] 初始状态 → 咨询顾问")
        return "advisor"
    
    last_message = messages[-1]
    
    # 1. 检查是否有工具调用
    if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
        default_logger.info("[Router] 检测到工具调用 → 执行工具")
        return "tools"
    
    # 3. 检查是否超限
    attempt_count = state.get("attempt_count", 0)
    max_attempts = state.get("max_attempts", 50)
    
    if attempt_count >= max_attempts:
        default_logger.warning(f"[Router] ⚠️ 尝试次数超限 ({attempt_count}/{max_attempts})")
        return "end"
    
    # 4. 有顾问建议且未使用 → 主攻手决策
    if state.get("advisor_suggestion"):
        default_logger.info("[Router] 已有顾问建议 → 主攻手决策")
        if tracker:
            tracker.record_router_decision("attacker", reason="已有顾问建议")
        return "attacker"
    
    # 5. 默认：主攻手继续思考
    default_logger.info("[Router] 主攻手继续思考")
    if tracker:
        tracker.record_router_decision("attacker", reason="默认继续")
    return "attacker"


def _analyze_failure_pattern(state: PenetrationState) -> Dict[str, Any]:
    """
    分析失败模式
    
    Returns:
        失败模式分析结果
    """
    action_history = state.get("action_history", [])
    consecutive_failures = state.get("consecutive_failures", 0)
    last_action_type = state.get("last_action_type")
    
    # 分析最近的操作
    recent_actions = action_history[-10:] if len(action_history) >= 10 else action_history
    
    # 检测重复操作
    if len(recent_actions) >= 3:
        last_three = [a.split('[')[1].split(']')[0] if '[' in a else "" for a in recent_actions[-3:]]
        if len(set(last_three)) == 1 and last_three[0]:
            return {
                "is_repeating": True,
                "repeated_tool": last_three[0],
                "severity": "high"
            }
    
    # 检测相同错误类型
    error_patterns = {}
    for action in recent_actions:
        if "❌" in action:
            # 提取错误类型（简化）
            if "404" in action or "not found" in action.lower():
                error_patterns["404"] = error_patterns.get("404", 0) + 1
            elif "403" in action or "forbidden" in action.lower():
                error_patterns["403"] = error_patterns.get("403", 0) + 1
            elif "401" in action or "unauthorized" in action.lower():
                error_patterns["401"] = error_patterns.get("401", 0) + 1
            elif "timeout" in action.lower():
                error_patterns["timeout"] = error_patterns.get("timeout", 0) + 1
    
    # 如果同一错误重复3次以上
    for error_type, count in error_patterns.items():
        if count >= 3:
            return {
                "is_repeating_error": True,
                "error_type": error_type,
                "count": count,
                "severity": "high"
            }
    
    return {
        "is_repeating": False,
        "is_repeating_error": False,
        "severity": "low"
    }


def should_continue_after_tool(state: PenetrationState) -> Literal["advisor", "attacker", "end"]:
    """
    工具执行后的智能路由函数
    
    智能决策策略：
    1. 优先检查完成状态
    2. 检测重复操作模式（相同工具连续失败）
    3. 检测重复错误模式（相同错误类型）
    4. 连续失败阈值
    5. 主动求助
    6. 关键节点检查
    7. 默认连续攻击模式
    
    Args:
        state: 当前状态
    
    Returns:
        下一个节点名称
    """
    # 1. 优先检查是否完成
    if state.get("flag"):
        default_logger.info(f"[Router-Tool] ✅ 工具执行后检测到FLAG: {state.get('flag')}")
        return "end"
    
    if state.get("is_finished"):
        default_logger.info("[Router-Tool] ✅ 工具执行后任务完成")
        return "end"
    
    # 1.1 检查消息中是否包含 **已验证** 的 FLAG（防止幻觉）
    from src.tools.flag_tool import extract_and_verify_flag, extract_flag_from_text
    messages = state.get("messages", [])
    for msg in messages[-3:]:  # 检查最近3条消息
        if hasattr(msg, "content") and msg.content:
            verified_flag = extract_and_verify_flag(str(msg.content))
            if verified_flag:
                default_logger.info(f"[Router-Tool] ✅ 在工具输出中检测到已验证的FLAG: {verified_flag}")
                return "end"
            # 如果检测到 FLAG 格式但未验证通过，记录警告
            unverified_flags = extract_flag_from_text(str(msg.content))
            if unverified_flags:
                default_logger.warning(f"[Router-Tool] ⚠️ 检测到未验证的FLAG: {unverified_flags}，继续执行（可能是幻觉）")
    
    # 2. 检查是否超限
    attempt_count = state.get("attempt_count", 0)
    max_attempts = state.get("max_attempts", 50)
    
    if attempt_count >= max_attempts:
        default_logger.warning(f"[Router-Tool] ⚠️ 尝试次数超限")
        return "end"
    
    # 3. 智能决策：是否需要顾问介入
    consecutive_failures = state.get("consecutive_failures", 0)
    request_help = state.get("request_advisor_help", False)
    
    # 配置参数
    failure_threshold = int(os.getenv("ADVISOR_FAILURE_THRESHOLD", "3"))
    consultation_interval = int(os.getenv("ADVISOR_CONSULTATION_INTERVAL", "5"))
    enable_smart_routing = os.getenv("ENABLE_SMART_ROUTING", "true").lower() == "true"
    
    # 3.0 元认知评估（最高优先级）
    enable_metacognition = os.getenv("ENABLE_METACOGNITION", "true").lower() == "true"
    if enable_metacognition:
        try:
            from src.utils.metacognition import get_metacognitive_assessor
            from src.utils.llm_client import LLMClient
            
            # 获取最后一次操作结果
            last_result = ""
            messages = state.get("messages", [])
            if messages:
                last_msg = messages[-1]
                if hasattr(last_msg, "content") and last_msg.content:
                    last_result = str(last_msg.content)[:500]
            
            # 初始化元认知评估器
            llm_client = LLMClient() if os.getenv("USE_LLM_METACOGNITION", "false").lower() == "true" else None
            assessor = get_metacognitive_assessor(llm_client)
            
            # 获取之前的信心值（用于更新计算）
            previous_confidence = state.get("confidence_score")
            
            # 评估信心（如果有之前的信心值，会使用更新公式）
            confidence_assessment = assessor.assess_confidence(
                state,
                last_result,
                previous_confidence
            )
            confidence_level = confidence_assessment.get("confidence_level", "medium")
            confidence_score = confidence_assessment.get("confidence_score", 50.0)
            
            # 根据信心水平决定是否咨询顾问（参考Cyber-AutoAgent: <50%咨询）
            if assessor.should_consult_advisor(state, confidence_assessment):
                default_logger.info(
                    f"[Router-Tool] 🧠 元认知评估: 信心{confidence_score:.1f}% ({confidence_level})，<50%建议咨询顾问"
                )
                return "advisor"
            else:
                strategy = assessor.get_tool_selection_strategy(confidence_score)
                default_logger.info(
                    f"[Router-Tool] 🧠 元认知评估: 信心{confidence_score:.1f}% ({confidence_level})，策略: {strategy}"
                )
        except Exception as e:
            default_logger.debug(f"元认知评估失败: {e}，继续使用其他规则")
    
    # 3.1 智能模式检测（优先于其他规则）
    if enable_smart_routing:
        failure_pattern = _analyze_failure_pattern(state)
        
        # 检测到重复操作模式
        if failure_pattern.get("is_repeating"):
            repeated_tool = failure_pattern.get("repeated_tool", "unknown")
            default_logger.warning(
                f"[Router-Tool] 🔄 检测到重复操作模式: {repeated_tool}，请求顾问帮助"
            )
            return "advisor"
        
        # 检测到重复错误模式
        if failure_pattern.get("is_repeating_error"):
            error_type = failure_pattern.get("error_type", "unknown")
            count = failure_pattern.get("count", 0)
            default_logger.warning(
                f"[Router-Tool] 🔄 检测到重复错误模式: {error_type} (出现{count}次)，请求顾问帮助"
            )
            return "advisor"
    
    # 3.1 连续失败达到阈值（动态阈值）
    # 失败越多，阈值越小（更频繁咨询）
    dynamic_threshold = failure_threshold
    if consecutive_failures >= 6:
        dynamic_threshold = 2  # 失败6次后，每2次失败就咨询
    elif consecutive_failures >= 3:
        dynamic_threshold = failure_threshold
    
    if consecutive_failures > 0 and consecutive_failures % dynamic_threshold == 0:
        last_advisor_at = state.get("last_advisor_at_failures", 0)
        if consecutive_failures != last_advisor_at:
            default_logger.info(
                f"[Router-Tool] 🆘 连续失败 {consecutive_failures} 次（阈值: {dynamic_threshold}），请求顾问帮助"
            )
            return "advisor"
    
    # 3.2 主攻手主动请求帮助（最高优先级）
    if request_help:
        default_logger.info("[Router-Tool] 🆘 主攻手主动请求顾问帮助")
        return "advisor"
    
    # 3.3 关键节点检查（动态间隔）
    # 尝试次数越多，咨询间隔越小
    dynamic_interval = consultation_interval
    if attempt_count >= 30:
        dynamic_interval = 3  # 30次后，每3次咨询一次
    elif attempt_count >= 15:
        dynamic_interval = 4  # 15次后，每4次咨询一次
    
    if attempt_count > 0 and attempt_count % dynamic_interval == 0:
        default_logger.info(
            f"[Router-Tool] 🔄 达到关键节点（第 {attempt_count} 次尝试，间隔: {dynamic_interval}），咨询顾问"
        )
        return "advisor"
    
    # 3.4 检查是否有进展（如果长时间没有进展，咨询顾问）
    if attempt_count >= 10:
        action_history = state.get("action_history", [])
        recent_successes = sum(1 for a in action_history[-10:] if "✅" in a)
        if recent_successes == 0 and attempt_count >= 10:
            default_logger.warning(
                f"[Router-Tool] ⚠️ 最近10次操作无成功，请求顾问帮助"
            )
            return "advisor"
    
    # 3.5 默认：返回主攻手（连续攻击模式）
    default_logger.info(
        f"[Router-Tool] ⚡ 工具执行完毕 → 返回主攻手（连续攻击模式，失败: {consecutive_failures}）"
    )
    return "attacker"

