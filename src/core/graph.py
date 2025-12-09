"""
LangGraph图构建
定义Agent的工作流程
"""
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.language_models import BaseChatModel
from src.core.state import PenetrationState
from src.agents.advisor import advisor_node
from src.agents.attacker import attacker_node
from src.agents.reflector import reflector_node
from src.core.router import should_continue, should_continue_after_tool, should_continue_after_reflection
from src.utils.logger import default_logger
from src.utils.observability import get_tracker, OperationType
import time
from src.tools.command_tool import execute_command
from src.tools.python_tool import execute_python_poc
from src.tools.flag_tool import submit_flag
from src.tools.knowledge_tool import search_knowledge
import os


async def build_agent_graph(
    main_llm: BaseChatModel,
    advisor_llm: BaseChatModel = None
) -> StateGraph:
    """
    构建LangGraph Agent图
    
    Args:
        main_llm: 主攻手LLM
        advisor_llm: 顾问LLM（可选，如果为None则使用main_llm）
    
    Returns:
        编译后的LangGraph应用
    """
    default_logger.info("--- 构建双Agent协作图 ---")
    
    # 获取所有工具（极简工具集：3个核心工具 + 1个知识库工具）
    tools = [
        execute_command,      # 执行 Kali 工具和 shell 命令
        execute_python_poc,   # 执行 Python 自动化脚本
        submit_flag,          # 提交 FLAG
        search_knowledge      # 检索知识库（按需）
    ]
    tool_node = ToolNode(tools)
    
    # 自定义工具节点（用于状态更新和FLAG检测）
    async def custom_tool_node(state: PenetrationState) -> PenetrationState:
        """
        自定义工具节点
        执行工具后更新状态，检测FLAG等
        同时进行知识库检索增强和输出压缩
        """
        # 追踪工具执行
        tracker = get_tracker()
        tool_start_time = time.time()
        
        # 记录工具调用
        messages = state.get("messages", [])
        tool_name = None
        if messages:
            last_msg = messages[-1]
            if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
                tool_name = last_msg.tool_calls[0].get("name", "unknown")
                if tracker:
                    tracker.start_operation(
                        OperationType.TOOL_EXECUTION,
                        agent_name="attacker",
                        tool_name=tool_name,
                        input_data={"tool_calls": last_msg.tool_calls}
                    )
        
        # 先执行基础工具调用
        result = await tool_node.ainvoke(state)
        
        # 记录工具执行结果
        if tracker and tool_name:
            duration_ms = (time.time() - tool_start_time) * 1000
            output_messages = result.get("messages", [])
            output_data = {}
            if output_messages:
                last_output = output_messages[-1]
                if hasattr(last_output, "content"):
                    output_data = {"content": str(last_output.content)[:500]}
            
            # 判断是否成功
            is_success = True
            if output_messages:
                last_output = output_messages[-1]
                if hasattr(last_output, "content"):
                    content = str(last_output.content).lower()
                    failure_keywords = ["error", "failed", "exception", "无法", "错误", "失败"]
                    if any(kw in content for kw in failure_keywords):
                        is_success = False
            
            # 结束本次工具执行的可观测性操作（持续时间由追踪器内部计算）
            tracker.end_operation(
                success=is_success,
                output_data=output_data,
            )
        
        # 更新尝试计数
        attempt_count = state.get("attempt_count", 0) + 1
        result["attempt_count"] = attempt_count
        
        # 记录工具执行结果到报告
        from src.utils.report_generator import get_report_generator
        report_gen = get_report_generator()
        
        # 从工具输出中提取关键发现（API端点、参数名、权限限制等）
        from src.utils.key_discovery import get_key_discovery_manager
        discovery_manager = get_key_discovery_manager()
        
        # 全局解析器：使用 HaE 规则提取关键信息（新增）⭐
        from src.utils.global_parser import get_global_parser
        global_parser = get_global_parser()
        
        messages = result.get("messages", [])
        for msg in messages:
            if hasattr(msg, "content") and msg.content:
                content = str(msg.content)
                # 记录工具结果（截取前 500 字符）
                report_gen.add_agent_log("attacker", "tool_result", content[:500])
                
                # 全局解析：使用 HaE 规则提取信息（自动缓存，相同响应只解析一次）⭐
                if len(content) > 100:  # 只解析较长的输出
                    parsed_results = global_parser.parse(content)
                    
                    # 将解析结果添加到状态中（供后续 Agent 使用）
                    if parsed_results:
                        # 存储到状态的 parsed_info 字段
                        if "parsed_info" not in result:
                            result["parsed_info"] = []
                        result["parsed_info"].append({
                            "tool": tool_name,
                            "results": parsed_results,
                            "summary": global_parser.get_summary(parsed_results)
                        })
                        
                        # 将 HAE 提取结果添加到 KeyDiscoveryManager（统一管理）
                        # 凭证（格式：{username, password, source}）
                        if "credentials" in parsed_results and parsed_results["credentials"]:
                            for cred_dict in parsed_results["credentials"]:
                                # 格式化为 username:password
                                cred_str = f"{cred_dict.get('username', '')}:{cred_dict.get('password', '')}"
                                discovery_manager.add_discovery(
                                    "credential",
                                    cred_str,
                                    source=f"hae_{tool_name}",
                                    confidence=95
                                )
                                default_logger.info(f"🔍 [HAE 凭证] {cred_str}")
                        
                        # 表单
                        if "form" in parsed_results:
                            for form in parsed_results["form"]:
                                discovery_manager.add_discovery(
                                    "form",
                                    form,
                                    source=f"hae_{tool_name}",
                                    confidence=90
                                )
                        
                        # SQL 错误
                        if "sql_error" in parsed_results:
                            for error in parsed_results["sql_error"]:
                                discovery_manager.add_discovery(
                                    "injection_point",
                                    f"SQL error: {error}",
                                    source=f"hae_{tool_name}",
                                    confidence=90
                                )
                        
                        # IDOR 指示器
                        if "idor_point" in parsed_results:
                            for point in parsed_results["idor_point"]:
                                discovery_manager.add_discovery(
                                    "idor_point",
                                    point,
                                    source=f"hae_{tool_name}",
                                    confidence=85
                                )
                        
                        # 权限字段
                        if "privilege_field" in parsed_results:
                            for field in parsed_results["privilege_field"]:
                                discovery_manager.add_discovery(
                                    "privilege_field",
                                    field,
                                    source=f"hae_{tool_name}",
                                    confidence=90
                                )
                
                # 提取关键发现（API端点、参数名、权限限制等）
                new_discoveries = discovery_manager.extract_from_output(content, source=tool_name or "tool")
                if new_discoveries:
                    for d in new_discoveries:
                        default_logger.info(f"🔍 [关键发现] {d.category}: {d.content}")
        
        # 检查工具输出中是否包含 **已验证** 的 FLAG（防止幻觉）
        from src.tools.flag_tool import extract_and_verify_flag, extract_flag_from_text
        for msg in messages:
            if hasattr(msg, "content") and msg.content:
                # 优先使用验证后的 FLAG
                verified_flag = extract_and_verify_flag(msg.content)
                if verified_flag:
                    result["flag"] = verified_flag
                    result["is_finished"] = True
                    default_logger.info(f"🏆 自动检测到已验证的FLAG: {verified_flag}")
                    
                    # 记录FLAG发现
                    if tracker:
                        tracker.record_flag_found(verified_flag)
                    break
                
                # 如果检测到 FLAG 格式但未验证通过，记录警告（不设置 flag）
                unverified_flags = extract_flag_from_text(msg.content)
                if unverified_flags:
                    default_logger.warning(f"⚠️ 检测到未验证的FLAG: {unverified_flags}，需要验证（可能是幻觉）")
        
        # 检查submit_flag的结果（验证通过）
        if messages:
            last_msg = messages[-1]
            if hasattr(last_msg, "content") and "✅ FLAG验证通过" in last_msg.content:
                result["flag"] = state.get("flag")  # 保持FLAG
                result["is_finished"] = True
                default_logger.info("✅ FLAG验证通过，任务完成")
        
        # 分析工具执行结果，更新失败计数
        # （这里简化处理，实际可以更智能地判断成功/失败）
        # 如果工具输出包含错误关键词，认为是失败
        failure_keywords = ["error", "failed", "exception", "无法", "错误", "失败"]
        is_failure = False
        
        for msg in messages:
            if hasattr(msg, "content") and msg.content:
                content_lower = str(msg.content).lower()
                if any(kw in content_lower for kw in failure_keywords):
                    is_failure = True
                    break
        
        consecutive_failures = state.get("consecutive_failures", 0)
        if is_failure:
            consecutive_failures += 1
        else:
            consecutive_failures = 0  # 成功则重置
        
        result["consecutive_failures"] = consecutive_failures
        
        # 记录操作历史
        if messages:
            last_msg = messages[-1]
            if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
                tool_name = last_msg.tool_calls[0].get("name", "unknown")
                status_emoji = "❌" if is_failure else "✅"
                action_record = f"{status_emoji} [{tool_name}]"
                
                action_history = state.get("action_history", [])
                action_history.append(action_record)
                result["action_history"] = action_history[-20:]  # 保留最近20条
        
        # 工具输出智能提取（如果输出过长）
        tool_output_threshold = int(os.getenv("TOOL_OUTPUT_THRESHOLD", "5000"))
        for msg in messages:
            if hasattr(msg, "content") and msg.content:
                content = str(msg.content)
                
                # 1. 提取关键发现（永不丢弃）
                try:
                    from src.utils.key_discovery import get_key_discovery_manager
                    discovery_manager = get_key_discovery_manager()
                    new_discoveries = discovery_manager.extract_from_output(content, source=tool_name or "tool")
                    if new_discoveries:
                        default_logger.info(f"🔍 发现 {len(new_discoveries)} 个关键信息")
                        # 更新状态中的关键发现
                        key_discoveries = state.get("key_discoveries", [])
                        key_discoveries.extend([d.to_dict() for d in new_discoveries])
                        result["key_discoveries"] = key_discoveries
                except Exception as e:
                    default_logger.debug(f"关键发现提取失败: {e}")
                
                # 2. 重复检测（检测相同请求参数 + 相同响应长度）
                try:
                    from src.utils.repetition_detector import get_repetition_detector
                    detector = get_repetition_detector()
                    
                    # 提取响应长度
                    response_length = detector.extract_response_length(content)
                    if response_length:
                        # 从工具调用中提取请求参数
                        request_params = ""
                        state_messages = state.get("messages", [])
                        if state_messages:
                            last_ai_msg = state_messages[-1]
                            if hasattr(last_ai_msg, "tool_calls") and last_ai_msg.tool_calls:
                                args = last_ai_msg.tool_calls[0].get("args", {})
                                code = args.get("code", "") or args.get("command", "")
                                # 提取请求参数（GET/POST 参数）
                                request_params = detector.extract_request_params(code)
                        
                        detector.record_response(
                            response_length=response_length,
                            request_params=request_params
                        )
                        
                        # 检测重复
                        repetition = detector.detect_repetition()
                        if repetition:
                            default_logger.warning(f"⚠️ 检测到重复模式: {repetition.pattern_type} = {repetition.value}")
                            # 更新策略切换计数
                            strategy_switch_count = state.get("strategy_switch_count", 0) + 1
                            result["strategy_switch_count"] = strategy_switch_count
                except Exception as e:
                    default_logger.debug(f"重复检测失败: {e}")
                
                # 3. 智能提取（如果输出过长）
                if len(content) > tool_output_threshold:
                    try:
                        from src.utils.context_compressor import extract_key_output
                        # 使用智能提取函数，保留关键信息
                        msg.content = extract_key_output(content, tool_output_threshold)
                        default_logger.info(f"工具输出已智能提取: {len(content)} → {len(msg.content)} 字符")
                    except Exception as e:
                        default_logger.debug(f"工具输出提取失败: {e}")
                        # 降级：简单截断，但保留头尾
                        head = content[:tool_output_threshold // 2]
                        tail = content[-(tool_output_threshold // 2):]
                        msg.content = f"{head}\n\n... [中间部分已省略] ...\n\n{tail}"
        
        # 记忆存储：自动存储重要发现（参考Cyber-AutoAgent）
        try:
            from src.utils.memory_store import get_memory_store
            
            memory_store = get_memory_store()
            if memory_store.enabled:
                # 检查是否有重要发现需要存储
                last_result = ""
                challenge_info = state.get("current_challenge", {})
                flag_found = result.get("flag")
                
                if messages:
                    last_msg = messages[-1]
                    if hasattr(last_msg, "content") and last_msg.content:
                        last_result = str(last_msg.content)
                
                # 检测FLAG发现
                if flag_found:
                    try:
                        memory_store.store(
                            content=f"FLAG发现: {flag_found}\n挑战: {challenge_info.get('name', 'unknown')}",
                            category="exploit",
                            metadata={
                                "type": "flag_found",
                                "challenge": challenge_info.get("name", ""),
                                "confidence": "100%"
                            }
                        )
                        default_logger.info("[记忆存储] FLAG发现已存储")
                    except Exception as e:
                        default_logger.debug(f"存储FLAG发现失败: {e}")
                
                # 检测可能的漏洞（简单启发式）
                vulnerability_keywords = [
                    "sql injection", "xss", "rce", "lfi", "rfi",
                    "命令执行", "代码执行", "文件包含", "sql注入"
                ]
                result_lower = last_result.lower()
                for keyword in vulnerability_keywords:
                    if keyword in result_lower and not is_failure:
                        try:
                            # 提取关键信息
                            memory_store.store(
                                content=f"可能的漏洞发现: {keyword}\n结果: {last_result[:500]}",
                                category="finding",
                                metadata={
                                    "type": "potential_vulnerability",
                                    "keyword": keyword,
                                    "confidence": "待验证"
                                }
                            )
                            default_logger.info(f"[记忆存储] 可能的漏洞发现已存储: {keyword}")
                            break
                        except Exception as e:
                            default_logger.debug(f"存储漏洞发现失败: {e}")
        except Exception as e:
            default_logger.debug(f"记忆存储失败: {e}")
        
        # 元认知信心更新（参考Cyber-AutoAgent实现）
        try:
            from src.utils.metacognition import get_metacognitive_assessor
            from src.utils.llm_client import LLMClient
            
            # 获取之前的信心值
            previous_confidence = state.get("confidence_score")
            
            # 获取最后一次操作结果
            last_result = ""
            if messages:
                last_msg = messages[-1]
                if hasattr(last_msg, "content") and last_msg.content:
                    last_result = str(last_msg.content)[:500]
            
            # 进行信心评估和更新
            llm_client = LLMClient() if os.getenv("USE_LLM_METACOGNITION", "false").lower() == "true" else None
            assessor = get_metacognitive_assessor(llm_client)
            
            # 如果有之前的信心值，使用更新公式
            if previous_confidence is not None:
                confidence_assessment = assessor.assess_confidence(
                    state,
                    last_result,
                    previous_confidence
                )
            else:
                confidence_assessment = assessor.assess_confidence(state, last_result)
            
            # 更新状态
            result["confidence_score"] = confidence_assessment.get("confidence_score", 50.0)
            result["confidence_level"] = confidence_assessment.get("confidence_level", "medium")
            
            # 记录更新公式（如果有）
            if "update_formula" in confidence_assessment:
                result["confidence_update_formula"] = confidence_assessment["update_formula"]
            
            default_logger.info(
                f"[元认知] 信心评估: {result['confidence_score']:.1f}% ({result['confidence_level']})"
            )
            
            # 自我反思（如果失败）
            if is_failure:
                last_action = ""
                if messages:
                    last_msg = messages[-1]
                    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
                        last_action = last_msg.tool_calls[0].get("name", "unknown")
                
                reflection = assessor.self_reflect(state, last_action, last_result)
                result["last_reflection"] = reflection.get("reflection", "")
                
                if reflection.get("lessons_learned"):
                    default_logger.info(
                        f"[元认知] 自我反思: {reflection['reflection']}"
                    )
        except Exception as e:
            default_logger.debug(f"元认知评估失败: {e}")
        
        # 注意：知识库按需加载，不在这里自动检索
        # Agent可以通过 search_knowledge 工具主动检索相关知识
        # 这样可以避免自动加载占用上下文
        
        return result
    
    # 创建状态图
    workflow = StateGraph(PenetrationState)
    
    # 添加节点
    workflow.add_node("advisor", advisor_node)
    workflow.add_node("attacker", attacker_node)
    workflow.add_node("tools", custom_tool_node)
    workflow.add_node("reflector", reflector_node)  # 新增 Reflector 节点
    
    # 设置入口点
    workflow.set_entry_point("advisor")
    
    # 定义边
    # 顾问 → 主攻手
    workflow.add_edge("advisor", "attacker")
    
    # 主攻手 → 条件路由
    workflow.add_conditional_edges(
        "attacker",
        should_continue,
        {
            "tools": "tools",
            "attacker": "attacker",
            "advisor": "advisor",
            "end": END
        }
    )
    
    # 工具 → Reflector（新增：工具执行后先审核）
    workflow.add_edge("tools", "reflector")
    
    # Reflector → 条件路由（新增：根据审核结果决定下一步）
    workflow.add_conditional_edges(
        "reflector",
        should_continue_after_reflection,
        {
            "advisor": "advisor",      # 继续尝试
            "submit_flag": "tools",    # 提交 FLAG
            "end": END                 # 终止任务
        }
    )
    
    # 编译图
    app = workflow.compile()
    
    default_logger.info("--- 双Agent协作图构建完成 ---")
    return app

