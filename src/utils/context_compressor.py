"""
上下文压缩机制
智能压缩长对话历史，保留渗透测试关键信息

关键信息优先级：
1. 凭证与权限 (Credentials) - 永不丢弃
2. 攻击线索 (Attack Vectors) - 高优先级
3. 资产状态 (Target State) - 中优先级
4. 执行历史 (Execution History) - 只保留摘要
"""
from typing import List, Dict, Any, Optional, Tuple
from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, AIMessage, ToolMessage
from src.utils.logger import default_logger
from src.utils.llm_client import LLMClient
from src.utils.pentest_context import get_pentest_context, PentestContextManager
import os
import re


def extract_key_output(output: str, max_length: int = 5000) -> str:
    """
    智能提取工具输出中的关键信息
    
    使用专门的工具输出解析器模块，自动识别工具类型并提取关键信息
    
    Args:
        output: 原始输出
        max_length: 最大长度
    
    Returns:
        提取后的关键输出
    """
    if len(output) <= max_length:
        return output
    
    try:
        # 使用工具输出解析器模块
        from src.utils.output_parsers import extract_key_info
        return extract_key_info(output, max_length)
    except Exception as e:
        # 降级：简单的头尾保留
        default_logger.debug(f"工具输出解析失败，使用降级策略: {e}")
        head_size = max_length // 3
        tail_size = max_length - head_size - 50
        return f"{output[:head_size]}\n\n... [中间部分已省略] ...\n\n{output[-tail_size:]}"


class ContextCompressor:
    """
    上下文压缩器
    
    功能：
    1. 检测上下文长度
    2. 使用LLM总结旧消息
    3. 保留关键信息（FLAG、错误、工具调用）
    4. 智能合并相似消息
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None):
        """
        初始化压缩器
        
        Args:
            llm_client: LLM客户端（用于总结）
        """
        self.llm_client = llm_client
        self.summary_threshold = int(os.getenv("CONTEXT_SUMMARY_THRESHOLD", "10000"))  # 字符数阈值
        self.max_messages = int(os.getenv("MAX_HISTORY_MESSAGES", "20"))
        self.enable_compression = os.getenv("ENABLE_CONTEXT_COMPRESSION", "true").lower() == "true"
    
    def should_compress(self, messages: List[BaseMessage]) -> bool:
        """
        判断是否需要压缩
        
        Args:
            messages: 消息列表
        
        Returns:
            是否需要压缩
        """
        if not self.enable_compression:
            return False
        
        # 检查消息数量
        if len(messages) > self.max_messages:
            return True
        
        # 检查总字符数
        total_chars = sum(len(str(msg.content)) for msg in messages if hasattr(msg, 'content') and msg.content)
        if total_chars > self.summary_threshold:
            return True
        
        return False
    
    def compress_messages(
        self,
        messages: List[BaseMessage],
        keep_recent: int = 5,
        state: dict = None
    ) -> List[BaseMessage]:
        """
        压缩消息历史（渗透测试专用）
        
        策略：
        1. 从所有消息中提取渗透测试关键信息到结构化上下文
        2. 保留系统消息
        3. 保留最近的N条消息
        4. 用结构化上下文替代旧消息的总结
        
        关键信息优先级：
        - 凭证与权限: 永不丢弃
        - 攻击线索: 高优先级
        - 资产状态: 中优先级
        - 执行历史: 只保留摘要
        
        Args:
            messages: 原始消息列表
            keep_recent: 保留最近的消息数量
            state: 状态字典（包含 parsed_info 等）
        
        Returns:
            压缩后的消息列表
        """
        if not self.should_compress(messages):
            return messages
        
        default_logger.info(f"开始压缩上下文: {len(messages)} 条消息")
        
        # 获取渗透测试上下文管理器
        ctx_manager = get_pentest_context()
        
        # 从所有消息中提取关键信息
        self._extract_pentest_info(messages, ctx_manager)
        
        # 分离系统消息和普通消息
        system_messages = [msg for msg in messages if isinstance(msg, SystemMessage)]
        other_messages = [msg for msg in messages if not isinstance(msg, SystemMessage)]
        
        if len(other_messages) <= keep_recent:
            return messages
        
        # 找到安全的切分点（确保 tool_call 和 tool_response 成对）
        safe_cut_index = self._find_safe_cut_index(other_messages, keep_recent)
        
        recent_messages = other_messages[safe_cut_index:]
        
        # 构建压缩后的消息列表
        compressed = system_messages.copy()
        
        # 添加结构化的渗透测试上下文（替代传统总结）
        pentest_context = ctx_manager.to_prompt_context()
        
        # 添加关键发现（永不丢弃）
        key_discovery_context = ""
        try:
            from src.utils.key_discovery import get_key_discovery_manager
            discovery_manager = get_key_discovery_manager()
            key_discovery_context = discovery_manager.to_prompt_context()
        except Exception:
            pass
        
        # 添加重复检测警告
        repetition_context = ""
        try:
            from src.utils.repetition_detector import get_repetition_detector
            detector = get_repetition_detector()
            repetition_context = detector.to_prompt_context()
        except Exception:
            pass
        
        # 添加解析结果（永不丢弃）⭐
        parsed_context = ""
        if state and "parsed_info" in state:
            parsed_info = state.get("parsed_info", [])
            if parsed_info:
                # 只保留最近3次的解析结果
                recent_parsed = parsed_info[-3:]
                parsed_lines = ["## 🔍 自动提取的关键信息（来自工具响应）"]
                
                for item in recent_parsed:
                    results = item.get("results", {})
                    
                    # 凭证
                    if results.get("credentials"):
                        parsed_lines.append("\n### 🔑 发现凭证")
                        for cred in results["credentials"][:3]:
                            if "username" in cred:
                                parsed_lines.append(f"- {cred['username']}:{cred['password']}")
                    
                    # 提权字段
                    if results.get("privilege_fields"):
                        parsed_lines.append("\n### ⚠️ 提权字段")
                        for field in results["privilege_fields"][:3]:
                            bypassable = " (可绕过)" if field.get("bypassable") else ""
                            parsed_lines.append(f"- {field['field']}{bypassable}")
                    
                    # IDOR 点
                    if results.get("idor_points"):
                        parsed_lines.append("\n### 🎯 IDOR 攻击点")
                        for idor in results["idor_points"][:3]:
                            parsed_lines.append(f"- {idor['id']}")
                
                if len(parsed_lines) > 1:
                    parsed_context = "\n".join(parsed_lines)
        
        # 组合上下文
        context_parts = []
        if pentest_context:
            context_parts.append(pentest_context)
        if key_discovery_context:
            context_parts.append(key_discovery_context)
        if parsed_context:  # 添加解析结果 ⭐
            context_parts.append(parsed_context)
        if repetition_context:
            context_parts.append(repetition_context)
        
        if context_parts:
            combined_context = "\n\n".join(context_parts)
            context_msg = HumanMessage(
                content=f"## 🔍 渗透测试上下文（自动提取的关键信息，永不丢弃）\n\n{combined_context}\n\n---\n\n以下是最近的对话："
            )
            compressed.append(context_msg)
        
        # 添加最近的消息
        compressed.extend(recent_messages)
        
        default_logger.info(f"压缩完成: {len(messages)} → {len(compressed)} 条消息")
        
        return compressed
    
    def _find_safe_cut_index(self, messages: List[BaseMessage], keep_recent: int) -> int:
        """
        找到安全的切分点，确保不会破坏 tool_call 和 tool_response 的配对
        
        Args:
            messages: 消息列表（不含系统消息）
            keep_recent: 期望保留的最近消息数量
        
        Returns:
            安全的切分索引
        """
        if len(messages) <= keep_recent:
            return 0
        
        # 从期望的切分点开始，向前找到安全位置
        target_cut = len(messages) - keep_recent
        
        # 收集所有 tool_call_id 和它们的位置
        tool_call_positions = {}  # tool_call_id -> (call_index, response_index)
        
        for i, msg in enumerate(messages):
            # 记录 tool_call 的位置
            if hasattr(msg, 'tool_calls') and msg.tool_calls:
                for tc in msg.tool_calls:
                    tc_id = tc.get('id')
                    if tc_id:
                        tool_call_positions[tc_id] = {'call': i, 'response': None}
            
            # 记录 tool_response 的位置
            if isinstance(msg, ToolMessage) and hasattr(msg, 'tool_call_id'):
                tc_id = msg.tool_call_id
                if tc_id in tool_call_positions:
                    tool_call_positions[tc_id]['response'] = i
        
        # 检查切分点是否会破坏配对
        safe_cut = target_cut
        for tc_id, positions in tool_call_positions.items():
            call_idx = positions['call']
            resp_idx = positions['response']
            
            if resp_idx is None:
                # 没有响应的 tool_call，确保它被移除
                if call_idx >= safe_cut:
                    safe_cut = call_idx + 1
            else:
                # 有配对的 tool_call 和 response
                # 如果切分点在它们之间，需要调整
                if call_idx < safe_cut <= resp_idx:
                    # 切分点在 call 和 response 之间，需要把 call 也包含进来
                    safe_cut = call_idx
        
        return max(0, safe_cut)
    
    def _extract_pentest_info(self, messages: List[BaseMessage], ctx_manager: PentestContextManager):
        """
        从消息中提取渗透测试关键信息
        
        提取内容：
        1. 资产状态 - 端口、技术栈、WAF
        2. 攻击线索 - 敏感路径、漏洞点
        3. 凭证信息 - 密码、Token、FLAG
        4. 执行历史 - 成功/失败记录
        """
        for msg in messages:
            # 从 ToolMessage 提取工具输出
            if isinstance(msg, ToolMessage) and hasattr(msg, 'content'):
                content = str(msg.content)
                # 尝试获取对应的命令（从前一条 AIMessage）
                ctx_manager.update_from_tool_output("execute_command", content)
            
            # 从 AIMessage 提取工具调用信息
            if isinstance(msg, AIMessage):
                tool_calls = getattr(msg, 'tool_calls', [])
                for tc in tool_calls:
                    tool_name = tc.get('name', '')
                    args = tc.get('args', {})
                    
                    # 记录执行历史
                    if tool_name == 'execute_command':
                        command = args.get('command', '')
                        description = args.get('description', '')
                        ctx_manager.add_execution_record(
                            action=self._categorize_command(command),
                            target=command[:50],
                            result="executed",
                            reason=description
                        )
    
    def _categorize_command(self, command: str) -> str:
        """将命令分类为操作类型"""
        cmd_lower = command.lower()
        
        if 'nmap' in cmd_lower:
            return 'port_scan'
        elif 'sqlmap' in cmd_lower:
            return 'sqli_test'
        elif any(x in cmd_lower for x in ['gobuster', 'dirb', 'dirsearch', 'ffuf']):
            return 'dir_scan'
        elif 'hydra' in cmd_lower or 'brute' in cmd_lower:
            return 'bruteforce'
        elif 'curl' in cmd_lower or 'wget' in cmd_lower:
            return 'http_request'
        elif 'nikto' in cmd_lower:
            return 'vuln_scan'
        else:
            return 'command'
    
    def _summarize_messages(self, messages: List[BaseMessage]) -> Optional[str]:
        """
        使用LLM总结消息
        
        Args:
            messages: 要总结的消息列表
        
        Returns:
            总结文本
        """
        if not messages:
            return None
        
        if not self.llm_client:
            # 如果没有LLM客户端，使用简单总结
            return self._simple_summarize(messages)
        
        # 构建总结提示
        messages_text = self._format_messages_for_summary(messages)
        
        summary_prompt = f"""请总结以下渗透测试对话历史，**必须保留**以下关键信息：

1. **发现的链接和路径**（如 admin.php, login.php, /api/ 等）
2. **发现的漏洞点**（如 SQL 注入参数、XSS 点等）
3. **工具执行结果**（成功的命令、错误信息）
4. **找到的 FLAG 或关键线索**
5. **技术栈信息**（PHP、MySQL、Apache 等）
6. **用户名、密码、token 等敏感信息**

对话历史：
{messages_text}

请用简洁的中文总结，格式如下：
【发现的路径】...
【漏洞点】...
【关键信息】...
【待跟进】...（列出发现但未处理的线索）"""
        
        try:
            summary = self.llm_client.invoke([
                {"role": "system", "content": "你是一个专业的对话总结助手，擅长提取关键信息。"},
                {"role": "user", "content": summary_prompt}
            ])
            return summary
        except Exception as e:
            default_logger.warning(f"LLM总结失败: {e}，使用简单总结")
            return self._simple_summarize(messages)
    
    def _format_messages_for_summary(self, messages: List[BaseMessage]) -> str:
        """格式化消息用于总结"""
        formatted = []
        for i, msg in enumerate(messages, 1):
            if isinstance(msg, SystemMessage):
                continue
            elif isinstance(msg, HumanMessage):
                formatted.append(f"[用户 {i}]: {msg.content[:500]}")
            elif isinstance(msg, AIMessage):
                content = msg.content or ""
                tool_calls = getattr(msg, 'tool_calls', [])
                if tool_calls:
                    tool_names = [tc.get('name', 'unknown') for tc in tool_calls]
                    formatted.append(f"[AI {i}]: 调用工具 {', '.join(tool_names)}")
                else:
                    formatted.append(f"[AI {i}]: {content[:500]}")
            elif isinstance(msg, ToolMessage):
                content = str(msg.content)[:500]
                formatted.append(f"[工具 {i}]: {content}")
        
        return "\n".join(formatted)
    
    def _simple_summarize(self, messages: List[BaseMessage]) -> str:
        """
        简单总结（不使用LLM）
        
        提取关键信息：
        - 发现的链接和路径
        - 工具调用
        - 错误信息
        - FLAG相关内容
        """
        import re
        
        key_info = {
            "paths": set(),      # 发现的路径
            "tools": [],         # 工具调用
            "errors": [],        # 错误
            "flags": [],         # FLAG
            "tech_stack": set(), # 技术栈
        }
        
        for msg in messages:
            # 提取工具调用
            if isinstance(msg, AIMessage):
                tool_calls = getattr(msg, 'tool_calls', [])
                if tool_calls:
                    for tc in tool_calls:
                        tool_name = tc.get('name', 'unknown')
                        key_info["tools"].append(tool_name)
            
            # 提取内容中的关键信息
            if hasattr(msg, 'content') and msg.content:
                content = str(msg.content)
                
                # 提取链接和路径
                paths = re.findall(r'href=["\']([^"\']+)["\']', content)
                paths += re.findall(r'(?:src|action)=["\']([^"\']+)["\']', content)
                paths += re.findall(r'/[\w\-\.]+\.(?:php|html|asp|jsp|py)', content)
                key_info["paths"].update(paths)
                
                # 提取技术栈
                tech_patterns = [
                    (r'PHP/[\d\.]+', 'PHP'),
                    (r'Apache/[\d\.]+', 'Apache'),
                    (r'nginx/[\d\.]+', 'Nginx'),
                    (r'MySQL', 'MySQL'),
                    (r'SQLite', 'SQLite'),
                ]
                for pattern, tech in tech_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        key_info["tech_stack"].add(tech)
                
                # 检查FLAG
                flags = re.findall(r'flag\{[^}]+\}', content, re.IGNORECASE)
                key_info["flags"].extend(flags)
                
                # 检查错误（只保留前50字符）
                if any(kw in content.lower() for kw in ['error', 'failed', 'exception']):
                    error_snippet = content[:50].replace('\n', ' ')
                    if error_snippet not in key_info["errors"]:
                        key_info["errors"].append(error_snippet)
        
        # 构建总结
        summary_parts = []
        
        if key_info["paths"]:
            summary_parts.append(f"【发现的路径】{', '.join(list(key_info['paths'])[:5])}")
        
        if key_info["tech_stack"]:
            summary_parts.append(f"【技术栈】{', '.join(key_info['tech_stack'])}")
        
        if key_info["flags"]:
            summary_parts.append(f"【FLAG】{', '.join(key_info['flags'])}")
        
        if key_info["errors"]:
            summary_parts.append(f"【错误】{key_info['errors'][0]}...")
        
        tool_counts = {}
        for t in key_info["tools"]:
            tool_counts[t] = tool_counts.get(t, 0) + 1
        if tool_counts:
            tools_str = ', '.join(f"{t}×{c}" for t, c in tool_counts.items())
            summary_parts.append(f"【工具调用】{tools_str}")
        
        if summary_parts:
            return "\n".join(summary_parts)
        else:
            return "已执行多次操作，详情见最近对话。"
    
    def extract_key_information(self, messages: List[BaseMessage]) -> Dict[str, Any]:
        """
        提取关键信息（不压缩，只提取）
        
        Returns:
            关键信息字典
        """
        key_info = {
            "flags_found": [],
            "tools_used": [],
            "errors": [],
            "successes": []
        }
        
        for msg in messages:
            if hasattr(msg, 'content') and msg.content:
                content = str(msg.content)
                
                # 提取FLAG
                if 'flag{' in content.lower():
                    import re
                    flags = re.findall(r'flag\{[^}]+\}', content, re.IGNORECASE)
                    key_info["flags_found"].extend(flags)
                
                # 提取工具调用
                if isinstance(msg, AIMessage):
                    tool_calls = getattr(msg, 'tool_calls', [])
                    for tc in tool_calls:
                        key_info["tools_used"].append(tc.get('name', 'unknown'))
                
                # 提取错误
                if any(kw in content.lower() for kw in ['error', 'failed', 'exception']):
                    key_info["errors"].append(content[:200])
                
                # 提取成功
                if any(kw in content.lower() for kw in ['success', '成功', 'found', '发现']):
                    key_info["successes"].append(content[:200])
        
        return key_info

