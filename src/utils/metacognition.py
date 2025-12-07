"""
元认知（Meta-Cognition）模块
实现Agent的自我反思和信心评估
"""
from typing import Dict, Any, Optional, Literal, Tuple
from src.core.state import PenetrationState
from src.utils.logger import default_logger
from src.utils.llm_client import LLMClient
import os


class MetacognitiveAssessor:
    """
    元认知评估器
    
    功能：
    1. 评估Agent对当前策略的信心水平
    2. 分析决策质量
    3. 提供自我反思
    4. 指导策略调整
    """
    
    def __init__(self, llm_client: Optional[LLMClient] = None):
        """
        初始化元认知评估器
        
        Args:
            llm_client: LLM客户端（用于信心评估）
        """
        self.llm_client = llm_client
        self.enable_metacognition = os.getenv("ENABLE_METACOGNITION", "true").lower() == "true"
    
    def assess_confidence(
        self,
        state: PenetrationState,
        last_action_result: Optional[str] = None,
        previous_confidence: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        评估Agent的信心水平（参考Cyber-AutoAgent实现）
        
        信心更新规则（参考Cyber-AutoAgent）：
        - 成功: +20%
        - 失败: -30%
        - 模糊/部分: -10%
        
        Args:
            state: 当前状态
            last_action_result: 最后一次操作的结果
            previous_confidence: 之前的信心值（用于更新计算）
        
        Returns:
            信心评估结果
            {
                "confidence_score": 0-100,  # 数值信心（0-100%）
                "confidence_level": "high" | "medium" | "low",  # 等级（用于显示）
                "reasoning": "评估理由",
                "recommendation": "建议",
                "update_formula": "更新公式（如果有）"
            }
        """
        if not self.enable_metacognition:
            return self._simple_confidence_assessment(state, previous_confidence)
        
        # 如果有之前的信心值，使用更新公式
        if previous_confidence is not None and last_action_result:
            updated_confidence, update_formula = self._update_confidence(
                previous_confidence,
                last_action_result
            )
            result = self._format_confidence_result(updated_confidence, state)
            result["update_formula"] = update_formula
            return result
        
        # 否则进行初始评估
        if self.llm_client:
            return self._llm_confidence_assessment(state, last_action_result)
        else:
            return self._simple_confidence_assessment(state, previous_confidence)
    
    def _update_confidence(
        self,
        previous_confidence: float,
        action_result: str
    ) -> Tuple[float, str]:
        """
        根据操作结果更新信心（参考Cyber-AutoAgent公式）
        
        更新规则（参考Cyber-AutoAgent）：
        - 成功: +20%
        - 失败: -30%
        - 模糊/部分: -10%
        
        Args:
            previous_confidence: 之前的信心值（0-100）
            action_result: 操作结果文本
        
        Returns:
            (更新后的信心值, 更新公式字符串)
        """
        result_lower = action_result.lower()
        
        # 检测成功
        success_indicators = [
            "success", "成功", "found", "发现", "flag{", "flag{",
            "200 ok", "access granted", "登录成功", "提取成功",
            "✅", "答案正确", "提交成功"
        ]
        is_success = any(indicator in result_lower for indicator in success_indicators)
        
        # 检测失败
        failure_indicators = [
            "error", "failed", "失败", "错误", "denied", "forbidden",
            "404", "403", "401", "500", "timeout", "拒绝", "禁止",
            "❌", "incorrect", "wrong"
        ]
        is_failure = any(indicator in result_lower for indicator in failure_indicators)
        
        # 应用更新公式（参考Cyber-AutoAgent）
        if is_success:
            delta = +20
            formula = f"{previous_confidence:.1f}% + 20% = {previous_confidence + delta:.1f}%"
        elif is_failure:
            delta = -30
            formula = f"{previous_confidence:.1f}% - 30% = {previous_confidence + delta:.1f}%"
        else:
            # 模糊/部分成功
            delta = -10
            formula = f"{previous_confidence:.1f}% - 10% (ambiguous) = {previous_confidence + delta:.1f}%"
        
        updated = previous_confidence + delta
        
        # 限制在0-100范围
        updated = max(0.0, min(100.0, updated))
        
        default_logger.info(f"[信心更新] {formula}")
        
        return updated, formula
    
    def _format_confidence_result(
        self,
        confidence_score: float,
        state: PenetrationState
    ) -> Dict[str, Any]:
        """
        格式化信心评估结果
        
        Args:
            confidence_score: 信心分数（0-100）
            state: 当前状态
        
        Returns:
            格式化的评估结果
        """
        # 确定等级
        if confidence_score >= 80:
            level = "high"
            recommendation = "高信心：直接使用专业工具执行"
        elif confidence_score >= 50:
            level = "medium"
            recommendation = "中等信心：假设测试，可以并行探索"
        else:
            level = "low"
            recommendation = "低信心：信息收集，切换策略或咨询顾问"
        
        # 构建理由
        consecutive_failures = state.get("consecutive_failures", 0)
        attempt_count = state.get("attempt_count", 0)
        
        reasoning_parts = []
        if consecutive_failures > 0:
            reasoning_parts.append(f"连续失败{consecutive_failures}次")
        if attempt_count > 0:
            reasoning_parts.append(f"已尝试{attempt_count}次")
        
        reasoning = ", ".join(reasoning_parts) if reasoning_parts else "初始评估"
        
        result = {
            "confidence_score": confidence_score,
            "confidence_level": level,
            "reasoning": reasoning,
            "recommendation": recommendation
        }
        
        # 如果有更新公式，添加进去
        if previous_confidence is not None:
            # 这个会在_update_confidence中计算
            pass
        
        return result
    
    def _simple_confidence_assessment(
        self,
        state: PenetrationState,
        previous_confidence: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        简单信心评估（基于规则，参考Cyber-AutoAgent）
        
        评估因素：
        1. 连续失败次数
        2. 成功操作比例
        3. 操作多样性
        4. 是否有进展
        
        如果提供了previous_confidence，则基于它计算初始值
        """
        consecutive_failures = state.get("consecutive_failures", 0)
        attempt_count = state.get("attempt_count", 0)
        action_history = state.get("action_history", [])
        
        # 如果有之前的信心值，从它开始
        if previous_confidence is not None:
            base_confidence = previous_confidence
        else:
            # 初始信心：基于成功比例
            if len(action_history) > 0:
                success_count = sum(1 for a in action_history if "✅" in a)
                success_rate = success_count / len(action_history)
                base_confidence = success_rate * 100  # 转换为0-100
            else:
                base_confidence = 50.0  # 初始50%
        
        # 调整因子
        adjustments = 0.0
        
        # 失败次数影响
        if consecutive_failures == 0:
            adjustments += 10  # 无失败，信心提升
        elif consecutive_failures >= 6:
            adjustments -= 30  # 连续失败6次以上，大幅降低
        elif consecutive_failures >= 3:
            adjustments -= 20  # 连续失败3次，降低
        
        # 操作多样性影响
        if len(action_history) >= 3:
            recent_tools = [a.split('[')[1].split(']')[0] if '[' in a else "" 
                          for a in action_history[-5:]]
            tool_diversity = len(set(recent_tools)) / max(len(recent_tools), 1)
            if tool_diversity < 0.5:  # 工具单一
                adjustments -= 15
        
        # 计算最终信心
        confidence_score = base_confidence + adjustments
        confidence_score = max(0.0, min(100.0, confidence_score))
        
        return self._format_confidence_result(confidence_score, state)
    
    def _llm_confidence_assessment(
        self,
        state: PenetrationState,
        last_action_result: Optional[str]
    ) -> Dict[str, Any]:
        """
        使用LLM进行深度信心评估
        """
        try:
            # 构建评估提示
            action_history = state.get("action_history", [])
            recent_actions = action_history[-10:] if len(action_history) >= 10 else action_history
            
            assessment_prompt = f"""请评估当前渗透测试Agent的信心水平。

当前状态：
- 连续失败次数: {state.get('consecutive_failures', 0)}
- 总尝试次数: {state.get('attempt_count', 0)}
- 最近操作: {chr(10).join(recent_actions[-5:]) if recent_actions else '无'}

最后一次操作结果：
{last_action_result[:500] if last_action_result else '无'}

请评估：
1. 信心水平（high/medium/low）
2. 信心分数（0.0-1.0）
3. 评估理由
4. 建议（继续当前策略/咨询顾问/切换策略）

请以JSON格式返回：
{{
    "confidence_level": "high|medium|low",
    "confidence_score": 0.0-1.0,
    "reasoning": "评估理由",
    "recommendation": "建议"
}}"""
            
            response = self.llm_client.invoke([
                {"role": "system", "content": "你是一个专业的元认知评估专家，擅长评估AI Agent的信心水平。"},
                {"role": "user", "content": assessment_prompt}
            ])
            
            # 解析JSON响应（简化处理）
            import json
            import re
            
            # 尝试提取JSON
            json_match = re.search(r'\{[^}]+\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                return result
            else:
                # 如果解析失败，回退到简单评估
                default_logger.warning("LLM信心评估解析失败，使用简单评估")
                return self._simple_confidence_assessment(state)
        
        except Exception as e:
            default_logger.warning(f"LLM信心评估失败: {e}，使用简单评估")
            return self._simple_confidence_assessment(state)
    
    def self_reflect(
        self,
        state: PenetrationState,
        last_action: str,
        last_result: str
    ) -> Dict[str, Any]:
        """
        自我反思
        
        Args:
            state: 当前状态
            last_action: 最后一次操作
            last_result: 最后一次操作结果
        
        Returns:
            反思结果
            {
                "reflection": "反思内容",
                "lessons_learned": ["学到的经验"],
                "next_steps": "下一步建议"
            }
        """
        if not self.enable_metacognition:
            return {
                "reflection": "元认知功能未启用",
                "lessons_learned": [],
                "next_steps": "继续尝试"
            }
        
        # 简单反思（基于规则）
        consecutive_failures = state.get("consecutive_failures", 0)
        action_history = state.get("action_history", [])
        
        reflection_parts = []
        lessons = []
        
        # 分析失败模式
        if consecutive_failures >= 3:
            reflection_parts.append(f"已连续失败{consecutive_failures}次，当前策略可能不适合。")
            lessons.append("需要尝试不同的攻击方法")
        
        # 分析操作模式
        if len(action_history) >= 3:
            recent_tools = [a.split('[')[1].split(']')[0] if '[' in a else "" 
                          for a in action_history[-3:]]
            if len(set(recent_tools)) == 1:
                reflection_parts.append(f"最近3次都使用了{recent_tools[0]}，可能需要尝试其他工具。")
                lessons.append("工具选择需要多样化")
        
        # 分析结果
        if "404" in last_result or "not found" in last_result.lower():
            reflection_parts.append("遇到404错误，可能是路径或参数错误。")
            lessons.append("需要重新检查目标路径和参数")
        elif "403" in last_result or "forbidden" in last_result.lower():
            reflection_parts.append("遇到403错误，可能需要认证或权限。")
            lessons.append("需要检查认证机制")
        
        if not reflection_parts:
            reflection_parts.append("当前进展正常，继续执行。")
        
        # 下一步建议
        if consecutive_failures >= 3:
            next_steps = "建议咨询顾问或切换攻击策略"
        elif consecutive_failures >= 1:
            next_steps = "可以继续尝试，但需要调整方法"
        else:
            next_steps = "继续当前策略"
        
        return {
            "reflection": " ".join(reflection_parts),
            "lessons_learned": lessons,
            "next_steps": next_steps
        }
    
    def should_consult_advisor(
        self,
        state: PenetrationState,
        confidence_assessment: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        根据信心评估决定是否应该咨询顾问（参考Cyber-AutoAgent）
        
        决策规则（参考Cyber-AutoAgent）：
        - >80%: 直接执行，不咨询
        - 50-80%: 继续执行，不咨询
        - <50%: 咨询顾问或切换策略
        
        Args:
            state: 当前状态
            confidence_assessment: 信心评估结果（如果为None则自动评估）
        
        Returns:
            是否应该咨询顾问
        """
        if confidence_assessment is None:
            confidence_assessment = self.assess_confidence(state)
        
        confidence_score = confidence_assessment.get("confidence_score", 50.0)
        
        # 参考Cyber-AutoAgent: <50%时咨询顾问
        if confidence_score < 50:
            return True
        
        # 即使信心>=50%，如果连续失败3次以上，也建议咨询
        if state.get("consecutive_failures", 0) >= 3 and confidence_score < 70:
            return True
        
        return False
    
    def get_tool_selection_strategy(
        self,
        confidence_score: float
    ) -> str:
        """
        根据信心水平获取工具选择策略（参考Cyber-AutoAgent）
        
        Args:
            confidence_score: 信心分数（0-100）
        
        Returns:
            策略描述
        """
        if confidence_score >= 80:
            return "直接使用专业工具（nmap, sqlmap等）"
        elif confidence_score >= 50:
            return "假设测试，可以并行探索"
        else:
            return "信息收集，切换策略或咨询顾问"


# 全局元认知评估器实例
_metacognitive_assessor: Optional[MetacognitiveAssessor] = None


def get_metacognitive_assessor(llm_client: Optional[LLMClient] = None) -> MetacognitiveAssessor:
    """获取全局元认知评估器实例"""
    global _metacognitive_assessor
    if _metacognitive_assessor is None:
        _metacognitive_assessor = MetacognitiveAssessor(llm_client=llm_client)
    return _metacognitive_assessor

