"""
重复检测器

检测相同响应长度连续出现的情况，自动建议切换策略
"""
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import deque
import re


@dataclass
class RepetitionPattern:
    """重复模式"""
    pattern_type: str  # response_length, payload_type, error_type
    value: Any  # 重复的值
    count: int  # 重复次数
    suggestion: str  # 建议的策略切换


@dataclass
class RequestRecord:
    """单次请求记录"""
    request_params: str  # 请求参数（GET/POST参数的规范化字符串）
    response_length: int  # 响应长度
    url: str = ""  # 请求URL
    method: str = ""  # 请求方法
    error_type: Optional[str] = None


class RepetitionDetector:
    """重复检测器
    
    检测逻辑：
    - 比较请求参数（GET/POST传入的参数）是否相同
    - 比较响应长度是否相同
    - 两者都相同连续3次才触发告警
    """
    
    def __init__(self, threshold: int = 3):
        """
        Args:
            threshold: 触发策略切换的重复次数阈值
        """
        self.threshold = threshold
        self.request_records: deque = deque(maxlen=10)  # 最近10次请求记录
        self.strategy_switches: List[str] = []  # 策略切换历史
    
    def record_response(
        self,
        response_length: int,
        request_params: str = "",
        url: str = "",
        method: str = "",
        error_type: Optional[str] = None
    ):
        """
        记录一次响应
        
        Args:
            response_length: 响应长度
            request_params: 请求参数（GET query string 或 POST body）
            url: 请求URL
            method: 请求方法 (GET/POST)
            error_type: 错误类型（可选）
        """
        # 规范化参数（排序，去除空格）
        normalized_params = self._normalize_params(request_params)
        
        self.request_records.append(RequestRecord(
            request_params=normalized_params,
            response_length=response_length,
            url=url,
            method=method,
            error_type=error_type
        ))
    
    def _normalize_params(self, params: str) -> str:
        """
        规范化请求参数，便于比较
        
        处理：
        - URL编码的参数
        - JSON格式的参数
        - 表单格式的参数
        """
        if not params:
            return ""
        
        params = params.strip()
        
        # 尝试解析为 key=value&key2=value2 格式
        if '=' in params and not params.startswith('{'):
            try:
                # 分割并排序参数
                pairs = []
                for pair in params.split('&'):
                    if '=' in pair:
                        pairs.append(pair.strip())
                pairs.sort()
                return '&'.join(pairs)
            except:
                pass
        
        # JSON 格式或其他格式，直接返回
        return params
    
    def detect_repetition(self) -> Optional[RepetitionPattern]:
        """
        检测重复模式
        
        只有当请求参数相同 且 响应长度相同 连续出现 threshold 次时才触发告警
        
        Returns:
            检测到的重复模式，如果没有则返回 None
        """
        if len(self.request_records) < self.threshold:
            return None
        
        recent = list(self.request_records)[-self.threshold:]
        
        # 提取最近的请求参数和响应长度
        params = [r.request_params for r in recent]
        lengths = [r.response_length for r in recent]
        
        # 核心判断：请求参数完全相同 且 响应长度完全相同
        if len(set(params)) == 1 and len(set(lengths)) == 1 and params[0]:
            return RepetitionPattern(
                pattern_type="identical_request",
                value=f"params='{params[0][:80]}{'...' if len(params[0]) > 80 else ''}', length={lengths[0]}",
                count=self.threshold,
                suggestion=self._get_repetition_suggestion(params[0], lengths[0])
            )
        
        # 检测错误类型重复
        error_types = [r.error_type for r in recent if r.error_type]
        if len(error_types) >= self.threshold:
            recent_errors = error_types[-self.threshold:]
            if len(set(recent_errors)) == 1:
                return RepetitionPattern(
                    pattern_type="error_type",
                    value=recent_errors[0],
                    count=self.threshold,
                    suggestion=self._get_error_repetition_suggestion(recent_errors[0])
                )
        
        return None
    
    def _get_repetition_suggestion(self, params: str, length: int) -> str:
        """生成重复请求的建议"""
        suggestions = [
            f"⚠️ 完全相同的请求连续 {self.threshold} 次，响应长度均为 {length} bytes",
            f"请求参数: {params[:100]}{'...' if len(params) > 100 else ''}",
            "",
            "这说明当前请求完全无效，必须切换策略：",
            "1. 修改请求参数的值",
            "2. 尝试不同的参数名",
            "3. 尝试不同的请求方法 (GET/POST)",
            "4. 尝试不同的编码方式",
            "5. 检查是否遗漏了必要的参数",
        ]
        return "\n".join(suggestions)
    
    def _get_error_repetition_suggestion(self, error_type: str) -> str:
        """获取错误类型重复时的建议"""
        return f"连续 {self.threshold} 次遇到相同错误 ({error_type})，建议：\n1. 检查目标是否可达\n2. 检查参数名是否正确\n3. 尝试其他攻击面"
    
    def record_strategy_switch(self, from_strategy: str, to_strategy: str, reason: str):
        """记录策略切换"""
        self.strategy_switches.append(f"{from_strategy} → {to_strategy}: {reason}")
        # 切换后清空历史，重新开始检测
        self.request_records.clear()
    
    def get_switch_history(self) -> List[str]:
        """获取策略切换历史"""
        return self.strategy_switches.copy()
    
    def extract_request_params(self, code: str) -> str:
        """
        从代码中提取请求参数
        
        支持提取：
        - requests.post(url, data={...}) 中的 data
        - requests.get(url, params={...}) 中的 params
        - curl -d "..." 中的数据
        """
        # 1. 提取 Python requests 的 data 参数
        # 匹配 data={'key': 'value', ...} 或 data={"key": "value", ...}
        data_match = re.search(r'data\s*=\s*(\{[^}]+\})', code)
        if data_match:
            return data_match.group(1)
        
        # 2. 提取 Python requests 的 params 参数
        params_match = re.search(r'params\s*=\s*(\{[^}]+\})', code)
        if params_match:
            return params_match.group(1)
        
        # 3. 提取 curl -d 的数据
        curl_data_match = re.search(r'-d\s+["\']([^"\']+)["\']', code)
        if curl_data_match:
            return curl_data_match.group(1)
        
        # 4. 提取 curl --data 的数据
        curl_data_match2 = re.search(r'--data\s+["\']([^"\']+)["\']', code)
        if curl_data_match2:
            return curl_data_match2.group(1)
        
        return ""
    
    def extract_response_length(self, output: str) -> Optional[int]:
        """从工具输出中提取响应长度"""
        # 匹配常见的长度输出格式
        patterns = [
            r'len[:\s]+(\d+)',
            r'length[:\s]+(\d+)',
            r'size[:\s]+(\d+)',
            r'(\d+)\s*bytes?',
            r'Content-Length[:\s]+(\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return int(match.group(1))
        
        return None
    
    def to_prompt_context(self) -> str:
        """生成用于提示词的上下文"""
        parts = []
        
        # 检测重复
        repetition = self.detect_repetition()
        if repetition:
            parts.append(f"## ⚠️ 检测到重复模式\n\n{repetition.suggestion}")
        
        # 策略切换历史
        if self.strategy_switches:
            parts.append(f"\n## 📊 策略切换历史\n")
            for switch in self.strategy_switches[-5:]:  # 最近5次
                parts.append(f"- {switch}")
        
        return "\n".join(parts)


# 全局单例
_repetition_detector: Optional[RepetitionDetector] = None


def get_repetition_detector() -> RepetitionDetector:
    """获取重复检测器单例"""
    global _repetition_detector
    if _repetition_detector is None:
        _repetition_detector = RepetitionDetector()
    return _repetition_detector


def reset_repetition_detector():
    """重置重复检测器"""
    global _repetition_detector
    _repetition_detector = RepetitionDetector()
