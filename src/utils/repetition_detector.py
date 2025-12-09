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
        
        检测三种重复：
        1. 完全相同的请求（参数+响应长度）
        2. 相似的 payload（只改了值，但结构相同）
        3. 相同的错误类型
        
        Returns:
            检测到的重复模式，如果没有则返回 None
        """
        if len(self.request_records) < self.threshold:
            return None
        
        recent = list(self.request_records)[-self.threshold:]
        
        # 提取最近的请求参数和响应长度
        params = [r.request_params for r in recent]
        lengths = [r.response_length for r in recent]
        
        # 1. 核心判断：请求参数完全相同 且 响应长度完全相同
        if len(set(params)) == 1 and len(set(lengths)) == 1 and params[0]:
            return RepetitionPattern(
                pattern_type="identical_request",
                value=f"params='{params[0][:80]}{'...' if len(params[0]) > 80 else ''}', length={lengths[0]}",
                count=self.threshold,
                suggestion=self._get_repetition_suggestion(params[0], lengths[0])
            )
        
        # 2. 检测 payload 结构相似（只改了值，但参数名相同）
        if self._are_payloads_similar(params):
            return RepetitionPattern(
                pattern_type="similar_payload",
                value=f"相似的 payload 结构，只改了参数值",
                count=self.threshold,
                suggestion=self._get_similar_payload_suggestion(params, lengths)
            )
        
        # 3. 检测响应长度完全相同（可能payload无效）
        if len(set(lengths)) == 1 and lengths[0] > 0:
            # 检查最近3次的响应长度是否完全相同
            if all(l == lengths[0] for l in lengths):
                return RepetitionPattern(
                    pattern_type="identical_response_length",
                    value=f"响应长度始终为 {lengths[0]} bytes",
                    count=self.threshold,
                    suggestion=self._get_identical_length_suggestion(lengths[0])
                )
        
        # 4. 检测错误类型重复
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
    
    def _are_payloads_similar(self, params: List[str]) -> bool:
        """
        检测 payload 是否结构相似（只改了值，但参数名相同）
        
        例如：
        - username=admin&password=admin
        - username=test&password=test
        - username=demo&password=demo
        这三个payload结构相似，只是值不同
        """
        if not all(params):
            return False
        
        # 提取参数名（忽略值）
        param_structures = []
        for param in params:
            if '=' in param:
                # key=value 格式
                keys = [p.split('=')[0].strip() for p in param.split('&') if '=' in p]
                param_structures.append(tuple(sorted(keys)))
            elif '{' in param and ':' in param:
                # JSON 格式，提取 key
                import json
                try:
                    obj = json.loads(param)
                    keys = list(obj.keys())
                    param_structures.append(tuple(sorted(keys)))
                except:
                    param_structures.append(param)
            else:
                param_structures.append(param)
        
        # 如果所有 payload 的参数名结构相同，但参数值不同
        if len(set(param_structures)) == 1 and len(set(params)) > 1:
            return True
        
        return False
    
    def _get_similar_payload_suggestion(self, params: List[str], lengths: List[int]) -> str:
        """生成相似 payload 的建议"""
        suggestions = [
            f"⚠️ 检测到相似的 payload 结构连续 {self.threshold} 次",
            f"响应长度: {', '.join(map(str, lengths))}",
            "",
            "你在尝试相同的攻击方法，只是改了参数值，但结果没有变化！",
            "",
            "必须切换策略：",
            "1. **改变攻击方法** - 不要再测试相同类型的 payload",
            "2. **改变参数名** - 尝试不同的参数",
            "3. **改变请求方式** - 从 POST 换到 GET，或反之",
            "4. **改变注入点** - 尝试其他参数或 URL 路径",
            "5. **使用 Python 脚本** - 编写自动化脚本批量测试",
            "",
            "❌ 错误做法：继续测试 username=xxx&password=yyy",
            "✅ 正确做法：测试其他端点、其他参数、或使用不同的攻击技术",
        ]
        return "\n".join(suggestions)
    
    def _get_identical_length_suggestion(self, length: int) -> str:
        """生成响应长度相同的建议"""
        suggestions = [
            f"⚠️ 最近 {self.threshold} 次请求的响应长度完全相同 ({length} bytes)",
            "",
            "这说明你的 payload 可能完全无效，服务器返回的是相同的错误页面或默认响应！",
            "",
            "必须立即切换策略：",
            "1. **检查 payload 是否正确** - 参数名、格式、编码",
            "2. **尝试完全不同的攻击面** - 换一个端点或参数",
            "3. **查看响应内容** - 用 curl -v 查看详细响应",
            "4. **检查是否有 WAF** - 可能被拦截了",
            "",
            "如果响应长度始终相同，说明当前方向完全错误！",
        ]
        return "\n".join(suggestions)
    
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
            r'Content-Length[:\s]+(\d+)',          # HTTP header
            r'len[:\s]+(\d+)',                      # len: 1234
            r'length[:\s]+(\d+)',                   # length: 1234
            r'size[:\s]+(\d+)',                     # size: 1234
            r'(\d+)\s*bytes?',                      # 1234 bytes
            r'100\s+(\d+)\s+0\s+0\s+100',          # curl 进度: 100  1234  0  0  100
            r'100\s+(\d+)\s+100\s+(\d+)',          # curl 进度: 100  1234  100  1234
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                # 对于 curl 进度格式，取第一个数字（Total）
                return int(match.group(1))
        
        # 如果都没匹配到，尝试从 JSON 响应中计算长度
        # 查找 JSON 对象
        json_match = re.search(r'\{[^{}]*\}', output)
        if json_match:
            return len(json_match.group(0))
        
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
