"""
关键发现管理器

管理渗透测试过程中的关键发现，确保这些信息永不丢失：
1. 登录页面和表单
2. 注入点
3. 凭证信息
4. FLAG
5. 技术栈信息

注意：本模块不再硬编码正则表达式，所有提取规则统一使用 HAE (extraction_rules.yaml)
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import re


@dataclass
class KeyDiscovery:
    """关键发现"""
    category: str  # login_page, injection_point, credential, flag, tech_stack, path
    content: str  # 发现的内容
    source: str  # 来源（工具名或URL）
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    confidence: int = 80  # 置信度 0-100
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "content": self.content,
            "source": self.source,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyDiscovery":
        return cls(
            category=data.get("category", "unknown"),
            content=data.get("content", ""),
            source=data.get("source", ""),
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            confidence=data.get("confidence", 80),
            metadata=data.get("metadata", {})
        )


class KeyDiscoveryManager:
    """关键发现管理器"""
    
    def __init__(self):
        self.discoveries: List[KeyDiscovery] = []
        self._seen_contents: set = set()  # 去重
    
    def add_discovery(
        self,
        category: str,
        content: str,
        source: str,
        confidence: int = 80,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        添加关键发现
        
        Returns:
            是否成功添加（重复内容会被跳过）
        """
        # 去重
        content_key = f"{category}:{content}"
        if content_key in self._seen_contents:
            return False
        
        self._seen_contents.add(content_key)
        self.discoveries.append(KeyDiscovery(
            category=category,
            content=content,
            source=source,
            confidence=confidence,
            metadata=metadata or {}
        ))
        return True
    
    def extract_from_output(self, output: str, source: str = "tool_output") -> List[KeyDiscovery]:
        """
        从工具输出中自动提取关键发现
        
        注意：大部分提取规则已迁移到 HAE (extraction_rules.yaml)
        本方法只保留少量特殊逻辑（如跳过专用解析器、FLAG 提取等）
        
        Args:
            output: 工具输出
            source: 来源标识
            
        Returns:
            新发现的列表
        """
        # 跳过已有专用解析器的工具（避免重复提取和错误提取）
        skip_tools = ['dirb', 'gobuster', 'ffuf', 'dirsearch', 'nikto', 'nmap', 'sqlmap', 'hydra', 'wpscan']
        if any(tool in output.lower() for tool in skip_tools):
            return []
        
        new_discoveries = []
        
        # 1. 提取 FLAG（高优先级，保留在这里）
        flag_pattern = r'flag\{[^}]+\}'
        flags = re.findall(flag_pattern, output, re.IGNORECASE)
        for flag in flags:
            if self.add_discovery("flag", flag, source, confidence=100):
                new_discoveries.append(self.discoveries[-1])
        
        # 2. 提取 API 端点（从 openapi.json）
        # 这个逻辑比较特殊，保留在这里
        api_patterns = [
            r'"(/[a-zA-Z_][a-zA-Z0-9_/\-]*)":\s*\{',  # openapi.json 中的路径
        ]
        for pattern in api_patterns:
            matches = re.findall(pattern, output)
            for match in matches:
                path = match if match.startswith('/') else f'/{match}'
                if len(path) > 1 and path not in ['/', '//', '/openapi.json']:
                    if self.add_discovery("api_endpoint", path, source, confidence=95, 
                                         metadata={"type": "endpoint"}):
                        new_discoveries.append(self.discoveries[-1])
        
        # 其他提取规则（凭证、表单、SQL注入、权限等）已迁移到 HAE
        # 由 graph.py 中的 global_parser 统一处理
        
        return new_discoveries
    
    def get_by_category(self, category: str) -> List[KeyDiscovery]:
        """获取指定类别的发现"""
        return [d for d in self.discoveries if d.category == category]
    
    def to_prompt_context(self) -> str:
        """
        生成用于提示词的上下文
        
        这个上下文应该被添加到每次LLM调用中，确保关键信息不丢失
        """
        if not self.discoveries:
            return ""
        
        sections = {
            "flag": "🚩 FLAG",
            "api_endpoint": "🌐 API端点（必须测试！）",
            "api_params": "📋 参数名（响应字段=请求参数！）",
            "permission_hint": "🔒 权限限制（攻击目标！）",
            "login_page": "🔐 登录页面",
            "form_fields": "📝 表单字段",
            "injection_point": "💉 注入点",
            "credential": "🔑 凭证信息",
            "tech_stack": "🛠 技术栈",
            "path": "📁 敏感路径",
        }
        
        output_parts = ["## 🔍 关键发现（永不丢弃）\n"]
        
        for category, title in sections.items():
            items = self.get_by_category(category)
            if items:
                output_parts.append(f"\n### {title}")
                for item in items:
                    output_parts.append(f"- {item.content} (来源: {item.source}, 置信度: {item.confidence}%)")
        
        return "\n".join(output_parts)
    
    def to_list(self) -> List[Dict[str, Any]]:
        """转换为可序列化的列表"""
        return [d.to_dict() for d in self.discoveries]
    
    def load_from_list(self, data: List[Dict[str, Any]]):
        """从列表加载"""
        for item in data:
            discovery = KeyDiscovery.from_dict(item)
            content_key = f"{discovery.category}:{discovery.content}"
            if content_key not in self._seen_contents:
                self._seen_contents.add(content_key)
                self.discoveries.append(discovery)


# 全局单例
_key_discovery_manager: Optional[KeyDiscoveryManager] = None


def get_key_discovery_manager() -> KeyDiscoveryManager:
    """获取关键发现管理器单例"""
    global _key_discovery_manager
    if _key_discovery_manager is None:
        _key_discovery_manager = KeyDiscoveryManager()
    return _key_discovery_manager


def reset_key_discovery_manager():
    """重置关键发现管理器"""
    global _key_discovery_manager
    _key_discovery_manager = KeyDiscoveryManager()
