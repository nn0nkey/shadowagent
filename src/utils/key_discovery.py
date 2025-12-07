"""
关键发现管理器

管理渗透测试过程中的关键发现，确保这些信息永不丢失：
1. 登录页面和表单
2. 注入点
3. 凭证信息
4. FLAG
5. 技术栈信息
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
        
        Args:
            output: 工具输出
            source: 来源标识
            
        Returns:
            新发现的列表
        """
        new_discoveries = []
        
        # 1. 提取登录页面
        # 只从 HTML 表单或明确的 .php 文件中提取，避免从目录扫描的 404 路径中提取
        login_patterns = [
            r'<form[^>]*action=["\']([^"\']*(?:login|admin|auth)[^"\']*)["\']',  # HTML 表单
            r'<a[^>]*href=["\']([^"\']*(?:admin|login)\.php)["\']',  # HTML 链接
            r'(?:admin|login|auth)\.php(?:\s|$)',  # 明确的 .php 文件（不在路径中）
        ]
        for pattern in login_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                # 确保不是目录扫描中的 404 路径
                # 如果输出包含 "CODE:404" 或 "Status: 404"，跳过
                if "404" not in output or "<" in output:  # 有 HTML 标签说明是真实页面
                    if self.add_discovery("login_page", match, source, confidence=90):
                        new_discoveries.append(self.discoveries[-1])
        
        # 2. 提取表单字段
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
        inputs = re.findall(input_pattern, output, re.IGNORECASE)
        if inputs:
            form_fields = ", ".join(set(inputs))
            if self.add_discovery("form_fields", form_fields, source, confidence=95):
                new_discoveries.append(self.discoveries[-1])
        
        # 3. 提取技术栈
        tech_patterns = [
            (r'Server:\s*([^\r\n]+)', "server"),
            (r'X-Powered-By:\s*([^\r\n]+)', "powered_by"),
            (r'PHP/([\d\.]+)', "php_version"),
            (r'Apache/([\d\.]+)', "apache_version"),
            (r'nginx/([\d\.]+)', "nginx_version"),
        ]
        for pattern, tech_type in tech_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                if self.add_discovery("tech_stack", f"{tech_type}: {match.group(1)}", source, confidence=95):
                    new_discoveries.append(self.discoveries[-1])
        
        # 4. 提取FLAG
        flag_pattern = r'flag\{[^}]+\}'
        flags = re.findall(flag_pattern, output, re.IGNORECASE)
        for flag in flags:
            if self.add_discovery("flag", flag, source, confidence=100):
                new_discoveries.append(self.discoveries[-1])
        
        # 5. 提取敏感路径
        path_patterns = [
            r'(?:href|src|action)=["\']([^"\']*(?:admin|config|backup|upload|api)[^"\']*)["\']',
            r'/([\w\-]+\.(?:php|asp|jsp|bak|sql|zip|tar|gz))',
        ]
        for pattern in path_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                if len(match) > 2 and self.add_discovery("path", match, source, confidence=85):
                    new_discoveries.append(self.discoveries[-1])
        
        # 6. 提取SQL注入线索
        sqli_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'PostgreSQL.*ERROR',
            r'ORA-\d{5}',
            r'SQLite.*error',
            r'SQLSTATE\[',
        ]
        for pattern in sqli_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                if self.add_discovery("injection_point", f"SQL error detected: {pattern}", source, confidence=90):
                    new_discoveries.append(self.discoveries[-1])
                break
        
        # 7. 提取 API 端点（从 openapi.json 或响应中）
        # 匹配 "/jobs", "/ping", "/api/xxx" 等路径
        api_patterns = [
            r'"(/[a-zA-Z_][a-zA-Z0-9_/\-]*)":\s*\{',  # openapi.json 中的路径
            r'"/([a-zA-Z_][a-zA-Z0-9_/\-]*)"',  # JSON 中的路径
        ]
        for pattern in api_patterns:
            matches = re.findall(pattern, output)
            for match in matches:
                path = match if match.startswith('/') else f'/{match}'
                if len(path) > 1 and path not in ['/', '//', '/openapi.json']:
                    if self.add_discovery("api_endpoint", path, source, confidence=95, 
                                         metadata={"type": "endpoint"}):
                        new_discoveries.append(self.discoveries[-1])
        
        # 8. 提取 JSON 响应中的字段名（仅作为参考，不一定是请求参数！）
        # 注意：响应字段 ≠ 请求参数，如 id 是返回值不是请求参数
        # 只有 openapi.json 中的 requestBody 才是真正的参数
        json_field_pattern = r'"([a-zA-Z_][a-zA-Z0-9_]*)":\s*(?:"[^"]*"|[\d\.\-]+|\[|\{|true|false|null)'
        json_fields = re.findall(json_field_pattern, output)
        if json_fields:
            # 去重并过滤常见的非参数字段和返回值字段
            exclude_fields = {'openapi', 'info', 'title', 'version', 'paths', 'summary', 
                            'operationId', 'responses', 'description', 'content', 'schema',
                            'application', 'json', 'text', 'html',
                            'id', 'name', 'created_at', 'updated_at', 'status'}  # 这些通常是返回值
            unique_fields = [f for f in set(json_fields) if f.lower() not in exclude_fields]
            if unique_fields:
                fields_str = ", ".join(sorted(unique_fields)[:10])  # 最多保留10个
                if self.add_discovery("api_params", f"响应字段（仅供参考，需从openapi确认）: {fields_str}", source, 
                                     confidence=60, metadata={"fields": unique_fields}):  # 降低置信度
                    new_discoveries.append(self.discoveries[-1])
        
        # 9. 提取权限限制信息（这是攻击目标！）
        permission_patterns = [
            r'Only\s+(\w+)\s+can',  # "Only admins can see..."
            r'Permission\s+denied',
            r'Access\s+denied',
            r'Unauthorized',
            r'Forbidden',
        ]
        for pattern in permission_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                content = match.group(0)
                if self.add_discovery("permission_hint", f"权限限制: {content}", source, 
                                     confidence=95, metadata={"pattern": pattern}):
                    new_discoveries.append(self.discoveries[-1])
        
        # 7. 提取凭证信息
        cred_patterns = [
            (r'(?:username|user|login)[\s:=]+["\']?(\w+)["\']?', "username"),
            (r'(?:password|pass|pwd)[\s:=]+["\']?([^\s"\']+)["\']?', "password"),
            (r'(?:token|api[_-]?key)[\s:=]+["\']?([^\s"\']+)["\']?', "token"),
        ]
        for pattern, cred_type in cred_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                if len(match) > 2 and match.lower() not in ['admin', 'test', 'user', 'password']:
                    if self.add_discovery("credential", f"{cred_type}: {match}", source, confidence=70):
                        new_discoveries.append(self.discoveries[-1])
        
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
