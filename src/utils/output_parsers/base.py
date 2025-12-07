"""
工具输出解析器基类

定义解析器的统一接口，所有具体解析器都继承此类
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class ParsedOutput:
    """解析后的输出结构"""
    # 核心发现
    findings: List[str] = field(default_factory=list)      # 关键发现（路径、端口、漏洞等）
    credentials: List[str] = field(default_factory=list)   # 凭证信息
    flags: List[str] = field(default_factory=list)         # FLAG
    
    # 技术信息
    tech_stack: List[str] = field(default_factory=list)    # 技术栈
    urls: List[str] = field(default_factory=list)          # 发现的URL
    
    # 状态信息
    errors: List[str] = field(default_factory=list)        # 错误信息
    warnings: List[str] = field(default_factory=list)      # 警告信息
    
    # 元数据
    tool_name: str = ""                                     # 工具名称
    success: bool = True                                    # 是否成功执行
    raw_summary: str = ""                                   # 原始输出摘要
    
    def to_summary(self, max_length: int = 2000) -> str:
        """生成摘要文本"""
        parts = []
        
        if self.flags:
            parts.append(f"🚩 FLAG: {', '.join(self.flags)}")
        
        if self.credentials:
            parts.append(f"🔑 凭证: {', '.join(self.credentials[:5])}")
        
        if self.findings:
            parts.append("📋 关键发现:")
            for f in self.findings[:20]:
                parts.append(f"  - {f}")
        
        if self.urls:
            parts.append("🔗 发现的URL:")
            for u in self.urls[:10]:
                parts.append(f"  - {u}")
        
        if self.tech_stack:
            parts.append(f"🛠 技术栈: {', '.join(self.tech_stack)}")
        
        if self.errors:
            parts.append("❌ 错误:")
            for e in self.errors[:5]:
                parts.append(f"  - {e[:100]}")
        
        if self.raw_summary:
            parts.append(f"\n📝 原始摘要:\n{self.raw_summary}")
        
        result = "\n".join(parts)
        if len(result) > max_length:
            result = result[:max_length] + "\n... [已截断]"
        
        return result


class BaseOutputParser(ABC):
    """输出解析器基类"""
    
    # 子类需要定义的属性
    tool_name: str = "unknown"
    tool_patterns: List[str] = []  # 用于识别该工具输出的特征
    
    @classmethod
    def can_parse(cls, output: str) -> bool:
        """判断是否能解析该输出"""
        output_lower = output.lower()
        return any(pattern.lower() in output_lower for pattern in cls.tool_patterns)
    
    @abstractmethod
    def parse(self, output: str) -> ParsedOutput:
        """
        解析工具输出
        
        Args:
            output: 原始工具输出
        
        Returns:
            ParsedOutput: 解析后的结构化数据
        """
        pass
    
    def _extract_flags(self, output: str) -> List[str]:
        """提取FLAG（通用方法）"""
        import re
        patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
        ]
        flags = []
        for pattern in patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            flags.extend(matches)
        return list(set(flags))
    
    def _extract_credentials(self, output: str) -> List[str]:
        """提取凭证信息（通用方法）"""
        import re
        creds = []
        
        # 用户名:密码 格式
        patterns = [
            r'(?:username|user|login)[:\s]+([^\s]+)',
            r'(?:password|passwd|pwd)[:\s]+([^\s]+)',
            r'(?:token|api_key|apikey)[:\s]+([^\s]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            creds.extend(matches)
        
        return list(set(creds))
