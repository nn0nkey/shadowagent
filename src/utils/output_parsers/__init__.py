"""
工具输出解析器模块

按工具类别组织，每类一个通用解析器：
- dirscan: 目录扫描（ffuf, gobuster, dirb, dirsearch）
- portscan: 端口扫描（nmap, masscan, rustscan）
- sqli: SQL注入（sqlmap）
- http: HTTP响应（curl, requests）
- generic: 通用解析器（兜底）

使用方法:
    from src.utils.output_parsers import parse_output, extract_key_info
    
    # 解析输出
    result = parse_output(tool_output)
    print(result.findings)
    print(result.to_summary())
    
    # 快速提取关键信息（用于上下文压缩）
    summary = extract_key_info(tool_output, max_length=3000)
"""
from typing import List, Type, Optional
from .base import BaseOutputParser, ParsedOutput
from .dirscan_parser import DirscanParser
from .nmap_parser import PortscanParser
from .sqlmap_parser import SqliParser
from .http_parser import HttpParser
from .generic_parser import GenericParser


# 注册所有解析器（按优先级排序）
PARSERS: List[Type[BaseOutputParser]] = [
    DirscanParser,    # 目录扫描
    PortscanParser,   # 端口扫描
    SqliParser,       # SQL注入
    HttpParser,       # HTTP响应
    GenericParser,    # 兜底，必须放最后
]


def get_parser(output: str) -> BaseOutputParser:
    """
    根据输出内容选择合适的解析器
    
    Args:
        output: 工具输出
    
    Returns:
        匹配的解析器实例
    """
    for parser_cls in PARSERS:
        if parser_cls.can_parse(output):
            return parser_cls()
    
    # 不应该到这里，因为 GenericParser 总是匹配
    return GenericParser()


def parse_output(output: str) -> ParsedOutput:
    """
    解析工具输出
    
    Args:
        output: 工具输出
    
    Returns:
        ParsedOutput: 解析后的结构化数据
    """
    parser = get_parser(output)
    return parser.parse(output)


def extract_key_info(output: str, max_length: int = 3000) -> str:
    """
    提取工具输出的关键信息（用于上下文压缩）
    
    Args:
        output: 工具输出
        max_length: 最大输出长度
    
    Returns:
        关键信息摘要
    """
    if len(output) <= max_length:
        return output
    
    # 解析输出
    parsed = parse_output(output)
    
    # 生成摘要
    summary = parsed.to_summary(max_length=max_length - 500)
    
    # 如果摘要太短，补充原始输出
    if len(summary) < max_length // 2:
        remaining = max_length - len(summary) - 100
        if remaining > 200:
            head_size = remaining // 3
            tail_size = remaining - head_size
            summary += f"\n\n--- 原始输出 ---\n[头部]\n{output[:head_size]}\n...\n[尾部]\n{output[-tail_size:]}"
    
    return summary


# 导出
__all__ = [
    'BaseOutputParser',
    'ParsedOutput',
    'parse_output',
    'extract_key_info',
    'get_parser',
    'PARSERS',
    # 按类别的解析器
    'DirscanParser',    # 目录扫描
    'PortscanParser',   # 端口扫描
    'SqliParser',       # SQL注入
    'HttpParser',       # HTTP响应
    'GenericParser',    # 通用
]
