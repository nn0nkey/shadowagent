"""
端口扫描输出解析器

支持: nmap, masscan, rustscan 等端口扫描工具
"""
import re
from typing import List
from .base import BaseOutputParser, ParsedOutput


class PortscanParser(BaseOutputParser):
    """端口扫描输出解析器（通用）"""
    
    tool_name = "portscan"
    tool_patterns = [
        "nmap", "masscan", "rustscan",
        "Nmap scan report", "PORT", "STATE", "SERVICE",
        "/tcp", "/udp", "open", "closed", "filtered"
    ]
    
    def parse(self, output: str) -> ParsedOutput:
        result = ParsedOutput(tool_name=self.tool_name)
        
        # 提取FLAG
        result.flags = self._extract_flags(output)
        
        # 提取开放端口
        # 格式: 22/tcp open ssh OpenSSH 8.9
        port_pattern = r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.+))?'
        matches = re.findall(port_pattern, output)
        
        for match in matches:
            port = match[0]
            protocol = match[1]
            state = match[2]
            service = match[3]
            version = match[4] if len(match) > 4 else ""
            
            if state == 'open':
                finding = f"{port}/{protocol} open {service}"
                if version:
                    finding += f" ({version.strip()})"
                    # 提取技术栈
                    result.tech_stack.append(f"{service}: {version.strip()}")
                result.findings.append(finding)
        
        # 提取目标主机
        host_pattern = r'Nmap scan report for\s+(\S+)'
        host_match = re.search(host_pattern, output)
        if host_match:
            result.raw_summary = f"目标主机: {host_match.group(1)}"
        
        # 提取操作系统信息
        os_pattern = r'OS details?:\s*(.+)'
        os_match = re.search(os_pattern, output)
        if os_match:
            result.tech_stack.append(f"OS: {os_match.group(1)}")
        
        # 检查是否有错误
        if 'error' in output.lower() or 'failed' in output.lower():
            result.success = False
        
        return result
