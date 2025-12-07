"""
目录扫描输出解析器

支持: ffuf, gobuster, dirb, dirsearch 等目录扫描工具
"""
import re
from typing import List
from .base import BaseOutputParser, ParsedOutput


class DirscanParser(BaseOutputParser):
    """目录扫描输出解析器（通用）"""
    
    tool_name = "dirscan"
    tool_patterns = [
        "ffuf", "gobuster", "dirb", "dirsearch",
        "[Status:", "(Status:", "DIRECTORY:", "==>",
        "/'___\\",  # ffuf ASCII art
    ]
    
    def parse(self, output: str) -> ParsedOutput:
        result = ParsedOutput(tool_name=self.tool_name)
        
        # 提取FLAG
        result.flags = self._extract_flags(output)
        
        # 多种格式的路径提取
        path_patterns = [
            # ffuf: /path [Status: 200, Size: 1234]
            r'(/?[\w\-\./]+)\s+\[Status:\s*(\d+)(?:,\s*Size:\s*(\d+))?',
            # gobuster: /path (Status: 200) [Size: 1234]
            r'(/?[\w\-\./]+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?',
            # dirb: + http://target/path (CODE:200|SIZE:1234)
            r'\+\s+https?://[^/]+(/?[\w\-\./]*)\s+\(CODE:(\d+)',
            # dirsearch: 200 - 1234B - /path
            r'(\d+)\s+-\s+\d+\w?\s+-\s+(/?[\w\-\./]+)',
            # 通用: /path.php 200
            r'(/?[\w\-\.]+\.(?:php|html|jsp|asp|txt|bak))\s+.*?(\d{3})',
        ]
        
        seen_paths = set()
        for pattern in path_patterns:
            matches = re.findall(pattern, output)
            for match in matches:
                # 根据不同格式提取 path 和 status
                if pattern.startswith(r'(\d+)'):  # dirsearch 格式
                    status, path = match[0], match[1]
                else:
                    path, status = match[0], match[1]
                
                # 规范化路径
                path = path.strip()
                if not path.startswith('/'):
                    path = '/' + path
                
                # 只保留有价值的状态码（200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403）
                # 排除 404, 500 等无效响应
                status_int = int(status)
                valid_statuses = [200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403]
                
                if path not in seen_paths and len(path) > 1 and status_int in valid_statuses:
                    seen_paths.add(path)
                    result.findings.append(f"{path} [Status: {status}]")
                    
                    # 敏感路径加入URL列表
                    sensitive_keywords = ['admin', 'login', 'upload', 'api', 'backup', 'config', 'dashboard', 'panel']
                    if any(kw in path.lower() for kw in sensitive_keywords):
                        result.urls.append(path)
        
        # 提取目标URL
        target_patterns = [
            r'URL\s*:\s*(https?://[^\s]+)',
            r'Url:\s*(https?://[^\s]+)',
            r'Target:\s*(https?://[^\s]+)',
        ]
        for pattern in target_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                result.raw_summary = f"目标: {match.group(1)}"
                break
        
        # 检查错误
        if 'error' in output.lower() or 'failed' in output.lower() or 'timeout' in output.lower():
            result.success = False
        
        return result
