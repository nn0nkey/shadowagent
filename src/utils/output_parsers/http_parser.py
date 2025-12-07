"""
HTTP 响应解析器

解析 curl、requests 等工具的 HTTP 响应输出
"""
import re
from typing import List
from .base import BaseOutputParser, ParsedOutput


class HttpParser(BaseOutputParser):
    """HTTP 响应解析器"""
    
    tool_name = "http"
    tool_patterns = ["HTTP/", "Status:", "Content-Type:", "<!DOCTYPE", "<html"]
    
    def parse(self, output: str) -> ParsedOutput:
        result = ParsedOutput(tool_name=self.tool_name)
        
        # 提取FLAG
        result.flags = self._extract_flags(output)
        
        # 提取状态码
        status_patterns = [
            r'HTTP/[\d.]+\s+(\d+)\s*(\w*)',
            r'Status:\s*(\d+)',
            r'status_code[:\s]+(\d+)',
        ]
        
        for pattern in status_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                status = match.group(1)
                result.findings.append(f"HTTP Status: {status}")
                break
        
        # 提取关键响应头
        header_patterns = [
            (r'Server:\s*(.+)', "Server"),
            (r'X-Powered-By:\s*(.+)', "X-Powered-By"),
            (r'Set-Cookie:\s*([^;\n]+)', "Cookie"),
            (r'Location:\s*(.+)', "Redirect"),
            (r'Content-Type:\s*(.+)', "Content-Type"),
            (r'X-Frame-Options:\s*(.+)', "X-Frame-Options"),
        ]
        
        for pattern, label in header_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches[:3]:
                value = match.strip()
                if label in ["Server", "X-Powered-By"]:
                    result.tech_stack.append(value)
                result.findings.append(f"{label}: {value}")
        
        # 提取链接
        link_patterns = [
            r'href=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+\.(?:php|jsp|asp|js))["\']',
        ]
        
        seen_urls = set()
        for pattern in link_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for url in matches:
                if url not in seen_urls and not url.startswith(('#', 'javascript:', 'data:')):
                    seen_urls.add(url)
                    result.urls.append(url)
        
        # 提取表单
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']?(\w+)["\']?'
        forms = re.findall(form_pattern, output, re.IGNORECASE)
        for action, method in forms:
            result.findings.append(f"表单: {method.upper()} {action}")
        
        # 提取输入字段
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']?(\w+)["\']?'
        inputs = re.findall(input_pattern, output, re.IGNORECASE)
        input_names = [f"{name}({type_})" for name, type_ in inputs]
        if input_names:
            result.findings.append(f"输入字段: {', '.join(input_names[:10])}")
        
        # 提取注释中的信息
        comment_pattern = r'<!--(.+?)-->'
        comments = re.findall(comment_pattern, output, re.DOTALL)
        for comment in comments[:3]:
            comment_clean = comment.strip()[:100]
            if comment_clean and len(comment_clean) > 5:
                result.findings.append(f"HTML注释: {comment_clean}")
        
        # 提取错误信息
        error_patterns = [
            r'(?:error|exception|warning):\s*(.+)',
            r'(?:SQL syntax|mysql_|pg_|sqlite_)(.+)',
            r'(?:Parse error|Fatal error):\s*(.+)',
        ]
        
        for pattern in error_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches[:3]:
                result.errors.append(match[:200])
        
        if result.errors:
            result.success = False
        
        return result
