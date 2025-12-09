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
    
    def __init__(self):
        super().__init__()
        # 延迟导入，避免循环依赖
        self._extractor = None
    
    @property
    def extractor(self):
        """延迟加载规则提取器"""
        if self._extractor is None:
            try:
                from src.utils.rule_based_extractor import get_extractor
                self._extractor = get_extractor()
            except Exception:
                self._extractor = None
        return self._extractor
    
    def parse(self, output: str) -> ParsedOutput:
        result = ParsedOutput(tool_name=self.tool_name)
        
        # 第一步：使用规则提取器提取关键信息（新增）⭐
        if self.extractor and len(output) > 100:  # 只对较长的输出使用规则提取
            try:
                extracted = self.extractor.extract(output, scope='critical')
                self._merge_extracted_info(result, extracted)
            except Exception as e:
                pass  # 降级到原有逻辑
        
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
    
    def _merge_extracted_info(self, result: ParsedOutput, extracted: dict):
        """将规则提取的信息合并到结果中"""
        # 凭证信息
        for cred in extracted.get('credentials', []):
            if 'username' in cred and 'password' in cred:
                result.findings.append(
                    f"🔑 发现凭证: {cred['username']}:{cred['password']} (来源: {cred['source']})"
                )
            elif 'type' in cred:
                result.findings.append(
                    f"🔑 认证信息: {cred['type']} {cred.get('value', '')[:50]}"
                )
        
        # 提权字段
        for field in extracted.get('privilege_fields', []):
            bypassable = " (disabled，可绕过)" if field.get('bypassable') else ""
            result.findings.append(
                f"⚠️ 提权字段: {field['field']}{bypassable}"
            )
        
        # IDOR 点
        for idor in extracted.get('idor_points', []):
            result.findings.append(
                f"🎯 IDOR 攻击点: ID={idor['id']} ({idor['type']})"
            )
        
        # API 端点
        for api in extracted.get('api_endpoints', []):
            param_note = " (有参数)" if api.get('has_param') else ""
            result.urls.append(api['endpoint'])
            result.findings.append(f"🔗 API: {api['endpoint']}{param_note}")
        
        # 漏洞指示器
        for vuln in extracted.get('vulnerabilities', []):
            result.findings.append(
                f"⚡ 漏洞指示器: {vuln['type']} - {vuln['indicator'][:50]}"
            )
        
        # 提示信息
        for hint in extracted.get('hints', []):
            result.findings.append(
                f"💡 提示: {hint['content'][:100]}"
            )
