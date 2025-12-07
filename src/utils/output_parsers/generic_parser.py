"""
通用输出解析器

当没有特定工具解析器匹配时使用的兜底解析器
"""
import re
from typing import List
from .base import BaseOutputParser, ParsedOutput


class GenericParser(BaseOutputParser):
    """通用输出解析器"""
    
    tool_name = "generic"
    tool_patterns = []  # 总是可以匹配
    
    @classmethod
    def can_parse(cls, output: str) -> bool:
        """通用解析器总是可以解析"""
        return True
    
    def parse(self, output: str) -> ParsedOutput:
        result = ParsedOutput(tool_name=self.tool_name)
        
        # 提取FLAG
        result.flags = self._extract_flags(output)
        
        # 提取凭证
        result.credentials = self._extract_credentials(output)
        
        # 按行分析，提取有价值的行
        lines = output.split('\n')
        
        # 有价值行的特征
        valuable_patterns = [
            (r'Status[:\s]+\d+', "状态码"),
            (r'\d+/tcp\s+open', "端口"),
            (r'http[s]?://[^\s]+', "URL"),
            (r'/[\w\-\.]+\.(php|html|jsp|asp|txt|bak|sql|xml|json)', "文件"),
            (r'(admin|login|upload|api|backup|config|dashboard)', "敏感路径"),
            (r'(error|warning|exception|failed|denied)', "错误"),
            (r'(found|discovered|detected|vulnerable)', "发现"),
            (r'Server:\s*\S+', "Server"),
            (r'X-Powered-By:\s*\S+', "技术栈"),
            (r'\[\+\]|\[!\]|\[\*\]', "工具标记"),
        ]
        
        # 无价值行的特征
        junk_patterns = [
            r'^[\s\-=_\*#]+$',
            r'^[\s]*$',
            r'^\s*[\|\\/\-]+\s*$',
            r'^\s*\d+%\s*$',
            r'^\.+$',
        ]
        
        for line in lines:
            line_stripped = line.strip()
            if not line_stripped or len(line_stripped) > 500:
                continue
            
            # 跳过无价值行
            is_junk = any(re.match(p, line_stripped) for p in junk_patterns)
            if is_junk:
                continue
            
            # 检查是否有价值
            for pattern, label in valuable_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # 根据类型分类
                    if label == "URL":
                        urls = re.findall(r'http[s]?://[^\s<>"\']+', line)
                        result.urls.extend(urls)
                    elif label == "技术栈" or label == "Server":
                        result.tech_stack.append(line_stripped)
                    elif label == "错误":
                        result.errors.append(line_stripped[:200])
                    else:
                        result.findings.append(line_stripped)
                    break
        
        # 去重
        result.findings = list(dict.fromkeys(result.findings))[:30]
        result.urls = list(dict.fromkeys(result.urls))[:20]
        result.tech_stack = list(dict.fromkeys(result.tech_stack))[:10]
        result.errors = list(dict.fromkeys(result.errors))[:5]
        
        # 生成原始摘要（头尾）
        if len(output) > 1000:
            head = output[:400]
            tail = output[-400:]
            result.raw_summary = f"[头部]\n{head}\n\n[尾部]\n{tail}"
        else:
            result.raw_summary = output
        
        return result
