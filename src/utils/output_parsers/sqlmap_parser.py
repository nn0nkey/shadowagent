"""
SQL注入工具输出解析器

支持: sqlmap 等SQL注入工具
"""
import re
from typing import List
from .base import BaseOutputParser, ParsedOutput


class SqliParser(BaseOutputParser):
    """SQL注入工具输出解析器（通用）"""
    
    tool_name = "sqli"
    tool_patterns = [
        "sqlmap", "[INFO]", "[WARNING]", 
        "injection", "injectable", "parameter",
        "DBMS", "database", "payload"
    ]
    
    def parse(self, output: str) -> ParsedOutput:
        result = ParsedOutput(tool_name=self.tool_name)
        
        # 提取FLAG
        result.flags = self._extract_flags(output)
        
        # 提取注入点
        # 格式: Parameter: id (GET) / Type: boolean-based blind
        injection_patterns = [
            r"Parameter:\s*'?(\w+)'?\s*\((\w+)\)",
            r"(\w+)\s+parameter\s+'(\w+)'\s+is\s+vulnerable",
            r"Type:\s*(.+)",
        ]
        
        for pattern in injection_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    result.findings.append(f"注入点: {' '.join(match)}")
                else:
                    result.findings.append(f"注入类型: {match}")
        
        # 提取数据库信息
        db_patterns = [
            (r"available databases\s*\[(\d+)\]:\s*\n((?:\[\*\]\s*\w+\n?)+)", "数据库"),
            (r"Database:\s*(\w+)", "当前数据库"),
            (r"back-end DBMS:\s*(.+)", "数据库类型"),
            (r"web application technology:\s*(.+)", "Web技术"),
        ]
        
        for pattern, label in db_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                result.findings.append(f"{label}: {match.group(1)}")
                if label == "数据库类型":
                    result.tech_stack.append(match.group(1))
        
        # 提取表和列
        table_pattern = r"Table:\s*(\w+)"
        tables = re.findall(table_pattern, output)
        if tables:
            result.findings.append(f"发现的表: {', '.join(set(tables))}")
        
        # 提取数据（用户名、密码等）
        data_pattern = r"\|\s*(\w+)\s*\|\s*(\w+)\s*\|"
        data_matches = re.findall(data_pattern, output)
        for match in data_matches[:10]:  # 最多10条
            result.credentials.append(f"{match[0]}:{match[1]}")
        
        # 提取警告和错误
        warning_pattern = r"\[WARNING\]\s*(.+)"
        warnings = re.findall(warning_pattern, output)
        result.warnings = warnings[:5]
        
        error_pattern = r"\[ERROR\]\s*(.+)"
        errors = re.findall(error_pattern, output)
        result.errors = errors[:5]
        
        if errors:
            result.success = False
        
        return result
