"""
基于规则的信息提取器（参考 HaE 项目）
使用正则规则从工具输出中提取关键信息
"""
import re
import yaml
from typing import Dict, List
from pathlib import Path
from src.utils.logger import default_logger


class RuleBasedExtractor:
    """基于规则的信息提取器"""
    
    def __init__(self, rules_file: str = None):
        if rules_file is None:
            rules_file = Path(__file__).parent / "extraction_rules.yaml"
        
        self.rules = self._load_rules(rules_file)
        self.compiled_patterns = self._compile_patterns()
    
    def _load_rules(self, rules_file: str) -> Dict:
        """加载规则文件"""
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            default_logger.error(f"加载规则文件失败: {e}")
            return {'rules': []}
    
    def _compile_patterns(self) -> Dict[str, List[Dict]]:
        """预编译正则表达式（HaE 格式）"""
        compiled = {}
        
        for group in self.rules.get('rules', []):
            group_name = group['group']
            compiled[group_name] = []
            
            for rule in group.get('rule', []):
                if not rule.get('loaded', True):
                    continue
                
                try:
                    f_regex = rule['f_regex']
                    s_regex = rule.get('s_regex', '')
                    engine = rule.get('engine', 'nfa')
                    
                    # 编译第一层正则
                    flags = re.IGNORECASE | re.DOTALL if engine == 'nfa' else 0
                    pattern = re.compile(f_regex, flags)
                    
                    # 编译第二层正则（如果有）
                    s_pattern = None
                    if s_regex:
                        s_pattern = re.compile(s_regex, flags)
                    
                    # 根据 group 名称推断提取类型
                    extract_type = self._infer_extract_type(group_name, rule['name'])
                    
                    compiled[group_name].append({
                        'name': rule['name'],
                        'f_pattern': pattern,
                        's_pattern': s_pattern,
                        'format': rule.get('format', '{0}'),
                        'scope': rule.get('scope', 'any'),
                        'engine': engine,
                        'extract_type': rule.get('extract_type', extract_type),
                        'group': group_name
                    })
                except Exception as e:
                    default_logger.warning(f"编译规则失败 [{rule.get('name', 'unknown')}]: {e}")
        
        return compiled
    
    def _infer_extract_type(self, group_name: str, rule_name: str) -> str:
        """根据 group 和 rule 名称推断提取类型（HaE 兼容）"""
        group_lower = group_name.lower()
        rule_lower = rule_name.lower()
        
        # HaE 的 group 名称映射
        if group_name == 'Fingerprint':
            return 'fingerprint'
        
        if group_name == 'Maybe Vulnerability':
            return 'vulnerability'
        
        if group_name == 'Basic Information':
            return 'basic_info'
        
        if group_name == 'Sensitive Information':
            if 'password' in rule_lower:
                return 'secret'
            if 'username' in rule_lower:
                return 'secret'
            if 'jdbc' in rule_lower or 'key' in rule_lower:
                return 'secret'
            return 'secret'
        
        if group_name == 'Other':
            if 'link' in rule_lower:
                return 'api_endpoint'
            return 'hint'
        
        # 自定义 group 的推断
        if 'credential' in group_lower or 'auth' in group_lower:
            if 'token' in rule_lower or 'jwt' in rule_lower:
                return 'token'
            return 'credentials'
        
        if 'privilege' in group_lower or 'escalation' in group_lower:
            return 'privilege_field'
        
        if 'idor' in group_lower:
            return 'idor_point'
        
        if 'form' in group_lower or 'input' in group_lower:
            return 'form'
        
        if 'api' in group_lower or 'endpoint' in group_lower:
            return 'api_endpoint'
        
        # 默认
        return 'hint'
    
    def _execute_nfa_engine(self, text: str, f_pattern, s_pattern, format_str: str) -> List[str]:
        """执行 NFA 引擎（支持复杂正则和格式化）"""
        results = []
        
        # 第一层匹配
        for match in f_pattern.finditer(text):
            if s_pattern:
                # 有第二层正则：对第一个捕获组进行二次匹配
                if match.lastindex and match.lastindex >= 1:
                    first_group = match.group(1)
                    if first_group:
                        # 对第一个捕获组进行二次匹配
                        for s_match in s_pattern.finditer(first_group):
                            formatted = self._format_match(s_match, format_str)
                            if formatted:
                                results.append(formatted)
            else:
                # 没有第二层正则：直接格式化
                formatted = self._format_match(match, format_str)
                if formatted:
                    results.append(formatted)
        
        return results
    
    def _execute_dfa_engine(self, text: str, f_pattern, s_pattern) -> List[str]:
        """执行 DFA 引擎（简单匹配，不支持格式化）"""
        results = []
        
        # DFA 只返回匹配的字符串，不支持捕获组和格式化
        for match in f_pattern.finditer(text):
            matched_str = match.group(0)
            if s_pattern:
                # 有第二层正则：对匹配的字符串进行二次匹配
                if s_pattern.search(matched_str):
                    results.append(matched_str)
            else:
                results.append(matched_str)
        
        return results
    
    def _format_match(self, match, format_str: str) -> str:
        """格式化匹配结果（HaE 标准）"""
        try:
            # 优化：当 format 为 {0} 时直接返回第一个捕获组
            if format_str == '{0}':
                if match.lastindex and match.lastindex >= 1:
                    return match.group(1)
                return match.group(0)
            
            # 复杂格式化：提取所有捕获组
            groups = []
            if match.lastindex:
                for i in range(1, match.lastindex + 1):
                    group = match.group(i)
                    groups.append(group if group else '')
            
            if groups:
                return format_str.format(*groups)
            else:
                return match.group(0)
        except:
            return ''
    
    def extract(self, text: str) -> Dict[str, List]:
        """从文本中提取信息（兼容 HaE 规则）"""
        results = {
            'credentials': [],
            'privilege_fields': [],
            'idor_points': [],
            'forms': [],
            'api_endpoints': [],
            'secrets': [],
            'errors': [],
            'hints': [],
            'fingerprints': [],  # 指纹信息
            'vulnerabilities': [],  # 漏洞指示器
            'basic_info': []  # 基础信息（IP、邮箱等）
        }
        
        for group_name, rules in self.compiled_patterns.items():
            for rule in rules:
                # 执行正则引擎（NFA 或 DFA）
                if rule['engine'] == 'nfa':
                    formatted_results = self._execute_nfa_engine(
                        text, 
                        rule['f_pattern'], 
                        rule['s_pattern'], 
                        rule['format']
                    )
                else:  # DFA
                    formatted_results = self._execute_dfa_engine(
                        text, 
                        rule['f_pattern'], 
                        rule['s_pattern']
                    )
                
                if not formatted_results:
                    continue
                
                # 根据提取类型分类
                extract_type = rule['extract_type']
                
                if extract_type == 'credentials':
                    for formatted in formatted_results:
                        if ':' in formatted:
                            parts = formatted.split(':', 1)
                            results['credentials'].append({
                                'username': parts[0],
                                'password': parts[1],
                                'source': rule['name']
                            })
                
                elif extract_type == 'hint':
                    for formatted in formatted_results:
                        results['hints'].append({
                            'content': formatted,
                            'source': rule['name']
                        })
                
                elif extract_type in ['privilege_field', 'privilege_options']:
                    for formatted in formatted_results:
                        results['privilege_fields'].append({
                            'field': formatted,
                            'source': rule['name'],
                            'bypassable': 'disabled' in rule['name'].lower()
                        })
                
                elif extract_type in ['idor_point', 'user_id', 'id_param']:
                    for formatted in formatted_results:
                        results['idor_points'].append({
                            'id': formatted,
                            'source': rule['name']
                        })
                
                elif extract_type in ['form', 'input_field', 'hidden_field']:
                    for formatted in formatted_results:
                        results['forms'].append({
                            'info': formatted,
                            'source': rule['name']
                        })
                
                elif extract_type in ['api_endpoint', 'rest_endpoint']:
                    for formatted in formatted_results:
                        results['api_endpoints'].append({
                            'endpoint': formatted,
                            'source': rule['name']
                        })
                
                elif extract_type in ['password', 'username', 'secret']:
                    for formatted in formatted_results:
                        results['secrets'].append({
                            'value': formatted[:100],
                            'source': rule['name']
                        })
                
                elif extract_type in ['sql_error', 'error']:
                    for formatted in formatted_results:
                        results['errors'].append({
                            'message': formatted[:200],
                            'source': rule['name']
                        })
                
                elif extract_type == 'token':
                    for formatted in formatted_results:
                        results['credentials'].append({
                            'type': 'JWT',
                            'value': formatted[:50] + '...',
                            'source': rule['name']
                        })
                
                elif extract_type == 'fingerprint':
                    for formatted in formatted_results:
                        results['fingerprints'].append({
                            'name': rule['name'],
                            'value': formatted,
                            'group': rule['group']
                        })
                
                elif extract_type == 'vulnerability':
                    for formatted in formatted_results:
                        results['vulnerabilities'].append({
                            'name': rule['name'],
                            'indicator': formatted,
                            'group': rule['group']
                        })
                
                elif extract_type == 'basic_info':
                    for formatted in formatted_results:
                        results['basic_info'].append({
                            'name': rule['name'],
                            'value': formatted,
                            'group': rule['group']
                        })
        
        # 去重
        for key in results:
            if isinstance(results[key], list):
                seen = set()
                unique = []
                for item in results[key]:
                    item_str = str(sorted(item.items()))
                    if item_str not in seen:
                        seen.add(item_str)
                        unique.append(item)
                results[key] = unique
        
        return results
    
    def to_summary(self, results: Dict) -> str:
        """将提取结果转换为可读摘要"""
        lines = []
        
        if results['credentials']:
            lines.append("🔑 **发现凭证**:")
            for cred in results['credentials'][:5]:
                if 'username' in cred:
                    lines.append(f"  - {cred['username']}:{cred['password']} (来源: {cred['source']})")
                else:
                    lines.append(f"  - {cred.get('type', 'unknown')}: {cred.get('value', '')[:50]}")
        
        if results['privilege_fields']:
            lines.append("\n⚠️ **提权字段**:")
            for field in results['privilege_fields'][:3]:
                bypassable = " (可绕过)" if field.get('bypassable') else ""
                lines.append(f"  - {field['field']}{bypassable}")
        
        if results['idor_points']:
            lines.append("\n🎯 **IDOR 攻击点**:")
            for idor in results['idor_points'][:3]:
                lines.append(f"  - {idor['id']}")
        
        if results['forms']:
            lines.append("\n📝 **表单**:")
            for form in results['forms'][:3]:
                lines.append(f"  - {form['info']}")
        
        if results['api_endpoints']:
            lines.append("\n🔗 **API 端点**:")
            for api in results['api_endpoints'][:5]:
                lines.append(f"  - {api['endpoint']}")
        
        if results['errors']:
            lines.append("\n❌ **错误信息**:")
            for error in results['errors'][:2]:
                lines.append(f"  - {error['message'][:100]}")
        
        if results['hints']:
            lines.append("\n💡 **提示信息**:")
            for hint in results['hints'][:3]:
                lines.append(f"  - {hint['content'][:100]}")
        
        if results.get('fingerprints'):
            lines.append("\n🔍 **指纹信息**:")
            for fp in results['fingerprints'][:5]:
                lines.append(f"  - {fp['name']}: {fp['value'][:50]}")
        
        if results.get('vulnerabilities'):
            lines.append("\n⚡ **漏洞指示器**:")
            for vuln in results['vulnerabilities'][:3]:
                lines.append(f"  - {vuln['name']}: {vuln['indicator'][:50]}")
        
        if results.get('basic_info'):
            lines.append("\n📊 **基础信息**:")
            for info in results['basic_info'][:5]:
                lines.append(f"  - {info['name']}: {info['value'][:50]}")
        
        return "\n".join(lines) if lines else "未提取到关键信息"


# 全局实例
_extractor = None

def get_extractor():
    """获取全局提取器实例"""
    global _extractor
    if _extractor is None:
        _extractor = RuleBasedExtractor()
    return _extractor
