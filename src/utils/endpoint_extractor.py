"""
端点发现工具 - 从JS文件和HTML中提取API端点

支持的提取方式：
1. 从HTML页面提取JS文件链接
2. 从JS文件中提取API端点（使用正则表达式）
3. 调用外部工具（LinkFinder, katana等）
"""

import re
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field


@dataclass
class Endpoint:
    """API端点信息"""
    path: str
    method: str = "GET"
    source: str = ""  # 来源（JS文件名、HTML等）
    params: List[str] = field(default_factory=list)
    confidence: float = 1.0  # 置信度


class EndpointExtractor:
    """端点提取器"""
    
    # API端点正则模式
    ENDPOINT_PATTERNS = [
        # REST API 路径
        r'["\'](/api/[a-zA-Z0-9_/\-\.]+)["\']',
        r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-\.]+)["\']',
        r'["\'](/graphql/?)["\']',
        r'["\'](/rest/[a-zA-Z0-9_/\-\.]+)["\']',
        
        # 常见端点路径
        r'["\'](/[a-zA-Z0-9_\-]+\.(php|asp|aspx|jsp|json|xml))["\']',
        r'["\'](/admin[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/login|/logout|/register|/auth[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/user[s]?[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/upload[s]?[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/download[s]?[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/file[s]?[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/config[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/setting[s]?[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/backup[s]?[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/debug[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/test[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/internal[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/private[a-zA-Z0-9_/\-]*)["\']',
        r'["\'](/secret[a-zA-Z0-9_/\-]*)["\']',
        
        # fetch/axios 调用
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
        
        # URL构造
        r'url\s*[=:]\s*["\']([^"\']+)["\']',
        r'endpoint\s*[=:]\s*["\']([^"\']+)["\']',
        r'path\s*[=:]\s*["\']([^"\']+)["\']',
        r'href\s*[=:]\s*["\']([^"\']+)["\']',
        r'action\s*[=:]\s*["\']([^"\']+)["\']',
    ]
    
    # JS文件链接正则
    JS_LINK_PATTERNS = [
        r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
        r'["\']([^"\']+\.js)["\']',
    ]
    
    # 敏感信息正则
    SENSITIVE_PATTERNS = {
        'api_key': r'["\']?(?:api[_-]?key|apikey)["\']?\s*[=:]\s*["\']([^"\']+)["\']',
        'secret': r'["\']?(?:secret|password|passwd|pwd)["\']?\s*[=:]\s*["\']([^"\']+)["\']',
        'token': r'["\']?(?:token|access[_-]?token|auth[_-]?token)["\']?\s*[=:]\s*["\']([^"\']+)["\']',
        'aws_key': r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}',
        'private_key': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
        'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
    }
    
    # 排除的路径模式（静态资源等）
    EXCLUDE_PATTERNS = [
        r'^https?://',  # 完整URL（外部链接）
        r'\.(css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$',
        r'^#',  # 锚点
        r'^javascript:',
        r'^data:',
        r'^mailto:',
        r'^tel:',
    ]
    
    def __init__(self):
        self.endpoints: Set[str] = set()
        self.js_files: Set[str] = set()
        self.sensitive_info: Dict[str, List[str]] = {}
    
    def extract_js_links(self, html_content: str, base_url: str = "") -> List[str]:
        """从HTML中提取JS文件链接"""
        js_links = []
        
        for pattern in self.JS_LINK_PATTERNS:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                # 处理相对路径
                if match.startswith('//'):
                    js_links.append('https:' + match)
                elif match.startswith('/'):
                    if base_url:
                        js_links.append(base_url.rstrip('/') + match)
                    else:
                        js_links.append(match)
                elif not match.startswith('http'):
                    if base_url:
                        js_links.append(base_url.rstrip('/') + '/' + match)
                    else:
                        js_links.append('/' + match)
                else:
                    js_links.append(match)
        
        # 去重并过滤外部CDN
        unique_links = []
        seen = set()
        for link in js_links:
            if link not in seen:
                seen.add(link)
                # 过滤常见CDN
                if not any(cdn in link for cdn in ['cdn.', 'cdnjs.', 'unpkg.com', 'jsdelivr.', 'googleapis.', 'bootstrapcdn.']):
                    unique_links.append(link)
        
        self.js_files.update(unique_links)
        return unique_links
    
    def extract_endpoints(self, content: str, source: str = "") -> List[Endpoint]:
        """从内容中提取API端点"""
        endpoints = []
        seen = set()
        
        for pattern in self.ENDPOINT_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                # 处理元组结果
                if isinstance(match, tuple):
                    match = match[0]
                
                # 清理路径
                path = match.strip()
                
                # 排除不需要的路径
                if self._should_exclude(path):
                    continue
                
                # 去重
                if path in seen:
                    continue
                seen.add(path)
                
                # 检测HTTP方法
                method = self._detect_method(content, path)
                
                # 提取参数
                params = self._extract_params(content, path)
                
                endpoint = Endpoint(
                    path=path,
                    method=method,
                    source=source,
                    params=params
                )
                endpoints.append(endpoint)
        
        self.endpoints.update(e.path for e in endpoints)
        return endpoints
    
    def extract_sensitive_info(self, content: str) -> Dict[str, List[str]]:
        """提取敏感信息"""
        results = {}
        
        for info_type, pattern in self.SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                results[info_type] = list(set(matches))
        
        # 合并到实例变量
        for k, v in results.items():
            if k in self.sensitive_info:
                self.sensitive_info[k].extend(v)
                self.sensitive_info[k] = list(set(self.sensitive_info[k]))
            else:
                self.sensitive_info[k] = v
        
        return results
    
    def _should_exclude(self, path: str) -> bool:
        """检查路径是否应该排除"""
        for pattern in self.EXCLUDE_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        return False
    
    def _detect_method(self, content: str, path: str) -> str:
        """检测端点的HTTP方法"""
        # 在路径附近查找方法指示
        escaped_path = re.escape(path)
        
        # POST 指示
        post_patterns = [
            rf'\.post\s*\([^)]*{escaped_path}',
            rf'method\s*[=:]\s*["\']POST["\'][^}}]*{escaped_path}',
            rf'{escaped_path}[^}}]*method\s*[=:]\s*["\']POST["\']',
        ]
        for pattern in post_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return "POST"
        
        # PUT 指示
        if re.search(rf'\.put\s*\([^)]*{escaped_path}', content, re.IGNORECASE):
            return "PUT"
        
        # DELETE 指示
        if re.search(rf'\.delete\s*\([^)]*{escaped_path}', content, re.IGNORECASE):
            return "DELETE"
        
        return "GET"
    
    def _extract_params(self, content: str, path: str) -> List[str]:
        """提取端点的参数"""
        params = []
        escaped_path = re.escape(path)
        
        # 查找路径附近的参数定义
        param_patterns = [
            rf'{escaped_path}[^}}]*params\s*[=:]\s*\{{([^}}]+)\}}',
            rf'{escaped_path}[^}}]*data\s*[=:]\s*\{{([^}}]+)\}}',
            rf'{escaped_path}\?([^"\']+)["\']',
        ]
        
        for pattern in param_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                param_str = match.group(1)
                # 提取参数名
                param_names = re.findall(r'["\']?(\w+)["\']?\s*:', param_str)
                params.extend(param_names)
        
        return list(set(params))
    
    def generate_commands(self, target_url: str) -> List[str]:
        """生成端点发现命令"""
        commands = []
        
        # 1. 使用 katana 爬取
        commands.append(
            f"katana -u {target_url} -jc -d 3 -o /tmp/katana_endpoints.txt 2>/dev/null && cat /tmp/katana_endpoints.txt"
        )
        
        # 2. 使用 LinkFinder 分析JS
        commands.append(
            f"linkfinder -i {target_url} -o cli 2>/dev/null | head -100"
        )
        
        # 3. 手动提取JS并分析
        commands.append(
            f"curl -s {target_url} | grep -oE 'src=\"[^\"]+\\.js[^\"]*\"' | cut -d'\"' -f2"
        )
        
        # 4. 使用 gau 获取历史URL（如果是公网目标）
        # commands.append(f"echo {target_url} | gau --threads 5 2>/dev/null | head -50")
        
        return commands
    
    def get_summary(self) -> str:
        """获取发现摘要"""
        lines = ["=== 端点发现摘要 ==="]
        
        if self.js_files:
            lines.append(f"\n📄 发现 {len(self.js_files)} 个JS文件:")
            for js in list(self.js_files)[:10]:
                lines.append(f"  - {js}")
            if len(self.js_files) > 10:
                lines.append(f"  ... 还有 {len(self.js_files) - 10} 个")
        
        if self.endpoints:
            lines.append(f"\n🔗 发现 {len(self.endpoints)} 个端点:")
            for ep in list(self.endpoints)[:20]:
                lines.append(f"  - {ep}")
            if len(self.endpoints) > 20:
                lines.append(f"  ... 还有 {len(self.endpoints) - 20} 个")
        
        if self.sensitive_info:
            lines.append(f"\n⚠️ 发现敏感信息:")
            for info_type, values in self.sensitive_info.items():
                lines.append(f"  - {info_type}: {len(values)} 个")
        
        return "\n".join(lines)


# 便捷函数
def extract_endpoints_from_html(html: str, base_url: str = "") -> Dict:
    """从HTML中提取所有端点信息"""
    extractor = EndpointExtractor()
    
    # 提取JS链接
    js_links = extractor.extract_js_links(html, base_url)
    
    # 从HTML中提取端点
    endpoints = extractor.extract_endpoints(html, source="HTML")
    
    # 提取敏感信息
    sensitive = extractor.extract_sensitive_info(html)
    
    return {
        "js_files": js_links,
        "endpoints": [{"path": e.path, "method": e.method, "params": e.params} for e in endpoints],
        "sensitive_info": sensitive,
        "summary": extractor.get_summary()
    }


def get_endpoint_discovery_prompt() -> str:
    """获取端点发现的提示词片段"""
    return """
## 🔍 端点发现策略（重要！）

在攻击Web应用时，**必须先进行端点发现**，不要只依赖目录扫描：

### 1. JS文件端点提取（最重要）
```bash
# 使用 LinkFinder 从JS中提取端点
linkfinder -i <target_url> -o cli

# 使用 katana 深度爬取
katana -u <target_url> -jc -d 3

# 手动提取JS文件
curl -s <target_url> | grep -oE 'src="[^"]+\\.js[^"]*"' | cut -d'"' -f2
```

### 2. 从JS中查找的关键信息
- API端点: `/api/`, `/v1/`, `/graphql`, `/rest/`
- 隐藏路径: `/admin`, `/internal`, `/debug`, `/backup`
- 敏感参数: `url=`, `path=`, `file=`, `redirect=`, `callback=`
- 认证信息: API密钥、Token、Secret

### 3. Python端点提取代码
```python
import requests
import re

# 获取页面
r = requests.get(target_url)

# 提取JS文件
js_files = re.findall(r'src="([^"]+\\.js[^"]*)"', r.text)

# 提取API端点
endpoints = re.findall(r'["\\'](/api/[a-zA-Z0-9_/\\-\\.]+)["\\'"]', r.text)
endpoints += re.findall(r'fetch\\s*\\(\\s*["\\'"]([^"\\']+)["\\'"]', r.text)

print("JS文件:", js_files)
print("端点:", endpoints)
```

### 4. 端点发现优先级
1. **首先**: 分析首页HTML，提取所有JS文件链接
2. **然后**: 下载并分析每个JS文件，提取API端点
3. **接着**: 查找敏感参数（url=, file=, path=等）
4. **最后**: 目录扫描补充遗漏的路径
"""
