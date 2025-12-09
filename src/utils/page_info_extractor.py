"""
页面信息提取器
每次访问新页面时自动提取关键信息
参考 ctfSolver 的实现
"""
import re
from typing import Dict, List
from src.utils.logger import default_logger
from src.utils.key_discovery import get_key_discovery_manager


def extract_page_info_from_output(command: str, output: str):
    """
    从命令输出中提取页面信息
    
    Args:
        command: 执行的命令
        output: 命令输出
    """
    # 提取 URL
    url = _extract_url_from_command(command)
    if not url:
        return
    
    default_logger.debug(f"[页面信息提取] 分析页面: {url}")
    
    discovery_manager = get_key_discovery_manager()
    
    # 1. 提取表单
    forms = _extract_forms(output)
    for form in forms:
        form_desc = f"{form['method']} {form['action']} - 参数: {', '.join(form['inputs'])}"
        discovery_manager.add_discovery(
            "form",
            form_desc,
            source="auto_extract",
            confidence=85
        )
        default_logger.info(f"[页面信息提取] 发现表单: {form_desc}")
    
    # 2. 提取链接
    links = _extract_links(output, url)
    for link in links[:10]:  # 最多记录10个
        if link not in [url, url + '/', url + '#']:
            discovery_manager.add_discovery(
                "link",
                link,
                source="auto_extract",
                confidence=70
            )
            default_logger.debug(f"[页面信息提取] 发现链接: {link}")
    
    # 3. 提取 API 端点（从 JS 或响应中）
    api_endpoints = _extract_api_endpoints(output)
    for endpoint in api_endpoints:
        discovery_manager.add_discovery(
            "api_endpoint",
            endpoint,
            source="auto_extract",
            confidence=75
        )
        default_logger.info(f"[页面信息提取] 发现 API: {endpoint}")
    
    # 4. 提取参数名（从表单、JS、响应中）
    params = _extract_parameters(output)
    if params:
        params_str = ', '.join(params[:10])  # 最多10个
        discovery_manager.add_discovery(
            "api_params",
            f"发现参数: {params_str}",
            source="auto_extract",
            confidence=80
        )
        default_logger.info(f"[页面信息提取] 发现参数: {params_str}")
    
    # 5. 提取凭证信息
    credentials = _extract_credentials(output)
    for cred in credentials:
        discovery_manager.add_discovery(
            "credential",
            cred,
            source="auto_extract",
            confidence=90
        )
        default_logger.info(f"[页面信息提取] 发现凭证: {cred}")


def _extract_url_from_command(command: str) -> str:
    """从命令中提取 URL"""
    # curl http://... 或 wget http://...
    match = re.search(r'(https?://[^\s\'"]+)', command)
    if match:
        return match.group(1).rstrip('/')
    return None


def _extract_forms(html: str) -> List[Dict]:
    """提取表单信息"""
    forms = []
    
    # 提取所有 form 标签
    form_pattern = r'<form[^>]*>(.*?)</form>'
    form_matches = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)
    
    for form_html in form_matches:
        form_info = {}
        
        # 提取 action
        action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        form_info['action'] = action_match.group(1) if action_match else '/'
        
        # 提取 method
        method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        form_info['method'] = method_match.group(1).upper() if method_match else 'GET'
        
        # 提取输入字段
        input_pattern = r'<input[^>]+name=["\']([^"\']+)["\']'
        inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
        form_info['inputs'] = inputs
        
        if form_info['inputs']:
            forms.append(form_info)
    
    return forms


def _extract_links(html: str, base_url: str) -> List[str]:
    """提取链接"""
    links = set()
    
    # 提取 href
    href_pattern = r'href=["\']([^"\']+)["\']'
    matches = re.findall(href_pattern, html, re.IGNORECASE)
    
    for match in matches:
        if match and not match.startswith(('#', 'javascript:', 'mailto:', 'data:')):
            # 简单处理相对路径
            if match.startswith('http'):
                links.add(match)
            elif match.startswith('/'):
                # 提取 base_url 的域名部分
                domain_match = re.match(r'(https?://[^/]+)', base_url)
                if domain_match:
                    links.add(domain_match.group(1) + match)
            else:
                links.add(base_url + '/' + match)
    
    return list(links)


def _extract_api_endpoints(content: str) -> List[str]:
    """提取 API 端点"""
    endpoints = set()
    
    # 常见的 API 路径模式
    patterns = [
        r'["\']/(api/[a-zA-Z0-9/_-]+)["\']',  # /api/...
        r'["\']/(v\d+/[a-zA-Z0-9/_-]+)["\']',  # /v1/...
        r'"path":\s*"([^"]+)"',                 # "path": "..."
        r'"url":\s*"([^"]+)"',                  # "url": "..."
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, content)
        for match in matches:
            if match.startswith('/') and len(match) > 1:
                # 过滤静态资源
                if not any(match.endswith(ext) for ext in ['.css', '.png', '.jpg', '.ico', '.svg', '.woff', '.js']):
                    endpoints.add(match)
    
    return list(endpoints)


def _extract_parameters(content: str) -> List[str]:
    """提取参数名"""
    params = set()
    
    # 从 JSON 中提取
    json_param_pattern = r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:'
    matches = re.findall(json_param_pattern, content)
    
    # 过滤常见的非参数字段
    exclude = {'html', 'head', 'body', 'div', 'span', 'script', 'style', 'meta', 'link', 
               'title', 'type', 'class', 'id', 'name', 'value', 'src', 'href', 'content'}
    
    for match in matches:
        if match not in exclude and len(match) > 2:
            params.add(match)
    
    # 从表单中提取
    input_pattern = r'name=["\']([^"\']+)["\']'
    input_matches = re.findall(input_pattern, content, re.IGNORECASE)
    params.update(input_matches)
    
    return list(params)


def _extract_credentials(content: str) -> List[str]:
    """提取凭证信息"""
    credentials = []
    
    # 常见的凭证模式
    patterns = [
        (r'username["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'username'),
        (r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'password'),
        (r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'token'),
        (r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'api_key'),
        (r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'secret'),
    ]
    
    for pattern, cred_type in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            if len(match) > 2 and match not in ['...', 'xxx', '***']:
                credentials.append(f"{cred_type}: {match}")
    
    # 提取演示账号信息
    demo_pattern = r'(?:demo|test|example)\s+(?:account|user|username|login).*?(?:username|user):\s*(\w+).*?password:\s*(\w+)'
    demo_matches = re.findall(demo_pattern, content, re.IGNORECASE | re.DOTALL)
    for username, password in demo_matches:
        credentials.append(f"demo_account: {username}/{password}")
    
    return credentials
