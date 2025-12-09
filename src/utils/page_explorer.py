"""
页面探索工具
自动收集目标网站的页面信息、API端点、JS文件等
"""
import re
import subprocess
import requests
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional
from src.utils.logger import default_logger
import json


def _can_access_url(url: str) -> bool:
    """
    检测当前环境能否直接访问 URL
    
    Returns:
        True: 可以直接用 requests 访问
        False: 需要通过 Docker 容器访问
    """
    try:
        # 快速测试连接（2秒超时，避免误判）
        response = requests.get(url, timeout=2)
        return response.status_code < 500  # 只要不是服务器错误就算成功
    except:
        return False


def _get_page_content(url: str) -> str:
    """
    获取页面内容（自动选择访问方式）
    
    Returns:
        页面 HTML 内容
    """
    # 检测是否能直接访问
    can_access = _can_access_url(url)
    default_logger.info(f"🌐 [页面访问] URL: {url}, 本地可访问: {can_access}")
    
    if can_access:
        # 本地环境可以直接访问
        default_logger.info(f"🌐 [页面访问] 使用本地 requests")
        response = requests.get(url, timeout=10, allow_redirects=True)
        html = response.text
        default_logger.info(f"🌐 [页面访问] 获取到 {len(html)} 字符")
        return html
    else:
        # 需要通过 Docker 容器访问（如 host.docker.internal）
        # 使用同步 subprocess 避免事件循环冲突
        default_logger.info(f"🌐 [页面访问] 使用 Docker 容器 curl")
        import subprocess
        try:
            result = subprocess.run(
                ["docker", "exec", "shadowagent-kali", "curl", "-s", "-L", url],
                capture_output=True,
                text=True,
                timeout=10
            )
            html = result.stdout
            default_logger.info(f"🌐 [页面访问] 获取到 {len(html)} 字符")
            return html
        except Exception as e:
            default_logger.error(f"🌐 [页面访问] Docker curl 失败: {e}")
            return ""


def explore_target_initial(url: str, timeout: int = 60) -> Dict:
    """
    初始探索：自动收集页面信息
    
    Args:
        url: 目标URL
        timeout: 超时时间（秒）
    
    Returns:
        探索结果字典
    """
    default_logger.info(f"🔍 [页面探索] 开始探索目标: {url}")
    
    result = {
        'base_info': {},
        'paths': [],
        'js_files': [],
        'api_endpoints': [],
        'forms': [],
        'links': [],
        'page_content': ''  # 添加页面内容字段（供 HAE 解析）
    }
    
    try:
        # 1. 获取基础信息
        default_logger.info("📋 [页面探索] 获取基础信息...")
        result['base_info'] = _get_base_info(url)
        
        # 2. 检查 API 文档（openapi.json, /docs, /swagger）
        default_logger.info("📚 [页面探索] 检查 API 文档...")
        api_docs = _check_api_docs(url)
        if api_docs:
            result['api_endpoints'].extend(api_docs)
            default_logger.info(f"✅ [页面探索] 从 API 文档发现 {len(api_docs)} 个端点")
        
        # 3. 快速路径扫描（使用 dirb，只扫描 common）
        default_logger.info("🔎 [页面探索] 快速路径扫描...")
        result['paths'] = _quick_path_scan(url, timeout=timeout)
        default_logger.info(f"✅ [页面探索] 发现 {len(result['paths'])} 个有效路径")
        
        # 4. 提取页面内容（JS、链接、表单）
        default_logger.info("📄 [页面探索] 提取页面内容...")
        page_content_data = _extract_page_content(url)
        result['js_files'] = page_content_data.get('js_files', [])
        result['links'] = page_content_data.get('links', [])
        result['forms'] = page_content_data.get('forms', [])
        result['page_content'] = page_content_data.get('html', '')  # 保存原始 HTML
        default_logger.info(f"✅ [页面探索] 提取到 {len(result['js_files'])} 个 JS 文件, {len(result['links'])} 个链接, {len(result['forms'])} 个表单")
        
        # 5. 分析 JS 文件（使用 linkfinder）
        if result['js_files']:
            default_logger.info("🔬 [页面探索] 分析 JS 文件...")
            for js_url in result['js_files'][:5]:  # 最多分析5个
                endpoints = _analyze_js_file(js_url)
                if endpoints:
                    result['api_endpoints'].extend(endpoints)
            default_logger.info(f"✅ [页面探索] 从 JS 文件发现 {len(result['api_endpoints'])} 个 API 端点")
        
        default_logger.info(f"🎉 [页面探索] 探索完成！总计: {len(result['paths'])} 路径, {len(result['api_endpoints'])} API, {len(result['js_files'])} JS")
        
    except Exception as e:
        default_logger.error(f"❌ [页面探索] 探索失败: {e}")
    
    return result


def _get_base_info(url: str) -> Dict:
    """
    获取目标的基础信息
    """
    info = {
        'url': url,
        'status_code': None,
        'title': None,
        'server': None,
        'tech_stack': []
    }
    
    try:
        # 使用统一的页面获取方法
        html = _get_page_content(url)
        
        # 提取标题
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        if title_match:
            info['title'] = title_match.group(1).strip()
        
        # 尝试从响应头获取信息（如果是本地访问）
        if _can_access_url(url):
            response = requests.get(url, timeout=10, allow_redirects=True)
            info['status_code'] = response.status_code
            info['server'] = response.headers.get('Server', 'Unknown')
            
            # 识别技术栈
            tech_stack = []
            if 'X-Powered-By' in response.headers:
                tech_stack.append(response.headers['X-Powered-By'])
            
            # 检测框架
            if 'uvicorn' in response.headers.get('Server', '').lower():
                tech_stack.append('FastAPI/Uvicorn')
            elif 'werkzeug' in response.headers.get('Server', '').lower():
                tech_stack.append('Flask/Werkzeug')
            elif 'express' in response.headers.get('X-Powered-By', '').lower():
                tech_stack.append('Express.js')
            
            info['tech_stack'] = tech_stack
        
    except Exception as e:
        default_logger.warning(f"获取基础信息失败: {e}")
    
    return info


def _check_api_docs(url: str) -> List[str]:
    """
    检查常见的 API 文档端点
    """
    api_endpoints = []
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # 常见的 API 文档路径
    doc_paths = [
        '/openapi.json',
        '/api/openapi.json',
        '/docs',
        '/api/docs',
        '/swagger.json',
        '/api/swagger.json',
        '/swagger',
        '/api-docs',
        '/redoc'
    ]
    
    for path in doc_paths:
        try:
            doc_url = urljoin(base_url, path)
            response = requests.get(doc_url, timeout=5)
            
            if response.status_code == 200:
                # 尝试解析 OpenAPI/Swagger JSON
                if path.endswith('.json'):
                    try:
                        api_spec = response.json()
                        if 'paths' in api_spec:
                            endpoints = list(api_spec['paths'].keys())
                            default_logger.info(f"✅ 从 {path} 发现 {len(endpoints)} 个端点")
                            api_endpoints.extend(endpoints)
                    except json.JSONDecodeError:
                        pass
                else:
                    default_logger.info(f"✅ 发现 API 文档: {doc_url}")
        except:
            pass
    
    return list(set(api_endpoints))  # 去重


def _quick_path_scan(url: str, timeout: int = 60) -> List[str]:
    """
    快速路径扫描
    
    注意：初始探索在本地环境执行，不在 Docker 容器中
    因此不使用 dirb/gobuster 等工具，而是使用简单的路径探测
    详细的目录扫描由 Agent 在 Docker 容器中执行
    """
    paths = []
    
    default_logger.info(f"快速路径探测: {url}")
    
    # 常见的重要路径
    common_paths = [
        # 认证相关
        '/login', '/signin', '/auth', '/token', '/logout',
        # 管理相关
        '/admin', '/dashboard', '/console', '/manage',
        # API 相关
        '/api', '/api/v1', '/api/v2', '/graphql',
        # 文档相关
        '/docs', '/swagger', '/redoc', '/api-docs',
        # 配置和状态
        '/config', '/status', '/health', '/metrics',
        # 用户相关
        '/users', '/user', '/profile', '/account',
        # 其他
        '/register', '/signup', '/reset', '/forgot'
    ]
    
    valid_statuses = [200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403]
    
    for path in common_paths:
        try:
            test_url = urljoin(url, path)
            response = requests.get(test_url, timeout=3, allow_redirects=False)
            if response.status_code in valid_statuses:
                paths.append(f"{path} [Status: {response.status_code}]")
                default_logger.debug(f"✓ {path} [{response.status_code}]")
        except requests.exceptions.Timeout:
            default_logger.debug(f"✗ {path} [Timeout]")
        except requests.exceptions.ConnectionError:
            default_logger.debug(f"✗ {path} [Connection Error]")
        except Exception as e:
            default_logger.debug(f"✗ {path} [{type(e).__name__}]")
    
    default_logger.info(f"快速探测完成，发现 {len(paths)} 个路径")
    return paths


def _extract_page_content(url: str) -> Dict:
    """
    从页面提取 JS 文件、链接、表单
    """
    content = {
        'js_files': [],
        'links': [],
        'forms': [],
        'html': ''  # 保存原始 HTML（供 HAE 解析）
    }
    
    try:
        # 使用统一的页面获取方法
        html = _get_page_content(url)
        content['html'] = html  # 保存原始 HTML
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # 1. 提取 JS 文件
        js_patterns = [
            r'<script[^>]+src=["\']([^"\']+)["\']',  # <script src="...">
            r'src=["\']([^"\']*\.js[^"\']*)["\']',   # src="...js..."
        ]
        
        js_urls = set()
        for pattern in js_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if match and not match.startswith('data:'):
                    # 处理相对路径
                    if match.startswith('http'):
                        js_urls.add(match)
                    elif match.startswith('/'):
                        js_urls.add(base_url + match)
                    else:
                        js_urls.add(urljoin(url, match))
        
        content['js_files'] = list(js_urls)
        
        # 2. 提取链接
        link_pattern = r'<a[^>]+href=["\']([^"\']+)["\']'
        links = re.findall(link_pattern, html, re.IGNORECASE)
        
        # 过滤和规范化链接
        valid_links = []
        for link in links:
            if link and not link.startswith(('#', 'javascript:', 'mailto:')):
                if link.startswith('http'):
                    valid_links.append(link)
                elif link.startswith('/'):
                    valid_links.append(base_url + link)
                else:
                    valid_links.append(urljoin(url, link))
        
        content['links'] = list(set(valid_links))
        
        # 3. 提取表单
        # 修改正则：同时捕获 <form> 标签和表单内容
        form_pattern = r'<form([^>]*)>(.*?)</form>'
        forms = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)
        
        for form_tag, form_content in forms:
            form_info = {}
            
            # 从 <form> 标签中提取 action
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_tag, re.IGNORECASE)
            if action_match:
                action = action_match.group(1)
                if action.startswith('http'):
                    form_info['action'] = action
                elif action.startswith('/'):
                    form_info['action'] = base_url + action
                else:
                    form_info['action'] = urljoin(url, action)
            else:
                form_info['action'] = url  # 默认提交到当前页面
            
            # 从 <form> 标签中提取 method
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_tag, re.IGNORECASE)
            form_info['method'] = method_match.group(1).upper() if method_match else 'GET'
            
            # 从表单内容中提取输入字段
            input_pattern = r'<input[^>]+name=["\']([^"\']+)["\']'
            inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
            form_info['inputs'] = inputs
            
            if form_info.get('inputs'):
                content['forms'].append(form_info)
        
    except Exception as e:
        default_logger.warning(f"提取页面内容失败: {e}")
    
    return content


def _analyze_js_file(js_url: str) -> List[str]:
    """
    分析 JS 文件，提取 API 端点
    优先使用 linkfinder，如果不可用则使用正则表达式
    """
    endpoints = []
    
    # 尝试使用 linkfinder
    try:
        check_linkfinder = subprocess.run(['which', 'linkfinder'], capture_output=True, timeout=5)
        if check_linkfinder.returncode == 0:
            cmd = [
                'linkfinder',
                '-i', js_url,
                '-o', 'cli'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # 解析 linkfinder 输出
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and line.startswith('/'):
                    # 过滤掉静态资源
                    if not any(line.endswith(ext) for ext in ['.css', '.png', '.jpg', '.ico', '.svg', '.woff']):
                        endpoints.append(line)
            
            if endpoints:
                return list(set(endpoints))
    except:
        pass
    
    # linkfinder 不可用，使用正则表达式分析
    try:
        default_logger.debug(f"使用正则表达式分析 JS: {js_url}")
        response = requests.get(js_url, timeout=10)
        js_content = response.text
        
        # 常见的 API 路径模式
        patterns = [
            r'["\']/(api/[a-zA-Z0-9/_-]+)["\']',  # /api/...
            r'["\']/(v\d+/[a-zA-Z0-9/_-]+)["\']',  # /v1/...
            r'["\'](/[a-zA-Z0-9/_-]+)["\']',       # 通用路径
            r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',  # endpoint: "..."
            r'url\s*[:=]\s*["\']([^"\']+)["\']',       # url: "..."
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if match.startswith('/') and len(match) > 1:
                    # 过滤静态资源
                    if not any(match.endswith(ext) for ext in ['.css', '.png', '.jpg', '.ico', '.svg', '.woff', '.js']):
                        endpoints.append(match)
        
    except Exception as e:
        default_logger.debug(f"正则分析 JS 失败: {e}")
    
    return list(set(endpoints))  # 去重
