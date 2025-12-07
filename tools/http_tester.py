#!/usr/bin/env python3
"""
HTTP 请求测试工具
用法:
    python http_tester.py -g "id=1&name=test"           # GET 请求
    python http_tester.py -p "username=admin&pass=123"  # POST 请求
    python http_tester.py -g "id=1" -p "data=test"      # 同时传 GET 和 POST
    python http_tester.py -u "http://other.com" -g "x=1" # 指定其他URL
"""

import argparse
import requests
from urllib.parse import urlencode, parse_qs
import sys
import json

# 默认目标
DEFAULT_URL = "http://ja-nids.jd.com:2000/"


def parse_params(param_str: str) -> dict:
    """解析参数字符串为字典"""
    if not param_str:
        return {}
    
    params = {}
    # 支持 key=value&key2=value2 格式
    for pair in param_str.split('&'):
        if '=' in pair:
            key, value = pair.split('=', 1)
            params[key.strip()] = value.strip()
        else:
            params[pair.strip()] = ''
    return params


def send_request(url: str, get_params: dict = None, post_params: dict = None, 
                 headers: dict = None, cookies: dict = None, verbose: bool = True):
    """发送 HTTP 请求"""
    
    # 构建完整 URL
    if get_params:
        separator = '&' if '?' in url else '?'
        url = url + separator + urlencode(get_params)
    
    # 默认 headers
    default_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
    }
    if headers:
        default_headers.update(headers)
    
    try:
        if post_params:
            # POST 请求
            default_headers['Content-Type'] = 'application/x-www-form-urlencoded'
            response = requests.post(url, data=post_params, headers=default_headers, 
                                    cookies=cookies, timeout=10, allow_redirects=True)
            method = 'POST'
        else:
            # GET 请求
            response = requests.get(url, headers=default_headers, cookies=cookies, 
                                   timeout=10, allow_redirects=True)
            method = 'GET'
        
        if verbose:
            print("=" * 60)
            print(f"📤 请求信息")
            print("=" * 60)
            print(f"方法: {method}")
            print(f"URL: {url}")
            if get_params:
                print(f"GET参数: {get_params}")
            if post_params:
                print(f"POST参数: {post_params}")
            
            print("\n" + "=" * 60)
            print(f"📥 响应信息")
            print("=" * 60)
            print(f"状态码: {response.status_code}")
            print(f"响应长度: {len(response.text)} bytes")
            print(f"Content-Type: {response.headers.get('Content-Type', 'N/A')}")
            
            # 显示响应头
            print(f"\n响应头:")
            for key, value in list(response.headers.items())[:10]:
                print(f"  {key}: {value}")
            
            # 显示响应内容
            print(f"\n响应内容:")
            print("-" * 60)
            content = response.text
            if len(content) > 2000:
                print(content[:2000])
                print(f"\n... [截断，共 {len(content)} 字符]")
            else:
                print(content)
            print("-" * 60)
            
            # 尝试检测 FLAG
            import re
            flags = re.findall(r'(?:flag|FLAG|Flag)\{[^}]+\}', content)
            if flags:
                print(f"\n🎯 发现 FLAG: {flags}")
        
        return response
        
    except requests.exceptions.RequestException as e:
        print(f"❌ 请求失败: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description='HTTP 请求测试工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s -g "id=1&name=test"                        # GET 请求(默认URL)
  %(prog)s -p "user=admin&pass=123"                   # POST 请求
  %(prog)s http://target.com -g "id=1"                # 指定URL + GET
  %(prog)s http://target.com -p "data=test"           # 指定URL + POST
  %(prog)s http://target.com -g "id=1" -p "x=1"       # GET + POST
  %(prog)s http://target.com -j '{"key": "value"}'    # POST JSON
        """
    )
    
    parser.add_argument('url', nargs='?', default=DEFAULT_URL,
                        help=f'目标URL (默认: {DEFAULT_URL})')
    parser.add_argument('-g', '--get', default='',
                        help='GET参数 (格式: key=value&key2=value2)')
    parser.add_argument('-p', '--post', default='',
                        help='POST参数 (格式: key=value&key2=value2)')
    parser.add_argument('-j', '--json', default='',
                        help='POST JSON数据')
    parser.add_argument('-H', '--header', action='append', default=[],
                        help='自定义Header (格式: "Key: Value")')
    parser.add_argument('-c', '--cookie', default='',
                        help='Cookie (格式: key=value; key2=value2)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='静默模式，只输出响应内容')
    
    args = parser.parse_args()
    
    # 解析参数
    get_params = parse_params(args.get)
    post_params = parse_params(args.post)
    
    # 解析 headers
    headers = {}
    for h in args.header:
        if ':' in h:
            key, value = h.split(':', 1)
            headers[key.strip()] = value.strip()
    
    # 解析 cookies
    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(';'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                cookies[key.strip()] = value.strip()
    
    # JSON 模式
    if args.json:
        try:
            json_data = json.loads(args.json)
            headers['Content-Type'] = 'application/json'
            response = requests.post(args.url, json=json_data, headers=headers, 
                                    cookies=cookies, timeout=10)
            if args.quiet:
                print(response.text)
            else:
                print(f"状态码: {response.status_code}")
                print(f"响应: {response.text}")
            return
        except json.JSONDecodeError as e:
            print(f"❌ JSON 解析错误: {e}")
            sys.exit(1)
    
    # 发送请求
    send_request(
        url=args.url,
        get_params=get_params if get_params else None,
        post_params=post_params if post_params else None,
        headers=headers if headers else None,
        cookies=cookies if cookies else None,
        verbose=not args.quiet
    )


if __name__ == '__main__':
    main()
