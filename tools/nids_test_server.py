#!/usr/bin/env python3
"""
NIDS/HIDS 测试服务器
用于测试安全设备的防护能力

⚠️ 警告：此服务器仅用于安全测试环境，包含危险功能！
"""

from flask import Flask, request, jsonify
import subprocess
import os

app = Flask(__name__)


@app.route('/')
def home():
    return """
    <h1>NIDS Test Server</h1>
    <p>用于测试安全设备防护能力</p>
    <h3>可用端点：</h3>
    <ul>
        <li><b>GET /cmd?c=命令</b> - 执行系统命令 (GET方式)</li>
        <li><b>POST /cmd</b> - 执行系统命令 (POST方式, 参数: cmd)</li>
        <li><b>GET /exec?command=命令</b> - 执行系统命令 (另一种参数名)</li>
        <li><b>POST /shell</b> - 执行系统命令 (参数: shell)</li>
        <li><b>GET /ping?ip=地址</b> - Ping测试 (可能存在命令注入)</li>
        <li><b>POST /eval</b> - Python代码执行 (参数: code)</li>
        <li><b>GET /file?path=路径</b> - 读取文件</li>
        <li><b>GET /sqli?id=值</b> - SQL注入测试点</li>
        <li><b>GET /xss?name=值</b> - XSS测试点</li>
        <li><b>GET /ssrf?url=地址</b> - SSRF测试点</li>
    </ul>
    """


# ==================== 命令执行端点 ====================

@app.route('/cmd', methods=['GET', 'POST'])
def cmd():
    """命令执行 - GET: ?c=命令, POST: cmd=命令"""
    if request.method == 'GET':
        command = request.args.get('c', '')
    else:
        command = request.form.get('cmd', '') or request.form.get('c', '')
    
    if not command:
        return jsonify({"error": "Missing parameter: c (GET) or cmd (POST)", "example": "/cmd?c=whoami"})
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        return jsonify({
            "command": command,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timeout", "command": command})
    except Exception as e:
        return jsonify({"error": str(e), "command": command})


@app.route('/exec', methods=['GET', 'POST'])
def exec_cmd():
    """命令执行 - 参数: command"""
    if request.method == 'GET':
        command = request.args.get('command', '') or request.args.get('cmd', '')
    else:
        command = request.form.get('command', '') or request.form.get('cmd', '')
    
    if not command:
        return jsonify({"error": "Missing parameter: command", "example": "/exec?command=id"})
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        return f"<pre>{result.stdout}{result.stderr}</pre>"
    except Exception as e:
        return f"<pre>Error: {e}</pre>"


@app.route('/shell', methods=['GET', 'POST'])
def shell():
    """命令执行 - 参数: shell"""
    if request.method == 'GET':
        command = request.args.get('shell', '')
    else:
        command = request.form.get('shell', '')
    
    if not command:
        return "Missing parameter: shell\nExample: /shell?shell=ls -la"
    
    try:
        output = os.popen(command).read()
        return f"$ {command}\n\n{output}"
    except Exception as e:
        return f"Error: {e}"


# ==================== 命令注入测试 ====================

@app.route('/ping', methods=['GET', 'POST'])
def ping():
    """Ping测试 - 存在命令注入漏洞"""
    if request.method == 'GET':
        ip = request.args.get('ip', '')
    else:
        ip = request.form.get('ip', '')
    
    if not ip:
        return jsonify({"error": "Missing parameter: ip", "example": "/ping?ip=127.0.0.1"})
    
    # 故意不过滤，存在命令注入
    command = f"ping -c 2 {ip}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        return jsonify({
            "command": command,
            "output": result.stdout + result.stderr
        })
    except Exception as e:
        return jsonify({"error": str(e)})


# ==================== 代码执行 ====================

@app.route('/eval', methods=['GET', 'POST'])
def eval_code():
    """Python代码执行"""
    if request.method == 'GET':
        code = request.args.get('code', '')
    else:
        code = request.form.get('code', '')
    
    if not code:
        return jsonify({"error": "Missing parameter: code", "example": "/eval?code=__import__('os').popen('id').read()"})
    
    try:
        result = eval(code)
        return jsonify({"code": code, "result": str(result)})
    except Exception as e:
        return jsonify({"code": code, "error": str(e)})


# ==================== 文件读取 ====================

@app.route('/file', methods=['GET', 'POST'])
def read_file():
    """文件读取 - 存在路径遍历漏洞"""
    if request.method == 'GET':
        path = request.args.get('path', '') or request.args.get('file', '')
    else:
        path = request.form.get('path', '') or request.form.get('file', '')
    
    if not path:
        return jsonify({"error": "Missing parameter: path", "example": "/file?path=/etc/passwd"})
    
    try:
        with open(path, 'r') as f:
            content = f.read()
        return jsonify({"path": path, "content": content})
    except Exception as e:
        return jsonify({"path": path, "error": str(e)})


# ==================== SQL注入测试 ====================

@app.route('/sqli', methods=['GET', 'POST'])
def sqli():
    """SQL注入测试点（模拟）"""
    if request.method == 'GET':
        user_id = request.args.get('id', '')
    else:
        user_id = request.form.get('id', '')
    
    if not user_id:
        return jsonify({"error": "Missing parameter: id", "example": "/sqli?id=1"})
    
    # 模拟SQL查询（实际不执行）
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return jsonify({
        "query": query,
        "note": "This is a simulated SQL injection test point",
        "input": user_id
    })


# ==================== XSS测试 ====================

@app.route('/xss', methods=['GET', 'POST'])
def xss():
    """XSS测试点"""
    if request.method == 'GET':
        name = request.args.get('name', '')
    else:
        name = request.form.get('name', '')
    
    if not name:
        return "<p>Missing parameter: name</p><p>Example: /xss?name=<script>alert(1)</script></p>"
    
    # 故意不转义，存在XSS
    return f"<h1>Hello, {name}!</h1>"


# ==================== SSRF测试 ====================

@app.route('/ssrf', methods=['GET', 'POST'])
def ssrf():
    """SSRF测试点"""
    import urllib.request
    
    if request.method == 'GET':
        url = request.args.get('url', '')
    else:
        url = request.form.get('url', '')
    
    if not url:
        return jsonify({"error": "Missing parameter: url", "example": "/ssrf?url=http://127.0.0.1:22"})
    
    try:
        response = urllib.request.urlopen(url, timeout=5)
        content = response.read().decode('utf-8', errors='ignore')[:1000]
        return jsonify({"url": url, "status": response.status, "content": content})
    except Exception as e:
        return jsonify({"url": url, "error": str(e)})


# ==================== 通用回显 ====================

@app.route('/echo', methods=['GET', 'POST'])
def echo():
    """回显所有参数"""
    return jsonify({
        "method": request.method,
        "args": dict(request.args),
        "form": dict(request.form),
        "headers": dict(request.headers),
        "url": request.url
    })


if __name__ == '__main__':
    print("""
    ⚠️  NIDS/HIDS 测试服务器
    ⚠️  仅用于安全测试环境！
    
    可用端点:
    - /cmd?c=命令        命令执行(GET)
    - /cmd POST cmd=命令 命令执行(POST)
    - /exec?command=命令 命令执行
    - /shell?shell=命令  命令执行
    - /ping?ip=地址      命令注入测试
    - /eval?code=代码    Python代码执行
    - /file?path=路径    文件读取
    - /sqli?id=值        SQL注入测试
    - /xss?name=值       XSS测试
    - /ssrf?url=地址     SSRF测试
    """)
    app.run(host='0.0.0.0', port=2000, debug=True)
