# 知识库文档

本目录存放攻击场景知识文档，用于RAG检索增强Agent能力。

## 文档格式

每个Markdown文件代表一个攻击场景或漏洞类型，格式如下：

```markdown
# 漏洞类型名称

## 漏洞描述
...

## 检测方法
1. ...
2. ...

## 利用示例

### 案例1: ...
```python
# Exploit代码
```

### 案例2: ...
...
```

## 文档组织

知识库由两部分组成：

1. **内置基础文档**（目录根部）  
- `SQL注入-攻击库.md`
- `XSS-攻击库.md`
- `SSTI-攻击库.md`

2. **H-Pentest扩展文档**（`hpentest/` 目录）  
   - 从 `agentproject/H-Pentest-main/knowledge/know` 迁移的 50+ 攻击库文档  
   - 覆盖 API/IDOR/SSRF/XXE/反序列化/权限提升 等高级场景  
   - `hpentest/knowledge_metadata.json` 提供每篇文档的标签、难度、摘要，供检索索引使用

> 目录结构示例
```
knowledge/
├── README.md
├── SQL注入-攻击库.md
├── XSS-攻击库.md
├── SSTI-攻击库.md
└── hpentest/
    ├── 00-INDEX.md
    ├── IDOR-攻击库.md
    ├── SSRF-攻击库.md
    ├── OAuth认证绕过-攻击库.md
    └── knowledge_metadata.json
```

## 使用

知识库会在首次运行时自动构建索引，后续会从缓存加载。

- `hpentest/knowledge_metadata.json` 会在索引构建阶段自动解析并注入标签/难度信息  
- 如果新增/修改了知识文档，请删除 `knowledge/cache/` 后重新运行以重建索引

