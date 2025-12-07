"""
记忆存储工具（参考Cyber-AutoAgent）
供Agent使用的记忆存储工具
"""
from typing import Optional, Dict, Any, List
from langchain_core.tools import tool

from src.utils.memory_store import get_memory_store
from src.utils.logger import default_logger


@tool
def store_memory(
    content: str,
    category: str = "general",
    metadata: Optional[Dict[str, Any]] = None
) -> str:
    """
    存储记忆
    
    支持的类别：
    - finding: 安全发现
    - plan: 计划
    - reflection: 反思
    - vulnerability: 漏洞
    - exploit: 利用
    - reconnaissance: 侦察
    
    Args:
        content: 记忆内容
        category: 类别
        metadata: 元数据（如severity, confidence等）
    
    Returns:
        记忆ID
    """
    try:
        memory_store = get_memory_store()
        if not memory_store.enabled:
            return "记忆存储功能不可用"
        
        memory_id = memory_store.store(
            content=content,
            category=category,
            metadata=metadata or {}
        )
        
        return f"记忆已存储，ID: {memory_id}"
    except Exception as e:
        default_logger.error(f"存储记忆失败: {e}")
        return f"存储失败: {str(e)}"


@tool
def store_finding(
    title: str,
    severity: str,
    description: str,
    evidence: str = "",
    validation_status: str = "hypothesis",
    artifacts: Optional[List[str]] = None,
    rationale: str = "",
    location: str = "",
    impact: str = "",
    remediation: str = "",
    confidence: int = 50,
    steps: str = ""
) -> str:
    """
    存储安全发现（参考Cyber-AutoAgent Proof Pack格式）
    
    **重要**: HIGH/CRITICAL发现必须包含Proof Pack（artifacts + rationale）
    
    Args:
        title: 发现标题（如"SQL注入 - jobs参数"）
        severity: 严重程度（CRITICAL/HIGH/MEDIUM/LOW/INFO）
        description: 详细描述
        evidence: 证据（响应内容、截图等）
        validation_status: 验证状态（verified=已验证, hypothesis=假设）
        artifacts: 证据文件路径列表（如["evidence/sqli.txt"]）
        rationale: 理由（一行说明为什么这是漏洞）
        location: 位置（如/graphql/）
        impact: 影响描述
        remediation: 修复建议
        confidence: 置信度（0-100）
        steps: 复现步骤
    
    Returns:
        记忆ID
    
    示例:
        store_finding(
            title="SQL注入 - jobs参数",
            severity="HIGH",
            description="GraphQL jobs查询的jobType参数存在SQL注入",
            evidence="响应包含所有用户数据，包括private类型",
            validation_status="verified",
            artifacts=["evidence/sqli_response.txt"],
            rationale="注入 ' OR 1=1-- 后返回了隐藏的FLAG",
            location="/graphql/",
            impact="可读取所有数据库内容",
            confidence=95
        )
    """
    try:
        memory_store = get_memory_store()
        
        # 同时添加到报告生成器
        try:
            from src.utils.report_generator import get_report_generator, Finding
            report_gen = get_report_generator()
            finding = Finding(
                title=title,
                severity=severity.upper(),
                description=description,
                evidence=evidence,
                validation_status=validation_status,
                artifacts=artifacts or [],
                rationale=rationale,
                location=location,
                impact=impact,
                remediation=remediation,
                confidence=confidence
            )
            report_gen.add_finding(finding)
        except Exception as e:
            default_logger.warning(f"添加到报告生成器失败: {e}")
        
        if not memory_store.enabled:
            return f"发现已记录到报告（记忆存储不可用）: {title}"
        
        # 构建Proof Pack格式的内容
        content_parts = [
            f"[FINDING] {title}",
            f"[SEVERITY] {severity.upper()}",
            f"[STATUS] {validation_status}",
            f"[CONFIDENCE] {confidence}%",
            f"[LOCATION] {location}" if location else "",
            f"[DESCRIPTION] {description}",
            f"[IMPACT] {impact}" if impact else "",
            f"[EVIDENCE] {evidence}" if evidence else "",
            f"[ARTIFACTS] {', '.join(artifacts or [])}" if artifacts else "",
            f"[RATIONALE] {rationale}" if rationale else "",
            f"[STEPS] {steps}" if steps else "",
            f"[REMEDIATION] {remediation}" if remediation else "",
        ]
        content = "\n".join(p for p in content_parts if p)
        
        memory_id = memory_store.store(
            content=content,
            category="finding",
            metadata={
                "title": title,
                "severity": severity.upper(),
                "validation_status": validation_status,
                "confidence": confidence,
                "artifacts": artifacts or [],
                "rationale": rationale
            }
        )
        
        return f"安全发现已存储（Proof Pack格式），ID: {memory_id}"
    except Exception as e:
        default_logger.error(f"存储发现失败: {e}")
        return f"存储失败: {str(e)}"


@tool
def store_plan(
    objective: str,
    current_phase: int = 1,
    total_phases: int = 1,
    phases: Optional[List[Dict[str, Any]]] = None
) -> str:
    """
    存储计划（参考Cyber-AutoAgent格式）
    
    Args:
        objective: 目标
        current_phase: 当前阶段（从1开始）
        total_phases: 总阶段数
        phases: 阶段列表，每个阶段包含：
            - id: 阶段ID
            - title: 阶段标题
            - status: 状态（active/pending/done/partial_failure/blocked）
            - criteria: 完成标准
    
    Returns:
        记忆ID
    """
    try:
        memory_store = get_memory_store()
        if not memory_store.enabled:
            return "记忆存储功能不可用"
        
        memory_id = memory_store.store_plan(
            objective=objective,
            current_phase=current_phase,
            total_phases=total_phases,
            phases=phases or []
        )
        
        return f"计划已存储，ID: {memory_id}"
    except Exception as e:
        default_logger.error(f"存储计划失败: {e}")
        return f"存储失败: {str(e)}"


@tool
def get_plan() -> str:
    """
    获取最新计划
    
    Returns:
        计划内容（JSON格式）
    """
    try:
        memory_store = get_memory_store()
        if not memory_store.enabled:
            return "记忆存储功能不可用"
        
        plan = memory_store.get_plan()
        if not plan:
            return "未找到计划"
        
        import json
        return json.dumps(plan, ensure_ascii=False, indent=2)
    except Exception as e:
        default_logger.error(f"获取计划失败: {e}")
        return f"获取失败: {str(e)}"


@tool
def retrieve_memories(
    query: str,
    category: Optional[str] = None,
    limit: int = 5
) -> str:
    """
    语义搜索记忆（参考Cyber-AutoAgent）
    
    Args:
        query: 查询文本
        category: 类别过滤（可选）
        limit: 返回数量
    
    Returns:
        相关记忆列表（格式化文本）
    """
    try:
        memory_store = get_memory_store()
        if not memory_store.enabled:
            return "记忆存储功能不可用"
        
        results = memory_store.retrieve(
            query=query,
            category=category,
            limit=limit
        )
        
        if not results:
            return "未找到相关记忆"
        
        # 格式化输出
        formatted_parts = [f"## 📝 相关记忆（查询: {query}）\n"]
        
        for i, result in enumerate(results, 1):
            memory_id = result.get("id", "unknown")
            category = result.get("category", "unknown")
            content = result.get("content", "")
            score = result.get("similarity_score", 0)
            created_at = result.get("created_at", "")
            
            # 截断内容
            if len(content) > 300:
                content = content[:300] + "..."
            
            formatted_parts.append(
                f"### {i}. [{category}] {memory_id} (相似度: {score:.2f})\n"
                f"时间: {created_at}\n"
                f"内容: {content}\n"
            )
        
        return "\n".join(formatted_parts)
    except Exception as e:
        default_logger.error(f"搜索记忆失败: {e}")
        return f"搜索失败: {str(e)}"


@tool
def list_memories(
    category: Optional[str] = None,
    limit: int = 10
) -> str:
    """
    列出记忆
    
    Args:
        category: 类别过滤（可选）
        limit: 限制数量
    
    Returns:
        记忆列表（格式化文本）
    """
    try:
        memory_store = get_memory_store()
        if not memory_store.enabled:
            return "记忆存储功能不可用"
        
        memories = memory_store.list_memories(
            category=category,
            limit=limit
        )
        
        if not memories:
            return "未找到记忆"
        
        # 格式化输出
        formatted_parts = [f"## 📋 记忆列表\n"]
        
        for i, memory in enumerate(memories, 1):
            memory_id = memory.get("id", "unknown")
            category = memory.get("category", "unknown")
            content = memory.get("content", "")
            created_at = memory.get("created_at", "")
            
            # 截断内容
            if len(content) > 200:
                content = content[:200] + "..."
            
            formatted_parts.append(
                f"### {i}. [{category}] {memory_id}\n"
                f"时间: {created_at}\n"
                f"内容: {content}\n"
            )
        
        return "\n".join(formatted_parts)
    except Exception as e:
        default_logger.error(f"列出记忆失败: {e}")
        return f"列出失败: {str(e)}"

