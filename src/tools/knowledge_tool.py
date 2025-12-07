"""
知识库检索工具（按需加载）
Agent可以主动调用此工具检索相关知识，避免一次性加载所有内容
"""
from typing import Optional
from langchain_core.tools import tool

from src.utils.knowledge_base import get_knowledge_base
from src.utils.logger import default_logger


@tool
def search_knowledge(
    query: str,
    vulnerability_type: Optional[str] = None,
    top_k: int = 3
) -> str:
    """
    按需检索知识库中的攻击场景知识（RAG检索）
    
    使用场景：
    - 当遇到不熟悉的漏洞类型时
    - 需要参考攻击场景时
    - 需要了解特定漏洞的利用方法时
    
    注意：此工具按需调用，不会自动加载所有知识，避免占用上下文。
    
    Args:
        query: 查询文本（如"SQL注入"、"XSS攻击"、"文件包含"等）
        vulnerability_type: 漏洞类型过滤（可选，如"SQL注入"、"XSS"等）
        top_k: 返回前K个最相关的结果（默认3个）
    
    Returns:
        相关知识内容（格式化文本）
    """
    try:
        kb = get_knowledge_base()
        if not kb.enabled:
            return "知识库功能不可用，请安装 faiss-cpu 和 sentence-transformers"
        
        # 执行搜索
        results = kb.search(
            query=query,
            top_k=top_k,
            vulnerability_type=vulnerability_type
        )
        
        if not results:
            return f"未找到与 '{query}' 相关的知识"
        
        # 格式化结果
        formatted = kb.format_search_results(
            query=query,
            results=results,
            max_length=2000  # 限制输出长度，避免占用过多上下文
        )
        
        default_logger.info(f"[知识库] 检索: {query}, 返回 {len(results)} 条结果")
        
        return formatted
    except Exception as e:
        default_logger.error(f"知识库检索失败: {e}")
        return f"检索失败: {str(e)}"

