"""
Python代码执行工具
在Docker容器中执行Python PoC代码
"""
from typing import Optional
from langchain_core.tools import tool
from src.executor.docker_executor import DockerExecutor


@tool
def execute_python_poc(
    code: str,
    description: Optional[str] = None
) -> str:
    """
    在Docker容器中执行Python代码
    
    用于执行复杂的渗透测试逻辑，如：
    - HTTP请求和会话管理
    - 多步骤攻击链
    - 数据处理和解析
    - 自定义漏洞利用
    
    Args:
        code: Python代码字符串
        description: 代码描述（可选，用于日志）
    
    Returns:
        代码执行结果（print输出或返回值）
    
    Example:
        execute_python_poc('''
        import requests
        response = requests.get("http://target.com")
        print(response.text)
        ''')
    """
    executor = DockerExecutor.get_instance()
    
    # 直接执行用户代码，不做额外包装（保持简洁）
    # LLM 生成的代码应该是完整可执行的
    result = executor.execute_python(code)
    
    
    if description:
        from src.utils.logger import log_tool_execution, default_logger
        log_tool_execution(
            default_logger,
            "execute_python_poc",
            f"{description}: {result[:100]}",
            success=True
        )
    
    return result

