"""
命令执行工具
在Docker容器中执行系统命令（如nmap, sqlmap, curl等）
"""
from typing import Optional
from langchain_core.tools import tool
from src.executor.docker_executor import DockerExecutor


@tool
def execute_command(
    command: str,
    description: Optional[str] = None
) -> str:
    """
    在Docker容器中执行系统命令
    
    用于执行渗透测试工具，如：
    - nmap: 端口扫描
    - sqlmap: SQL注入检测
    - curl: HTTP请求
    - nikto: Web漏洞扫描
    - 其他Kali Linux工具
    
    Args:
        command: 要执行的命令（如 "nmap -p 80,443 target.com"）
        description: 命令描述（可选，用于日志）
    
    Returns:
        命令执行结果
    
    Example:
        execute_command("nmap -p 80,443 target.com")
        execute_command("curl -v http://target.com/api")
    """
    executor = DockerExecutor.get_instance()
    result = executor.execute(command)
    
    # 自动提取页面信息（如果是 HTTP 请求）
    if 'curl' in command.lower() or 'wget' in command.lower():
        try:
            from src.utils.page_info_extractor import extract_page_info_from_output
            extract_page_info_from_output(command, result)
        except Exception as e:
            pass  # 静默失败，不影响主流程
    
    if description:
        from src.utils.logger import log_tool_execution, default_logger
        log_tool_execution(
            default_logger,
            "execute_command",
            f"{description}: {result[:100]}",
            success=True
        )
    
    return result

