"""
FLAG提交工具
用于提交找到的FLAG到XBOW基准测试系统
"""
import os
from typing import Optional
from langchain_core.tools import tool
from src.utils.logger import default_logger, log_flag_found


@tool
def submit_flag(
    flag: str,
    challenge_id: Optional[str] = None
) -> str:
    """
    本地验证FLAG是否与期望值一致
    
    FLAG格式通常为：flag{...} 或 FLAG{...}
    
    Args:
        flag: 找到的FLAG字符串
        challenge_id: (保留参数以兼容旧逻辑，目前未使用)
    
    Returns:
        验证结果（成功/失败信息）
    
    Example:
        submit_flag("flag{abc123}")
    """
    # 验证FLAG格式
    if not (flag.startswith("flag{") or flag.startswith("FLAG{")):
        return f"❌ FLAG格式错误: {flag}，应为 flag{{...}} 或 FLAG{{...}}"
    expected_flag = os.getenv("EXPECTED_FLAG_VALUE")
    expected_flag_file = os.getenv("EXPECTED_FLAG_FILE")
    
    if not expected_flag and expected_flag_file:
        try:
            with open(expected_flag_file, "r", encoding="utf-8") as f:
                expected_flag = f.read().strip()
        except OSError as e:
            return f"❌ 无法读取 EXPECTED_FLAG_FILE: {e}"
    
    if not expected_flag:
        return (
            "⚠️ 未配置 EXPECTED_FLAG_VALUE（或 EXPECTED_FLAG_FILE），"
            "当前环境仅做本地验证，请在 .env 中设置期望的FLAG值。"
        )
    
    if flag.strip() == expected_flag.strip():
        log_flag_found(default_logger, flag)
        return "✅ FLAG验证通过，本地期望值匹配。"
    
    return (
        "❌ FLAG验证失败：与期望值不一致。"
        "请重新确认或继续攻击流程。"
    )


def extract_flag_from_text(text: str) -> list[str]:
    """
    从文本中提取所有可能的FLAG
    
    支持嵌套格式如 FLAG{flag{xxx}}
    
    Args:
        text: 要搜索的文本
    
    Returns:
        FLAG列表
    """
    import re
    
    # FLAG格式：flag{...} 或 FLAG{...}，支持嵌套 {}
    # 使用贪婪匹配 + 后向查找来处理嵌套
    patterns = [
        r'[Ff][Ll][Aa][Gg]\{[^}]*\{[^}]+\}[^}]*\}',  # 嵌套格式: FLAG{flag{xxx}}
        r'[Ff][Ll][Aa][Gg]\{[^{}]+\}',  # 简单格式: flag{xxx}
    ]
    
    flags = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        flags.extend(matches)
    
    # 去重
    unique_flags = []
    seen = set()
    for flag in flags:
        if flag.lower() not in seen:
            seen.add(flag.lower())
            unique_flags.append(flag)
    
    return unique_flags


def verify_flag(flag: str) -> bool:
    """
    验证 FLAG 是否与配置文件中的期望值一致
    
    Args:
        flag: 要验证的 FLAG
    
    Returns:
        True 如果验证通过，False 否则
    """
    expected_flag = os.getenv("EXPECTED_FLAG_VALUE")
    expected_flag_file = os.getenv("EXPECTED_FLAG_FILE")
    
    # 从文件读取期望值
    if not expected_flag and expected_flag_file:
        try:
            with open(expected_flag_file, "r", encoding="utf-8") as f:
                expected_flag = f.read().strip()
        except OSError:
            return False
    
    if not expected_flag:
        # 未配置期望值，无法验证
        return False
    
    # 规范化比较（忽略大小写和空白）
    return flag.strip().lower() == expected_flag.strip().lower()


def extract_and_verify_flag(text: str) -> Optional[str]:
    """
    从文本中提取并验证 FLAG
    
    只返回验证通过的 FLAG，防止幻觉
    
    Args:
        text: 要搜索的文本
    
    Returns:
        验证通过的 FLAG，或 None
    """
    flags = extract_flag_from_text(text)
    
    for flag in flags:
        if verify_flag(flag):
            return flag
    
    return None

