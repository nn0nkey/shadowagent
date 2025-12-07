"""
日志系统
提供结构化的日志记录功能
"""
import logging
import sys
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path


class ColoredFormatter(logging.Formatter):
    """彩色日志格式化器"""
    
    COLORS = {
        'DEBUG': '\033[36m',      # 青色
        'INFO': '\033[32m',       # 绿色
        'WARNING': '\033[33m',    # 黄色
        'ERROR': '\033[31m',      # 红色
        'CRITICAL': '\033[35m',   # 紫色
    }
    RESET = '\033[0m'
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logger(
    name: str = "myagent",
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    use_color: bool = True
) -> logging.Logger:
    """
    设置日志记录器
    
    Args:
        name: 日志记录器名称
        level: 日志级别
        log_file: 日志文件路径（可选）
        use_color: 是否使用彩色输出
    
    Returns:
        配置好的Logger实例
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # 避免重复添加handler
    if logger.handlers:
        return logger
    
    # 控制台handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    if use_color:
        formatter = ColoredFormatter(
            '%(asctime)s | %(levelname)s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 文件handler（如果指定）
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def log_agent_thought(
    logger: logging.Logger,
    message: str,
    extra: Optional[Dict[str, Any]] = None
):
    """
    记录Agent思考过程
    
    Args:
        logger: Logger实例
        message: 消息内容
        extra: 额外信息
    """
    if extra:
        logger.info(f"🤔 {message}", extra=extra)
    else:
        logger.info(f"🤔 {message}")


def log_tool_execution(
    logger: logging.Logger,
    tool_name: str,
    result: str,
    success: bool = True
):
    """
    记录工具执行结果
    
    Args:
        logger: Logger实例
        tool_name: 工具名称
        result: 执行结果
        success: 是否成功
    """
    emoji = "✅" if success else "❌"
    logger.info(f"{emoji} [{tool_name}] {result[:200]}...")


def log_flag_found(
    logger: logging.Logger,
    flag: str
):
    """
    记录FLAG发现
    
    Args:
        logger: Logger实例
        flag: 发现的FLAG
    """
    logger.info(f"🏆 FLAG发现: {flag}")


# 默认logger实例
default_logger = setup_logger()

