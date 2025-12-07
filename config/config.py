"""
配置管理
统一管理所有配置项
"""
import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# 加载环境变量
env_file = Path(__file__).parent.parent / ".env"
if env_file.exists():
    load_dotenv(env_file)


class Config:
    """配置类"""
    
    # LLM配置
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai")
    LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o")
    LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.7"))
    LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "4096"))
    
    # 顾问LLM配置
    ADVISOR_LLM_PROVIDER = os.getenv("ADVISOR_LLM_PROVIDER", LLM_PROVIDER)
    ADVISOR_LLM_MODEL = os.getenv("ADVISOR_LLM_MODEL", LLM_MODEL)
    
    # Docker配置
    DOCKER_CONTAINER_NAME = os.getenv("DOCKER_CONTAINER_NAME", "shadowagent-kali")
    DOCKER_IMAGE = os.getenv("DOCKER_IMAGE", "h-pentest/kali:latest")
    
    # XBOW配置
    XBOW_BASE_URL = os.getenv("XBOW_BASE_URL", "http://localhost:8080")
    XBOW_API_KEY = os.getenv("XBOW_API_KEY", "")
    
    # Agent配置
    MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", "50"))
    ADVISOR_FAILURE_THRESHOLD = int(os.getenv("ADVISOR_FAILURE_THRESHOLD", "3"))
    ADVISOR_CONSULTATION_INTERVAL = int(os.getenv("ADVISOR_CONSULTATION_INTERVAL", "5"))
    MAX_HISTORY_MESSAGES = int(os.getenv("MAX_HISTORY_MESSAGES", "20"))
    ENABLE_SMART_ROUTING = os.getenv("ENABLE_SMART_ROUTING", "true").lower() == "true"
    
    # 元认知配置
    ENABLE_METACOGNITION = os.getenv("ENABLE_METACOGNITION", "true").lower() == "true"
    USE_LLM_METACOGNITION = os.getenv("USE_LLM_METACOGNITION", "false").lower() == "true"  # 使用LLM进行深度评估
    
    # 日志配置
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = os.getenv("LOG_FILE", None)
    
    @classmethod
    def get_llm_config(cls) -> dict:
        """获取LLM配置"""
        return {
            "provider": cls.LLM_PROVIDER,
            "model": cls.LLM_MODEL,
            "temperature": cls.LLM_TEMPERATURE,
            "max_tokens": cls.LLM_MAX_TOKENS
        }
    
    @classmethod
    def get_advisor_llm_config(cls) -> dict:
        """获取顾问LLM配置"""
        return {
            "provider": cls.ADVISOR_LLM_PROVIDER,
            "model": cls.ADVISOR_LLM_MODEL,
            "temperature": cls.LLM_TEMPERATURE + 0.1,  # 顾问可以更有创造性
            "max_tokens": cls.LLM_MAX_TOKENS
        }

