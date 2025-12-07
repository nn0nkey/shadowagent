"""
LLM客户端封装
支持多种LLM提供商
"""
import os
from typing import Optional, List, Dict, Any
from langchain_core.language_models import BaseChatModel
from langchain_openai import ChatOpenAI
from langchain_community.chat_models import ChatTongyi, QianfanChatEndpoint


class LLMClient:
    """
    LLM客户端统一接口
    
    支持的提供商：
    - OpenAI (GPT-4, GPT-3.5)
    - DeepSeek
    - Qwen (通义千问)
    - 百度文心一言
    """
    
    def __init__(
        self,
        provider: str = "openai",
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        timeout: int = 120
    ):
        """
        初始化LLM客户端
        
        Args:
            provider: 提供商名称 (openai, deepseek, qwen, baidu)
            model: 模型名称
            api_key: API密钥
            base_url: API基础URL（可选）
            temperature: 温度参数
            max_tokens: 最大token数
            timeout: 超时时间（秒）
        """
        self.provider = provider.lower()
        self.model = model or self._get_default_model()
        self.api_key = api_key or self._get_api_key()
        self.base_url = base_url
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        
        self.llm = self._create_llm()
    
    def _get_default_model(self) -> str:
        """获取默认模型"""
        defaults = {
            "openai": "gpt-4o",
            "deepseek": "deepseek-chat",
            "qwen": "qwen-turbo",
            "baidu": "ernie-4.0-8k",
            # Kimi / Moonshot 默认模型
            "kimi": "kimi-k2-turbo-preview",
            # x-aio 默认模型
            "xaio": "gpt-4o",
        }
        return defaults.get(self.provider, "gpt-4o")
    
    def _get_api_key(self) -> str:
        """从环境变量获取API密钥"""
        env_map = {
            "openai": "OPENAI_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY",
            "qwen": "DASHSCOPE_API_KEY",
            "baidu": "QIANFAN_API_KEY",
            # Kimi / Moonshot 使用官方示例中的环境变量名
            "kimi": "MOONSHOT_API_KEY",
            # x-aio API
            "xaio": "XAIO_API_KEY",
        }
        env_key = env_map.get(self.provider, "OPENAI_API_KEY")
        api_key = os.getenv(env_key)
        if not api_key:
            raise ValueError(f"未找到环境变量 {env_key}，请设置API密钥")
        return api_key
    
    def _create_llm(self) -> BaseChatModel:
        """创建LLM实例"""
        common_params = {
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout,
        }
        
        if self.provider == "openai":
            # 支持通过环境变量自定义 OpenAI Base URL（例如第三方兼容服务）
            base_url = self.base_url or os.getenv("OPENAI_API_BASE")
            return ChatOpenAI(
                model_name=self.model,
                openai_api_key=self.api_key,
                openai_api_base=base_url,
                **common_params
            )
        
        elif self.provider == "deepseek":
            # DeepSeek 使用 OpenAI 兼容接口
            base_url = self.base_url or os.getenv("DEEPSEEK_API_BASE") or "https://api.deepseek.com/v1"
            return ChatOpenAI(
                model_name=self.model,
                openai_api_key=self.api_key,
                openai_api_base=base_url,
                **common_params
            )
        
        elif self.provider == "qwen":
            return ChatTongyi(
                model=self.model,
                dashscope_api_key=self.api_key,
                **common_params
            )
        
        elif self.provider == "baidu":
            return QianfanChatEndpoint(
                model=self.model,
                api_key=os.getenv("QIANFAN_AK"),
                secret_key=os.getenv("QIANFAN_SK"),
                **common_params
            )

        elif self.provider == "kimi":
            """
            Kimi / Moonshot 官方为 OpenAI 兼容接口：
            - 使用 MOONSHOT_API_KEY 作为 api_key
            - 使用 https://api.moonshot.cn/v1 作为 base_url（可通过环境变量覆盖）
            """
            base_url = self.base_url or os.getenv("MOONSHOT_API_BASE", "https://api.moonshot.cn/v1")
            return ChatOpenAI(
                model_name=self.model,
                openai_api_key=self.api_key,
                openai_api_base=base_url,
                **common_params
            )
        
        elif self.provider == "xaio":
            """
            x-aio API（OpenAI 兼容接口）：
            - 使用 XAIO_API_KEY 作为 api_key
            - 使用 https://api.x-aio.com/v1 作为 base_url
            """
            base_url = self.base_url or os.getenv("XAIO_API_BASE", "https://api.x-aio.com/v1")
            return ChatOpenAI(
                model_name=self.model,
                openai_api_key=self.api_key,
                openai_api_base=base_url,
                **common_params
            )
        
        else:
            raise ValueError(f"不支持的提供商: {self.provider}")
    
    def get_llm(self) -> BaseChatModel:
        """获取LLM实例"""
        return self.llm
    
    def invoke(self, messages: List[Dict[str, str]]) -> str:
        """
        调用LLM（同步）
        
        Args:
            messages: 消息列表
        
        Returns:
            LLM响应内容
        """
        from langchain_core.messages import HumanMessage, SystemMessage
        
        langchain_messages = []
        for msg in messages:
            role = msg.get("role") if isinstance(msg, dict) else None
            content = msg.get("content", "") if isinstance(msg, dict) else ""
            
            if not role or not content:
                continue
                
            if role == "system":
                langchain_messages.append(SystemMessage(content=str(content)))
            else:
                langchain_messages.append(HumanMessage(content=str(content)))
        
        if not langchain_messages:
            return "无有效消息"
        
        response = self.llm.invoke(langchain_messages)
        return response.content
    
    async def ainvoke(self, messages: List[Dict[str, str]]) -> str:
        """
        调用LLM（异步）
        
        Args:
            messages: 消息列表
        
        Returns:
            LLM响应内容
        """
        from langchain_core.messages import HumanMessage, SystemMessage
        from src.utils.observability import get_tracker
        
        langchain_messages = []
        for msg in messages:
            role = msg.get("role") if isinstance(msg, dict) else None
            content = msg.get("content", "") if isinstance(msg, dict) else ""
            
            if not role or not content:
                continue
                
            if role == "system":
                langchain_messages.append(SystemMessage(content=str(content)))
            else:
                langchain_messages.append(HumanMessage(content=str(content)))
        
        if not langchain_messages:
            return "无有效消息"
        
        response = await self.llm.ainvoke(langchain_messages)
        
        # 记录 Token 使用量
        tracker = get_tracker()
        if tracker and hasattr(response, 'response_metadata'):
            metadata = response.response_metadata
            token_usage = metadata.get('token_usage', {})
            if token_usage:
                input_tokens = token_usage.get('prompt_tokens', 0)
                output_tokens = token_usage.get('completion_tokens', 0)
                tracker.record_token_usage(input_tokens, output_tokens)
        
        return response.content

