"""
LangGraph状态定义
定义Agent运行过程中的所有状态数据
"""
from typing import TypedDict, List, Optional, Dict, Any, Annotated
from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class PenetrationState(TypedDict):
    """
    渗透测试Agent的状态定义
    
    核心字段：
    - messages: 对话历史（LangGraph标准）
    - current_challenge: 当前挑战信息
    - flag: 找到的FLAG
    - is_finished: 是否完成
    - advisor_suggestion: 顾问建议
    - consecutive_failures: 连续失败次数
    - action_history: 操作历史
    """
    # 对话历史（使用 add_messages 确保消息正确累加和匹配 tool_call）
    messages: Annotated[List[BaseMessage], add_messages]
    
    # 当前挑战信息
    current_challenge: Optional[Dict[str, Any]]
    
    # FLAG相关
    flag: Optional[str]
    is_finished: bool
    
    # 顾问Agent相关
    advisor_suggestion: Optional[str]
    request_advisor_help: bool
    
    # 失败追踪
    consecutive_failures: int
    last_action_type: Optional[str]
    last_advisor_at_failures: int  # 上次咨询顾问时的失败次数
    
    # 操作历史（供顾问参考）
    action_history: List[str]
    
    # 知识库检索结果
    knowledge_context: Optional[str]
    
    # 元数据
    attempt_count: int
    max_attempts: int
    start_time: Optional[float]
    
    # 元认知相关（参考Cyber-AutoAgent实现）
    confidence_score: Optional[float]  # 0-100（数值信心，参考Cyber-AutoAgent）
    confidence_level: Optional[str]  # high/medium/low（用于显示）
    last_reflection: Optional[str]  # 最后一次反思内容
    confidence_update_formula: Optional[str]  # 信心更新公式（如 "70% - 30% = 40%"）

    # 可观测性相关
    operation_id: Optional[str]  # 当前操作ID（用于可观测性追踪）
    
    # 关键发现（永不压缩丢弃）
    key_discoveries: List[Dict[str, Any]]  # 关键发现列表（登录页、注入点等）
    
    # 重复检测相关
    recent_response_lengths: List[int]  # 最近的响应长度列表（用于检测重复）
    strategy_switch_count: int  # 策略切换次数
    
    # 全局解析结果（HaE 规则提取的信息）⭐
    parsed_info: List[Dict[str, Any]]  # 解析结果列表，每次工具执行后添加

