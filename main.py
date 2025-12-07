"""
主入口文件
启动Agent并运行XBOW基准测试
"""
import asyncio
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 添加项目路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.core.graph import build_agent_graph
from src.core.state import PenetrationState
from src.utils.llm_client import LLMClient
from src.utils.logger import setup_logger, default_logger
from src.utils.observability import initialize_tracker, get_tracker
from langchain_core.messages import SystemMessage
import argparse
import time
import logging


async def run_challenge(
    target_url: str,
    challenge_id: str = None,
    description: str = None,
    max_attempts: int = 50
):
    """
    运行单个挑战
    
    Args:
        target_url: 目标URL
        challenge_id: 挑战ID
        description: 挑战描述
        max_attempts: 最大尝试次数
    """
    default_logger.info(f"🎯 开始挑战: {challenge_id or 'unknown'}")
    default_logger.info(f"📍 目标URL: {target_url}")
    
    # 重置全局状态管理器（确保每次挑战从干净状态开始）
    try:
        from src.utils.key_discovery import reset_key_discovery_manager
        from src.utils.repetition_detector import reset_repetition_detector
        from src.utils.pentest_context import reset_pentest_context
        
        reset_key_discovery_manager()
        reset_repetition_detector()
        reset_pentest_context()
        default_logger.info("🔄 全局状态管理器已重置")
    except Exception as e:
        default_logger.warning(f"重置状态管理器失败: {e}")
    
    # 初始化可观测性追踪器
    operation_id = f"{challenge_id or 'unknown'}_{int(time.time())}"
    tracker = initialize_tracker(operation_id)
    default_logger.info(f"[可观测性] 追踪器已初始化: {operation_id}")
    
    # 初始化LLM
    main_provider = os.getenv("LLM_PROVIDER", "openai")
    main_model = os.getenv("LLM_MODEL", "gpt-4o")
    
    main_llm_client = LLMClient(
        provider=main_provider,
        model=main_model
    )
    main_llm = main_llm_client.get_llm()
    
    # 顾问LLM（可以使用不同模型）
    advisor_provider = os.getenv("ADVISOR_LLM_PROVIDER", main_provider)
    advisor_model = os.getenv("ADVISOR_LLM_MODEL", main_model)
    
    advisor_llm_client = LLMClient(
        provider=advisor_provider,
        model=advisor_model
    )
    advisor_llm = advisor_llm_client.get_llm()
    
    # 构建图
    app = await build_agent_graph(main_llm, advisor_llm)
    
    # 初始化状态
    initial_state: PenetrationState = {
        "messages": [],
        "current_challenge": {
            "id": challenge_id or "unknown",
            "target_url": target_url,
            "description": description or ""
        },
        "flag": None,
        "is_finished": False,
        "advisor_suggestion": None,
        "request_advisor_help": False,
        "consecutive_failures": 0,
        "last_action_type": None,
        "last_advisor_at_failures": 0,
        "action_history": [],
        "knowledge_context": None,
        "attempt_count": 0,
        "max_attempts": max_attempts,
        "start_time": time.time(),
        # 元认知相关（参考Cyber-AutoAgent）
        "confidence_score": None,  # 初始信心值（0-100）
        "confidence_level": None,
        "last_reflection": None,
        "confidence_update_formula": None,
        # 可观测性相关
        "operation_id": operation_id,
        # 关键发现（永不压缩丢弃）
        "key_discoveries": [],
        # 重复检测相关
        "recent_response_lengths": [],
        "strategy_switch_count": 0
    }
    
    # 运行Agent（增加递归限制，max_attempts * 3 以确保足够）
    recursion_limit = max(200, max_attempts * 4)
    config = {"recursion_limit": recursion_limit}
    
    try:
        final_state = None
        async for state in app.astream(initial_state, config=config):
            # 打印当前状态
            if "attacker" in state:
                default_logger.debug(f"主攻手状态更新")
            if "advisor" in state:
                default_logger.debug(f"顾问状态更新")
            if "tools" in state:
                default_logger.debug(f"工具执行完成")
            
            # 检查是否完成
            current_state = state.get("attacker") or state.get("tools") or state.get("advisor")
            if current_state:
                if current_state.get("flag"):
                    default_logger.info(f"🏆 找到FLAG: {current_state['flag']}")
                if current_state.get("is_finished"):
                    final_state = current_state
                    break
        
        # 输出结果
        if final_state:
            if final_state.get("flag"):
                default_logger.info(f"✅ 挑战完成！FLAG: {final_state['flag']}")
            else:
                default_logger.warning("⚠️ 挑战未完成，未找到FLAG")
        else:
            default_logger.warning("⚠️ 挑战超时或达到最大尝试次数")
    
    except Exception as e:
        default_logger.error(f"❌ 运行异常: {e}", exc_info=True)
    finally:
        # 完成追踪并生成统一报告
        try:
            tracker = get_tracker()
            if tracker:
                # 保存所有追踪数据和报告（统一在 observability/ 文件夹）
                tracker.finalize()
                default_logger.info(f"[报告] 测试报告已保存: observability/{operation_id}/")
        except Exception as e:
            default_logger.warning(f"[报告] 保存报告失败: {e}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="ShadowAgent - 自动化渗透测试Agent")
    parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="目标URL（XBOW挑战地址）"
    )
    parser.add_argument(
        "--challenge-id",
        type=str,
        help="挑战ID"
    )
    parser.add_argument(
        "--description",
        type=str,
        help="挑战描述"
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=50,
        help="最大尝试次数（默认50）"
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="日志级别"
    )
    parser.add_argument(
        "--log-file",
        type=str,
        help="日志文件路径（可选）"
    )
    
    args = parser.parse_args()
    
    # 设置日志
    log_level = getattr(logging, args.log_level.upper())
    log_file = Path(args.log_file) if args.log_file else None
    
    setup_logger(
        name="shadowagent",
        level=log_level,
        log_file=log_file
    )
    
    # 运行挑战
    asyncio.run(run_challenge(
        target_url=args.target,
        challenge_id=args.challenge_id,
        description=args.description,
        max_attempts=args.max_attempts
    ))


if __name__ == "__main__":
    import logging
    main()

