"""
可观测性系统（操作追踪和性能评估）
参考Cyber-AutoAgent实现
"""
import time
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum

from src.utils.logger import default_logger


class OperationType(Enum):
    """操作类型"""
    TOOL_EXECUTION = "tool_execution"
    AGENT_DECISION = "agent_decision"
    ROUTER_DECISION = "router_decision"
    STATE_UPDATE = "state_update"
    FLAG_FOUND = "flag_found"
    ERROR = "error"


@dataclass
class OperationTrace:
    """操作追踪记录"""
    timestamp: float
    operation_type: str
    operation_id: str
    agent_name: Optional[str] = None
    tool_name: Optional[str] = None
    input_data: Optional[Dict[str, Any]] = None
    output_data: Optional[Dict[str, Any]] = None
    duration_ms: Optional[float] = None
    success: Optional[bool] = None
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        data = asdict(self)
        data["datetime"] = datetime.fromtimestamp(self.timestamp).isoformat()
        return data


@dataclass
class PerformanceMetrics:
    """性能指标"""
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    total_duration_ms: float = 0.0
    average_duration_ms: float = 0.0
    tool_executions: int = 0
    agent_decisions: int = 0
    router_decisions: int = 0
    flags_found: int = 0
    errors: int = 0
    token_usage: Dict[str, int] = None  # {input_tokens, output_tokens, total_tokens}
    
    def __post_init__(self):
        if self.token_usage is None:
            self.token_usage = {
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0
            }
    
    def calculate_success_rate(self) -> float:
        """计算成功率"""
        if self.total_operations == 0:
            return 0.0
        return self.successful_operations / self.total_operations
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        data = asdict(self)
        data["success_rate"] = self.calculate_success_rate()
        return data


class ObservabilityTracker:
    """
    可观测性追踪器
    
    功能：
    1. 操作追踪：记录所有操作的时间线和详细信息
    2. 性能评估：收集和计算性能指标
    3. 指标报告：生成性能报告和统计信息
    """
    
    def __init__(
        self,
        operation_id: str,
        storage_dir: Optional[Path] = None
    ):
        """
        初始化追踪器
        
        Args:
            operation_id: 操作ID（用于标识本次运行）
            storage_dir: 存储目录
        """
        self.operation_id = operation_id
        self.start_time = time.time()
        
        # 设置存储路径
        project_root = Path(__file__).parent.parent.parent
        self.storage_dir = storage_dir or (project_root / "observability" / operation_id)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # 追踪数据
        self.traces: List[OperationTrace] = []
        self.metrics = PerformanceMetrics()
        
        # 当前操作追踪
        self.current_operation_start: Optional[float] = None
        self.current_operation_id: Optional[str] = None
        
        default_logger.info(f"[可观测性] 初始化追踪器: {operation_id}")
    
    def start_operation(
        self,
        operation_type: OperationType,
        operation_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        tool_name: Optional[str] = None,
        input_data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        开始追踪一个操作
        
        Args:
            operation_type: 操作类型
            operation_id: 操作ID（如果为None则自动生成）
            agent_name: Agent名称
            tool_name: 工具名称
            input_data: 输入数据
            metadata: 元数据
        
        Returns:
            操作ID
        """
        if operation_id is None:
            operation_id = f"{operation_type.value}_{int(time.time() * 1000)}"
        
        self.current_operation_start = time.time()
        self.current_operation_id = operation_id
        
        # 记录开始
        trace = OperationTrace(
            timestamp=self.current_operation_start,
            operation_type=operation_type.value,
            operation_id=operation_id,
            agent_name=agent_name,
            tool_name=tool_name,
            input_data=input_data,
            metadata=metadata
        )
        
        self.traces.append(trace)
        
        return operation_id
    
    def end_operation(
        self,
        operation_id: Optional[str] = None,
        success: bool = True,
        output_data: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None
    ):
        """
        结束追踪一个操作
        
        Args:
            operation_id: 操作ID（如果为None则使用当前操作）
            success: 是否成功
            output_data: 输出数据
            error_message: 错误消息
        """
        if operation_id is None:
            operation_id = self.current_operation_id
        
        if operation_id is None:
            default_logger.warning("[可观测性] 结束操作时未找到操作ID")
            return
        
        # 计算持续时间
        duration_ms = None
        if self.current_operation_start:
            duration_ms = (time.time() - self.current_operation_start) * 1000
        
        # 更新最后一个trace
        if self.traces:
            last_trace = self.traces[-1]
            if last_trace.operation_id == operation_id:
                last_trace.duration_ms = duration_ms
                last_trace.success = success
                last_trace.output_data = output_data
                last_trace.error_message = error_message
        
        # 更新指标
        self.metrics.total_operations += 1
        if success:
            self.metrics.successful_operations += 1
        else:
            self.metrics.failed_operations += 1
            self.metrics.errors += 1
        
        if duration_ms:
            self.metrics.total_duration_ms += duration_ms
            self.metrics.average_duration_ms = (
                self.metrics.total_duration_ms / self.metrics.total_operations
            )
        
        # 根据操作类型更新指标
        if last_trace:
            if last_trace.operation_type == OperationType.TOOL_EXECUTION.value:
                self.metrics.tool_executions += 1
            elif last_trace.operation_type == OperationType.AGENT_DECISION.value:
                self.metrics.agent_decisions += 1
            elif last_trace.operation_type == OperationType.ROUTER_DECISION.value:
                self.metrics.router_decisions += 1
            elif last_trace.operation_type == OperationType.FLAG_FOUND.value:
                self.metrics.flags_found += 1
        
        # 重置当前操作
        self.current_operation_start = None
        self.current_operation_id = None
    
    def record_tool_execution(
        self,
        tool_name: str,
        input_data: Dict[str, Any],
        output_data: Dict[str, Any],
        success: bool = True,
        duration_ms: Optional[float] = None
    ):
        """
        记录工具执行
        
        Args:
            tool_name: 工具名称
            input_data: 输入数据
            output_data: 输出数据
            success: 是否成功
            duration_ms: 持续时间（毫秒）
        """
        trace = OperationTrace(
            timestamp=time.time(),
            operation_type=OperationType.TOOL_EXECUTION.value,
            operation_id=f"tool_{int(time.time() * 1000)}",
            tool_name=tool_name,
            input_data=input_data,
            output_data=output_data,
            duration_ms=duration_ms,
            success=success
        )
        
        self.traces.append(trace)
        
        # 更新指标
        self.metrics.total_operations += 1
        self.metrics.tool_executions += 1
        if success:
            self.metrics.successful_operations += 1
        else:
            self.metrics.failed_operations += 1
        
        if duration_ms:
            self.metrics.total_duration_ms += duration_ms
            self.metrics.average_duration_ms = (
                self.metrics.total_duration_ms / self.metrics.total_operations
            )
    
    def record_agent_decision(
        self,
        agent_name: str,
        decision: str,
        reasoning: Optional[str] = None
    ):
        """
        记录Agent决策
        
        Args:
            agent_name: Agent名称
            decision: 决策内容
            reasoning: 推理过程
        """
        trace = OperationTrace(
            timestamp=time.time(),
            operation_type=OperationType.AGENT_DECISION.value,
            operation_id=f"decision_{int(time.time() * 1000)}",
            agent_name=agent_name,
            input_data={"decision": decision, "reasoning": reasoning}
        )
        
        self.traces.append(trace)
        self.metrics.agent_decisions += 1
        self.metrics.total_operations += 1
    
    def record_router_decision(
        self,
        decision: str,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        记录路由决策
        
        Args:
            decision: 决策（advisor/attacker/end）
            reason: 决策原因
            metadata: 元数据
        """
        trace = OperationTrace(
            timestamp=time.time(),
            operation_type=OperationType.ROUTER_DECISION.value,
            operation_id=f"router_{int(time.time() * 1000)}",
            input_data={"decision": decision, "reason": reason},
            metadata=metadata
        )
        
        self.traces.append(trace)
        self.metrics.router_decisions += 1
        self.metrics.total_operations += 1
    
    def record_flag_found(self, flag: str):
        """
        记录FLAG发现
        
        Args:
            flag: FLAG内容
        """
        trace = OperationTrace(
            timestamp=time.time(),
            operation_type=OperationType.FLAG_FOUND.value,
            operation_id=f"flag_{int(time.time() * 1000)}",
            input_data={"flag": flag},
            success=True
        )
        
        self.traces.append(trace)
        self.metrics.flags_found += 1
        self.metrics.total_operations += 1
    
    def record_token_usage(
        self,
        input_tokens: int,
        output_tokens: int
    ):
        """
        记录Token使用
        
        Args:
            input_tokens: 输入token数
            output_tokens: 输出token数
        """
        self.metrics.token_usage["input_tokens"] += input_tokens
        self.metrics.token_usage["output_tokens"] += output_tokens
        self.metrics.token_usage["total_tokens"] += (input_tokens + output_tokens)
    
    def save_traces(self):
        """保存追踪数据到文件"""
        traces_file = self.storage_dir / "traces.json"
        
        traces_data = [trace.to_dict() for trace in self.traces]
        
        with open(traces_file, 'w', encoding='utf-8') as f:
            json.dump(traces_data, f, ensure_ascii=False, indent=2)
        
        default_logger.info(f"[可观测性] 追踪数据已保存: {traces_file}")
    
    def save_metrics(self):
        """保存指标数据到文件"""
        metrics_file = self.storage_dir / "metrics.json"
        
        metrics_data = self.metrics.to_dict()
        metrics_data["operation_id"] = self.operation_id
        metrics_data["start_time"] = datetime.fromtimestamp(self.start_time).isoformat()
        metrics_data["end_time"] = datetime.fromtimestamp(time.time()).isoformat()
        metrics_data["total_duration_seconds"] = time.time() - self.start_time
        
        with open(metrics_file, 'w', encoding='utf-8') as f:
            json.dump(metrics_data, f, ensure_ascii=False, indent=2)
        
        default_logger.info(f"[可观测性] 指标数据已保存: {metrics_file}")
    
    def generate_report(self) -> str:
        """
        生成性能报告
        
        Returns:
            报告文本
        """
        total_duration = time.time() - self.start_time
        
        report_lines = [
            "=" * 60,
            "📊 性能评估报告",
            "=" * 60,
            f"操作ID: {self.operation_id}",
            f"开始时间: {datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')}",
            f"总时长: {total_duration:.2f} 秒",
            "",
            "📈 核心指标",
            "-" * 60,
            f"总操作数: {self.metrics.total_operations}",
            f"成功操作: {self.metrics.successful_operations}",
            f"失败操作: {self.metrics.failed_operations}",
            f"成功率: {self.metrics.calculate_success_rate():.2%}",
            f"平均响应时间: {self.metrics.average_duration_ms:.2f} ms",
            "",
            "🔧 操作统计",
            "-" * 60,
            f"工具执行: {self.metrics.tool_executions}",
            f"Agent决策: {self.metrics.agent_decisions}",
            f"路由决策: {self.metrics.router_decisions}",
            f"FLAG发现: {self.metrics.flags_found}",
            f"错误数: {self.metrics.errors}",
            "",
            "💻 Token使用",
            "-" * 60,
            f"输入Token: {self.metrics.token_usage['input_tokens']:,}",
            f"输出Token: {self.metrics.token_usage['output_tokens']:,}",
            f"总Token: {self.metrics.token_usage['total_tokens']:,}",
        ]
        
        # 工具执行统计
        if self.metrics.tool_executions > 0:
            tool_stats = {}
            for trace in self.traces:
                if trace.operation_type == OperationType.TOOL_EXECUTION.value and trace.tool_name:
                    tool_name = trace.tool_name
                    tool_stats[tool_name] = tool_stats.get(tool_name, 0) + 1
            
            if tool_stats:
                report_lines.extend([
                    "",
                    "🛠️ 工具使用统计",
                    "-" * 60,
                ])
                for tool_name, count in sorted(tool_stats.items(), key=lambda x: x[1], reverse=True):
                    report_lines.append(f"  {tool_name}: {count} 次")
        
        report_lines.append("")
        report_lines.append("=" * 60)
        
        return "\n".join(report_lines)
    
    def save_report(self):
        """保存报告到文件"""
        report_file = self.storage_dir / "report.txt"
        report = self.generate_report()
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        default_logger.info(f"[可观测性] 报告已保存: {report_file}")
        
        # 同时打印报告
        default_logger.info("\n" + report)
    
    def finalize(self):
        """完成追踪，保存所有数据"""
        self.save_traces()
        self.save_metrics()
        self.save_report()


# 全局追踪器实例
_tracker: Optional[ObservabilityTracker] = None


def get_tracker() -> Optional[ObservabilityTracker]:
    """获取全局追踪器实例"""
    return _tracker


def initialize_tracker(operation_id: str, storage_dir: Optional[Path] = None) -> ObservabilityTracker:
    """初始化全局追踪器"""
    global _tracker
    _tracker = ObservabilityTracker(operation_id, storage_dir)
    return _tracker

