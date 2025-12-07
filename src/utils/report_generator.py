"""
安全评估报告生成器（参考Cyber-AutoAgent）

生成专业的渗透测试报告，包含：
- 执行摘要
- 发现汇总
- 详细发现（带Proof Pack）
- 建议和修复方案
- 时间线
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    """安全发现"""
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    evidence: str = ""
    validation_status: str = "hypothesis"  # verified, hypothesis
    artifacts: List[str] = field(default_factory=list)
    rationale: str = ""
    location: str = ""
    impact: str = ""
    remediation: str = ""
    confidence: int = 50
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class OperationSummary:
    """操作摘要"""
    target: str
    objective: str
    operation_id: str
    start_time: str
    end_time: str = ""
    duration_seconds: float = 0
    total_steps: int = 0
    successful_steps: int = 0
    failed_steps: int = 0
    tools_used: List[str] = field(default_factory=list)
    flag_found: bool = False
    flag_value: str = ""


@dataclass
class AgentLog:
    """Agent 对话日志"""
    agent: str  # attacker, advisor
    role: str  # thought, action, tool_call, tool_result, suggestion
    content: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class ReportGenerator:
    """安全评估报告生成器"""
    
    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    SEVERITY_COLORS = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "INFO": "🔵"
    }
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        self.findings: List[Finding] = []
        self.summary: Optional[OperationSummary] = None
        self.timeline: List[Dict[str, Any]] = []
        self.agent_logs: List[AgentLog] = []  # Agent 对话日志
        
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)
    
    def set_summary(self, summary: OperationSummary):
        """设置操作摘要"""
        self.summary = summary
    
    def add_finding(self, finding: Finding):
        """添加发现"""
        self.findings.append(finding)
    
    def add_timeline_event(self, event: str, details: str = "", success: bool = True):
        """添加时间线事件"""
        self.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "details": details,
            "success": success
        })
    
    def add_agent_log(self, agent: str, role: str, content: str):
        """添加 Agent 对话日志
        
        Args:
            agent: 'attacker' 或 'advisor'
            role: 'thought'(思考), 'action'(行动), 'tool_call'(工具调用), 
                  'tool_result'(工具结果), 'suggestion'(建议)
            content: 日志内容
        """
        self.agent_logs.append(AgentLog(
            agent=agent,
            role=role,
            content=content[:2000]  # 限制长度
        ))
    
    def _sort_findings(self) -> List[Finding]:
        """按严重程度排序发现"""
        return sorted(
            self.findings,
            key=lambda f: self.SEVERITY_ORDER.index(f.severity) if f.severity in self.SEVERITY_ORDER else 999
        )
    
    def _generate_executive_summary(self) -> str:
        """生成执行摘要"""
        if not self.summary:
            return "无操作摘要可用。"
        
        # 统计发现
        severity_counts = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        verified_count = sum(1 for f in self.findings if f.validation_status == "verified")
        hypothesis_count = len(self.findings) - verified_count
        
        lines = [
            "# 执行摘要",
            "",
            f"**目标**: {self.summary.target}",
            f"**目标**: {self.summary.objective}",
            f"**操作ID**: {self.summary.operation_id}",
            f"**持续时间**: {self.summary.duration_seconds:.1f} 秒",
            "",
            "## 关键指标",
            "",
            f"| 指标 | 值 |",
            f"|------|-----|",
            f"| 总步骤 | {self.summary.total_steps} |",
            f"| 成功步骤 | {self.summary.successful_steps} |",
            f"| 失败步骤 | {self.summary.failed_steps} |",
            f"| 成功率 | {self.summary.successful_steps / max(self.summary.total_steps, 1) * 100:.1f}% |",
            f"| FLAG发现 | {'✅ 是' if self.summary.flag_found else '❌ 否'} |",
            "",
            "## 发现摘要",
            "",
        ]
        
        if self.findings:
            lines.append("| 严重程度 | 数量 |")
            lines.append("|----------|------|")
            for severity in self.SEVERITY_ORDER:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    emoji = self.SEVERITY_COLORS.get(severity, "")
                    lines.append(f"| {emoji} {severity} | {count} |")
            lines.append("")
            lines.append(f"- **已验证发现**: {verified_count}")
            lines.append(f"- **假设发现**: {hypothesis_count}")
        else:
            lines.append("未发现安全问题。")
        
        if self.summary.flag_found:
            lines.append("")
            lines.append(f"## 🏆 FLAG")
            lines.append("")
            lines.append(f"```")
            lines.append(f"{self.summary.flag_value}")
            lines.append(f"```")
        
        return "\n".join(lines)
    
    def _generate_findings_section(self) -> str:
        """生成详细发现部分"""
        if not self.findings:
            return "# 详细发现\n\n无发现。"
        
        lines = ["# 详细发现", ""]
        
        sorted_findings = self._sort_findings()
        
        for i, finding in enumerate(sorted_findings, 1):
            emoji = self.SEVERITY_COLORS.get(finding.severity, "")
            status_emoji = "✅" if finding.validation_status == "verified" else "❓"
            
            lines.append(f"## {i}. {emoji} [{finding.severity}] {finding.title}")
            lines.append("")
            lines.append(f"**状态**: {status_emoji} {finding.validation_status.upper()}")
            lines.append(f"**置信度**: {finding.confidence}%")
            if finding.location:
                lines.append(f"**位置**: {finding.location}")
            lines.append("")
            
            lines.append("### 描述")
            lines.append("")
            lines.append(finding.description)
            lines.append("")
            
            if finding.impact:
                lines.append("### 影响")
                lines.append("")
                lines.append(finding.impact)
                lines.append("")
            
            if finding.evidence:
                lines.append("### 证据")
                lines.append("")
                lines.append("```")
                lines.append(finding.evidence[:1000])
                if len(finding.evidence) > 1000:
                    lines.append("... [截断]")
                lines.append("```")
                lines.append("")
            
            if finding.artifacts:
                lines.append("### Proof Pack")
                lines.append("")
                lines.append("**证据文件**:")
                for artifact in finding.artifacts:
                    lines.append(f"- `{artifact}`")
                lines.append("")
                if finding.rationale:
                    lines.append(f"**理由**: {finding.rationale}")
                    lines.append("")
            
            if finding.remediation:
                lines.append("### 修复建议")
                lines.append("")
                lines.append(finding.remediation)
                lines.append("")
            
            lines.append("---")
            lines.append("")
        
        return "\n".join(lines)
    
    def _generate_timeline_section(self) -> str:
        """生成时间线部分"""
        if not self.timeline:
            return "# 操作时间线\n\n无时间线数据。"
        
        lines = ["# 操作时间线", ""]
        
        for event in self.timeline:
            status = "✅" if event.get("success", True) else "❌"
            timestamp = event.get("timestamp", "")[:19]  # 截取到秒
            lines.append(f"- **{timestamp}** {status} {event.get('event', '')}")
            if event.get("details"):
                lines.append(f"  - {event['details'][:100]}")
        
        return "\n".join(lines)
    
    def _generate_tools_section(self) -> str:
        """生成工具使用部分"""
        if not self.summary or not self.summary.tools_used:
            return "# 使用的工具\n\n无工具使用记录。"
        
        lines = ["# 使用的工具", ""]
        
        # 统计工具使用次数
        tool_counts = {}
        for tool in self.summary.tools_used:
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        
        lines.append("| 工具 | 使用次数 |")
        lines.append("|------|----------|")
        for tool, count in sorted(tool_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| {tool} | {count} |")
        
        return "\n".join(lines)
    
    def _generate_recommendations(self) -> str:
        """生成建议部分"""
        lines = ["# 建议", ""]
        
        if not self.findings:
            lines.append("基于本次评估，未发现需要立即处理的安全问题。")
            lines.append("")
            lines.append("建议定期进行安全评估以确保持续的安全态势。")
            return "\n".join(lines)
        
        # 按严重程度分组建议
        critical_high = [f for f in self.findings if f.severity in ["CRITICAL", "HIGH"]]
        medium_low = [f for f in self.findings if f.severity in ["MEDIUM", "LOW"]]
        
        if critical_high:
            lines.append("## 🔴 紧急修复（CRITICAL/HIGH）")
            lines.append("")
            for f in critical_high:
                lines.append(f"1. **{f.title}**")
                if f.remediation:
                    lines.append(f"   - {f.remediation}")
                else:
                    lines.append(f"   - 立即调查并修复此漏洞")
            lines.append("")
        
        if medium_low:
            lines.append("## 🟡 计划修复（MEDIUM/LOW）")
            lines.append("")
            for f in medium_low:
                lines.append(f"1. **{f.title}**")
                if f.remediation:
                    lines.append(f"   - {f.remediation}")
            lines.append("")
        
        lines.append("## 📋 通用建议")
        lines.append("")
        lines.append("1. 实施输入验证和输出编码")
        lines.append("2. 使用参数化查询防止SQL注入")
        lines.append("3. 实施适当的访问控制")
        lines.append("4. 定期进行安全评估")
        lines.append("5. 保持软件和依赖项更新")
        
        return "\n".join(lines)
    
    def _generate_agent_logs_section(self) -> str:
        """生成 Agent 对话日志部分"""
        if not self.agent_logs:
            return ""
        
        lines = [
            "# 🤖 Agent 思考过程",
            "",
            "以下是主攻手和顾问的完整对话记录：",
            ""
        ]
        
        # 角色图标映射
        role_icons = {
            "thought": "💭",
            "action": "⚡",
            "tool_call": "🔧",
            "tool_result": "📋",
            "suggestion": "💡"
        }
        
        agent_names = {
            "attacker": "主攻手",
            "advisor": "顾问"
        }
        
        for log in self.agent_logs:
            icon = role_icons.get(log.role, "📝")
            agent_name = agent_names.get(log.agent, log.agent)
            timestamp = log.timestamp.split("T")[1].split(".")[0] if "T" in log.timestamp else log.timestamp
            
            lines.append(f"### {icon} [{timestamp}] {agent_name} - {log.role}")
            lines.append("")
            lines.append("```")
            lines.append(log.content)
            lines.append("```")
            lines.append("")
        
        return "\n".join(lines)
    
    def generate_report(self) -> str:
        """生成完整报告"""
        sections = [
            self._generate_executive_summary(),
            self._generate_findings_section(),
            self._generate_tools_section(),
            self._generate_timeline_section(),
            self._generate_recommendations(),
            self._generate_agent_logs_section(),  # 添加 Agent 日志
        ]
        
        # 过滤空部分
        sections = [s for s in sections if s.strip()]
        
        report = "\n\n".join(sections)
        
        # 添加页脚
        report += f"\n\n---\n\n*报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"
        report += "*由 ShadowAgent 安全评估系统生成*\n"
        
        return report
    
    def save_report(self, filename: Optional[str] = None) -> str:
        """保存报告到文件"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            op_id = self.summary.operation_id if self.summary else "unknown"
            filename = f"report_{op_id}_{timestamp}.md"
        
        filepath = os.path.join(self.output_dir, filename)
        
        report = self.generate_report()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report)
        
        # 同时保存 JSON 格式
        json_filepath = filepath.replace('.md', '.json')
        json_data = {
            "summary": asdict(self.summary) if self.summary else None,
            "findings": [asdict(f) for f in self.findings],
            "timeline": self.timeline,
            "agent_logs": [asdict(log) for log in self.agent_logs],  # 添加 Agent 日志
            "generated_at": datetime.now().isoformat()
        }
        
        with open(json_filepath, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2)
        
        return filepath
    
    def generate_html_report(self) -> str:
        """生成 HTML 格式报告"""
        md_report = self.generate_report()
        
        # 简单的 Markdown 到 HTML 转换
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>安全评估报告 - {self.summary.operation_id if self.summary else 'Unknown'}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #1a1a1a; border-bottom: 2px solid #333; }}
        h2 {{ color: #333; margin-top: 30px; }}
        h3 {{ color: #555; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background-color: #f5f5f5; }}
        code {{ background-color: #f5f5f5; padding: 2px 6px; border-radius: 3px; }}
        pre {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        .info {{ color: #1976d2; }}
    </style>
</head>
<body>
<pre>{md_report}</pre>
</body>
</html>"""
        
        return html


# 全局报告生成器实例
_report_generator: Optional[ReportGenerator] = None


def get_report_generator(output_dir: str = "reports") -> ReportGenerator:
    """获取报告生成器实例"""
    global _report_generator
    if _report_generator is None:
        _report_generator = ReportGenerator(output_dir)
    return _report_generator


def reset_report_generator():
    """重置报告生成器"""
    global _report_generator
    _report_generator = None
