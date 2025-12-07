"""
记忆存储系统（参考Cyber-AutoAgent实现）
提供发现、计划、反思等信息的持久化存储和检索
"""
import os
import json
import pickle
from typing import List, Optional, Dict, Any
from pathlib import Path
from datetime import datetime
import uuid

try:
    import faiss
    from sentence_transformers import SentenceTransformer
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False

from src.utils.logger import default_logger


class MemoryStore:
    """
    记忆存储系统（参考Cyber-AutoAgent）
    
    功能：
    1. 存储发现（findings）、计划（plans）、反思（reflections）等
    2. 语义搜索
    3. 结构化metadata支持
    4. 持久化存储
    """
    
    def __init__(
        self,
        storage_dir: Optional[Path] = None,
        embedding_model: str = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
    ):
        """
        初始化记忆存储
        
        Args:
            storage_dir: 存储目录
            embedding_model: 嵌入模型名称
        """
        if not FAISS_AVAILABLE:
            default_logger.warning("记忆存储功能不可用，请安装 faiss-cpu 和 sentence-transformers")
            self.enabled = False
            return
        
        self.enabled = True
        
        # 设置存储路径
        project_root = Path(__file__).parent.parent.parent
        self.storage_dir = storage_dir or (project_root / "memory")
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # 索引文件
        self.index_file = self.storage_dir / "memory.faiss"
        self.metadata_file = self.storage_dir / "memory.pkl"
        
        # 初始化嵌入模型
        default_logger.info(f"加载嵌入模型: {embedding_model}")
        self.embedding_model = SentenceTransformer(embedding_model)
        self.embedding_dim = self.embedding_model.get_sentence_embedding_dimension()
        
        # 记忆数据
        self.memories: List[Dict[str, Any]] = []
        self.index = None
        
        # 加载或创建索引
        self._load_or_create_index()
    
    def _load_or_create_index(self):
        """加载现有索引或创建新索引"""
        if self.index_file.exists() and self.metadata_file.exists():
            try:
                default_logger.info("加载已有记忆索引...")
                self.index = faiss.read_index(str(self.index_file))
                with open(self.metadata_file, 'rb') as f:
                    self.memories = pickle.load(f)
                default_logger.info(f"已加载 {len(self.memories)} 条记忆")
                return
            except Exception as e:
                default_logger.warning(f"加载索引失败: {e}，将重新创建")
        
        # 创建新索引
        self.index = faiss.IndexFlatL2(self.embedding_dim)
        self.memories = []
        default_logger.info("创建新的记忆索引")
    
    def store(
        self,
        content: str,
        category: str = "general",
        metadata: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ) -> str:
        """
        存储记忆（参考Cyber-AutoAgent格式）
        
        Args:
            content: 记忆内容
            category: 类别（finding, plan, reflection, vulnerability, exploit, reconnaissance）
            metadata: 额外元数据（severity, confidence, validation_status等）
            user_id: 用户ID
            agent_id: Agent ID
        
        Returns:
            记忆ID
        """
        if not self.enabled:
            return ""
        
        # 生成记忆ID
        memory_id = f"mem_{uuid.uuid4().hex[:12]}"
        
        # 构建记忆对象
        memory = {
            "id": memory_id,
            "content": content,
            "category": category,
            "metadata": metadata or {},
            "user_id": user_id or "pentest_agent",
            "agent_id": agent_id or "pentest_agent",
            "created_at": datetime.now().isoformat(),
            "timestamp": datetime.now().timestamp()
        }
        
        # 添加到列表
        self.memories.append(memory)
        
        # 生成嵌入向量
        embedding = self.embedding_model.encode([content])[0]
        
        # 添加到索引
        self.index.add(embedding.astype('float32').reshape(1, -1))
        
        # 保存索引
        self._save_index()
        
        default_logger.info(f"存储记忆: {memory_id} (类别: {category})")
        
        return memory_id
    
    def store_finding(
        self,
        vulnerability: str,
        location: str,
        impact: str,
        evidence: str,
        steps: str = "",
        remediation: str = "",
        confidence: str = "",
        severity: str = "medium",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        存储安全发现（参考Cyber-AutoAgent格式）
        
        格式: [VULNERABILITY][WHERE][IMPACT][EVIDENCE][STEPS][REMEDIATION][CONFIDENCE]
        
        Args:
            vulnerability: 漏洞类型
            location: 位置
            impact: 影响
            evidence: 证据
            steps: 复现步骤
            remediation: 修复建议
            confidence: 信心水平
            severity: 严重程度（critical/high/medium/low）
            metadata: 额外元数据
        
        Returns:
            记忆ID
        """
        # 构建结构化内容
        content_parts = [
            f"[VULNERABILITY] {vulnerability}",
            f"[WHERE] {location}",
            f"[IMPACT] {impact}",
            f"[EVIDENCE] {evidence}"
        ]
        
        if steps:
            content_parts.append(f"[STEPS] {steps}")
        if remediation:
            content_parts.append(f"[REMEDIATION] {remediation}")
        if confidence:
            content_parts.append(f"[CONFIDENCE] {confidence}")
        
        content = "\n".join(content_parts)
        
        # 构建metadata
        finding_metadata = {
            "severity": severity,
            "confidence": confidence,
            "validation_status": metadata.get("validation_status", "verified") if metadata else "verified",
            **(metadata or {})
        }
        
        return self.store(
            content=content,
            category="finding",
            metadata=finding_metadata,
            user_id="pentest_agent"
        )
    
    def store_plan(
        self,
        objective: str,
        current_phase: int = 1,
        total_phases: int = 1,
        phases: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        存储计划（参考Cyber-AutoAgent格式）
        
        Args:
            objective: 目标
            current_phase: 当前阶段
            total_phases: 总阶段数
            phases: 阶段列表（每个阶段包含id, title, status, criteria）
            metadata: 额外元数据
        
        Returns:
            记忆ID
        """
        plan_data = {
            "objective": objective,
            "current_phase": current_phase,
            "total_phases": total_phases,
            "phases": phases or []
        }
        
        content = json.dumps(plan_data, ensure_ascii=False, indent=2)
        
        plan_metadata = {
            "type": "plan",
            **(metadata or {})
        }
        
        return self.store(
            content=content,
            category="plan",
            metadata=plan_metadata,
            user_id="pentest_agent"
        )
    
    def get_plan(self) -> Optional[Dict[str, Any]]:
        """
        获取最新计划
        
        Returns:
            计划数据，如果没有则返回None
        """
        # 查找最新的plan类别记忆
        plans = [
            m for m in self.memories
            if m.get("category") == "plan"
        ]
        
        if not plans:
            return None
        
        # 返回最新的
        latest_plan = max(plans, key=lambda x: x.get("timestamp", 0))
        
        try:
            return json.loads(latest_plan["content"])
        except:
            return None
    
    def retrieve(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 10,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        语义搜索记忆（参考Cyber-AutoAgent）
        
        Args:
            query: 查询文本
            category: 类别过滤
            limit: 返回数量
            filters: 额外过滤条件
        
        Returns:
            相关记忆列表
        """
        if not self.enabled or not self.index or not self.memories:
            return []
        
        # 生成查询向量
        query_embedding = self.embedding_model.encode([query])[0]
        
        # 搜索
        k = min(limit * 2, len(self.memories))  # 多搜索一些，用于过滤
        distances, indices = self.index.search(
            query_embedding.astype('float32').reshape(1, -1),
            k
        )
        
        # 构建结果
        results = []
        for idx, distance in zip(indices[0], distances[0]):
            if idx >= len(self.memories):
                continue
            
            memory = self.memories[idx].copy()
            
            # 类别过滤
            if category and memory.get("category") != category:
                continue
            
            # 额外过滤
            if filters:
                match = True
                for key, value in filters.items():
                    if memory.get("metadata", {}).get(key) != value:
                        match = False
                        break
                if not match:
                    continue
            
            # 计算相似度分数
            memory["similarity_score"] = float(1 / (1 + distance))
            memory["distance"] = float(distance)
            results.append(memory)
            
            if len(results) >= limit:
                break
        
        # 按相似度排序
        results.sort(key=lambda x: x.get("similarity_score", 0), reverse=True)
        
        return results
    
    def list_memories(
        self,
        category: Optional[str] = None,
        user_id: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        列出记忆
        
        Args:
            category: 类别过滤
            user_id: 用户ID过滤
            limit: 限制数量
        
        Returns:
            记忆列表
        """
        memories = self.memories.copy()
        
        # 过滤
        if category:
            memories = [m for m in memories if m.get("category") == category]
        
        if user_id:
            memories = [m for m in memories if m.get("user_id") == user_id]
        
        # 按时间排序（最新的在前）
        memories.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        
        # 限制数量
        if limit:
            memories = memories[:limit]
        
        return memories
    
    def get(self, memory_id: str) -> Optional[Dict[str, Any]]:
        """
        根据ID获取记忆
        
        Args:
            memory_id: 记忆ID
        
        Returns:
            记忆对象，如果不存在则返回None
        """
        for memory in self.memories:
            if memory.get("id") == memory_id:
                return memory.copy()
        return None
    
    def delete(self, memory_id: str) -> bool:
        """
        删除记忆
        
        Args:
            memory_id: 记忆ID
        
        Returns:
            是否成功删除
        """
        for i, memory in enumerate(self.memories):
            if memory.get("id") == memory_id:
                # 从列表中删除
                self.memories.pop(i)
                
                # 重建索引（简单实现，可以优化）
                self._rebuild_index()
                
                default_logger.info(f"删除记忆: {memory_id}")
                return True
        
        return False
    
    def _rebuild_index(self):
        """重建索引"""
        if not self.memories:
            self.index = faiss.IndexFlatL2(self.embedding_dim)
            return
        
        # 重新生成所有嵌入
        contents = [m["content"] for m in self.memories]
        embeddings = self.embedding_model.encode(contents)
        
        # 重建索引
        self.index = faiss.IndexFlatL2(self.embedding_dim)
        self.index.add(embeddings.astype('float32'))
        
        # 保存
        self._save_index()
    
    def _save_index(self):
        """保存索引到文件"""
        try:
            faiss.write_index(self.index, str(self.index_file))
            with open(self.metadata_file, 'wb') as f:
                pickle.dump(self.memories, f)
        except Exception as e:
            default_logger.error(f"保存索引失败: {e}")


# 全局记忆存储实例
_memory_store: Optional[MemoryStore] = None


def get_memory_store() -> MemoryStore:
    """获取全局记忆存储实例"""
    global _memory_store
    if _memory_store is None:
        _memory_store = MemoryStore()
    return _memory_store

