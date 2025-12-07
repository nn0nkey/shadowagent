"""
RAG知识库系统
提供攻击场景知识检索和增强
"""
import os
from typing import List, Optional, Dict, Any
from pathlib import Path
import pickle
import json

try:
    import faiss
    from sentence_transformers import SentenceTransformer
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    print("警告: faiss-cpu 或 sentence-transformers 未安装，知识库功能将受限")

from src.utils.logger import default_logger


class KnowledgeBase:
    """
    RAG知识库
    
    功能：
    1. 加载攻击场景知识文档
    2. 向量化存储
    3. 相似度检索
    4. 格式化输出
    """
    
    def __init__(
        self,
        knowledge_dir: Optional[Path] = None,
        embedding_model: str = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
        cache_dir: Optional[Path] = None
    ):
        """
        初始化知识库
        
        Args:
            knowledge_dir: 知识库文档目录
            embedding_model: 嵌入模型名称
            cache_dir: 缓存目录
        """
        if not FAISS_AVAILABLE:
            default_logger.warning("知识库功能不可用，请安装 faiss-cpu 和 sentence-transformers")
            self.enabled = False
            return
        
        self.enabled = True
        
        # 设置路径
        project_root = Path(__file__).parent.parent.parent
        self.knowledge_dir = knowledge_dir or (project_root / "knowledge")
        self.cache_dir = cache_dir or (project_root / "knowledge" / "cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_map = self._load_metadata()
        
        # 初始化嵌入模型
        default_logger.info(f"加载嵌入模型: {embedding_model}")
        self.embedding_model = SentenceTransformer(embedding_model)
        self.embedding_dim = self.embedding_model.get_sentence_embedding_dimension()
        
        # 知识库数据
        self.documents: List[Dict[str, Any]] = []
        self.index = None
        
        # 加载或构建索引
        self._load_or_build_index()
    
    def _load_or_build_index(self):
        """加载现有索引或构建新索引"""
        index_file = self.cache_dir / "knowledge.faiss"
        metadata_file = self.cache_dir / "knowledge.pkl"
        
        if index_file.exists() and metadata_file.exists():
            try:
                default_logger.info("加载已有知识库索引...")
                self.index = faiss.read_index(str(index_file))
                with open(metadata_file, 'rb') as f:
                    self.documents = pickle.load(f)
                default_logger.info(f"已加载 {len(self.documents)} 条知识")
                return
            except Exception as e:
                default_logger.warning(f"加载索引失败: {e}，将重新构建")
        
        # 构建新索引
        self._build_index()
    
    def _build_index(self):
        """构建知识库索引"""
        default_logger.info("构建知识库索引...")
        
        # 加载知识文档
        self._load_documents()
        
        if not self.documents:
            default_logger.warning("未找到知识文档，知识库为空")
            return
        
        # 生成嵌入向量
        texts = [doc["content"] for doc in self.documents]
        embeddings = self.embedding_model.encode(texts, show_progress_bar=True)
        
        # 创建FAISS索引
        self.index = faiss.IndexFlatL2(self.embedding_dim)
        self.index.add(embeddings.astype('float32'))
        
        # 保存索引
        index_file = self.cache_dir / "knowledge.faiss"
        metadata_file = self.cache_dir / "knowledge.pkl"
        
        faiss.write_index(self.index, str(index_file))
        with open(metadata_file, 'wb') as f:
            pickle.dump(self.documents, f)
        
        default_logger.info(f"知识库索引构建完成，共 {len(self.documents)} 条知识")
    
    def _load_documents(self):
        """加载知识文档"""
        if not self.knowledge_dir.exists():
            default_logger.warning(f"知识库目录不存在: {self.knowledge_dir}")
            return
        
        # 查找所有Markdown文件（包含子目录）
        md_files = [
            p for p in self.knowledge_dir.rglob("*.md")
            if "cache" not in p.parts  # 跳过缓存目录
        ]
        metadata_map = self.metadata_map or {}
        
        for md_file in md_files:
            if md_file.name.lower() == "readme.md":
                # README仅做说明，不纳入检索
                continue
            try:
                content = md_file.read_text(encoding='utf-8')
                relative_path = md_file.relative_to(self.knowledge_dir)
                metadata = metadata_map.get(md_file.stem, {})
                
                # 解析文档（简单实现，可以更复杂）
                doc = {
                    "id": metadata.get("doc_id", md_file.stem),
                    "title": metadata.get("title") or self._extract_title(content),
                    "content": content,
                    "file_path": str(relative_path),
                    "vuln_type": metadata.get("vuln_type"),
                    "tags": metadata.get("tags", []),
                    "summary": metadata.get("summary"),
                    "difficulty": metadata.get("difficulty"),
                    "metadata": metadata,
                    "source": metadata.get("file_path", str(relative_path))
                }
                
                self.documents.append(doc)
            except Exception as e:
                default_logger.warning(f"加载文档失败 {md_file}: {e}")
        
        default_logger.info(f"已加载 {len(self.documents)} 个知识文档")
    
    def _load_metadata(self) -> Dict[str, Dict[str, Any]]:
        """加载知识库元数据（如果存在）"""
        metadata_map: Dict[str, Dict[str, Any]] = {}
        if not self.knowledge_dir.exists():
            return metadata_map
        
        metadata_files = list(self.knowledge_dir.rglob("knowledge_metadata.json"))
        for meta_file in metadata_files:
            try:
                with open(meta_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    metadata_map.update(data)
            except Exception as e:
                default_logger.warning(f"加载元数据失败 {meta_file}: {e}")
        
        if metadata_map:
            default_logger.info(f"已加载 {len(metadata_map)} 条知识元数据")
        return metadata_map
    
    def _extract_title(self, content: str) -> str:
        """从Markdown内容中提取标题"""
        lines = content.split('\n')
        for line in lines:
            if line.startswith('# '):
                return line[2:].strip()
        return "未命名文档"
    
    def search(
        self,
        query: str,
        top_k: int = 5,
        vulnerability_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        搜索相关知识
        
        Args:
            query: 查询文本
            top_k: 返回前K个结果
            vulnerability_type: 漏洞类型过滤（可选）
        
        Returns:
            相关知识列表
        """
        if not self.enabled or not self.index:
            return []
        
        if not self.documents:
            default_logger.warning("知识库为空，无法搜索")
            return []
        
        # 生成查询向量
        query_embedding = self.embedding_model.encode([query])
        
        # 搜索
        k = min(top_k, len(self.documents))
        distances, indices = self.index.search(query_embedding.astype('float32'), k)
        
        # 构建结果
        results = []
        for idx, distance in zip(indices[0], distances[0]):
            if idx < len(self.documents):
                doc = self.documents[idx].copy()
                doc["similarity_score"] = float(1 / (1 + distance))  # 转换为相似度分数
                results.append(doc)
        
        # 按漏洞类型过滤（如果指定）
        if vulnerability_type:
            results = [
                r for r in results
                if vulnerability_type.lower() in r.get("content", "").lower()
            ]
        
        return results
    
    def format_search_results(
        self,
        query: str,
        results: List[Dict[str, Any]],
        max_length: int = 2000
    ) -> str:
        """
        格式化搜索结果
        
        Args:
            query: 原始查询
            results: 搜索结果
            max_length: 最大输出长度
        
        Returns:
            格式化后的文本
        """
        if not results:
            return ""
        
        formatted_parts = [f"## 📚 相关知识检索（查询: {query}）\n"]
        
        for i, result in enumerate(results[:3], 1):  # 只显示前3个
            title = result.get("title", "未命名")
            content = result.get("content", "")
            score = result.get("similarity_score", 0)
            
            # 截断内容
            if len(content) > 500:
                content = content[:500] + "..."
            
            formatted_parts.append(
                f"### {i}. {title} (相似度: {score:.2f})\n\n{content}\n"
            )
        
        formatted_text = "\n".join(formatted_parts)
        
        # 如果太长，截断
        if len(formatted_text) > max_length:
            formatted_text = formatted_text[:max_length] + "\n..."
        
        return formatted_text


# 全局知识库实例
_knowledge_base: Optional[KnowledgeBase] = None


def get_knowledge_base() -> KnowledgeBase:
    """获取全局知识库实例"""
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = KnowledgeBase()
    return _knowledge_base

