"""
字典学习模块
根据测试中发现的端点，自动学习并更新 dirb 字典
"""
from pathlib import Path
from src.utils.key_discovery import get_key_discovery_manager
from src.utils.logger import default_logger
from src.executor.docker_executor import DockerExecutor


# 学习配置文件路径
LEARNED_PATHS_FILE = Path(__file__).parent.parent.parent / "config" / "learned_paths.txt"


def learn_and_update_wordlist():
    """
    从本次测试中学习新端点，更新字典
    
    流程：
    1. 从 KeyDiscoveryManager 获取所有发现的路径
    2. 过滤出有价值的端点（排除常见的、已知的）
    3. 保存到本地学习文件
    4. 更新 Docker 容器中的 dirb 字典
    """
    default_logger.info("🎓 [学习] 开始分析本次测试发现的端点...")
    
    # 1. 获取所有发现的路径
    discovery_manager = get_key_discovery_manager()
    paths = discovery_manager.get_by_category("path")
    api_endpoints = discovery_manager.get_by_category("api_endpoint")
    
    if not paths and not api_endpoints:
        default_logger.info("🎓 [学习] 本次测试未发现新端点")
        return
    
    # 2. 提取路径名（去除状态码等信息）
    discovered_paths = set()
    
    for p in paths:
        # 格式: "/ping [Status: 200]" -> "ping"
        path = p.content.split()[0].strip('/')
        if path and len(path) > 1:
            discovered_paths.add(path)
    
    for ep in api_endpoints:
        # 格式: "/api/users" -> "api/users" 或 "users"
        path = ep.content.strip('/')
        if path and len(path) > 1:
            # 只保留第一级路径（如 "api/users" -> "api"）
            first_level = path.split('/')[0]
            if first_level:
                discovered_paths.add(first_level)
    
    if not discovered_paths:
        default_logger.info("🎓 [学习] 未提取到有效路径")
        return
    
    default_logger.info(f"🎓 [学习] 本次发现 {len(discovered_paths)} 个端点: {', '.join(list(discovered_paths)[:5])}...")
    
    # 3. 过滤已知路径
    known_paths = _load_known_paths()
    new_paths = discovered_paths - known_paths
    
    if not new_paths:
        default_logger.info("🎓 [学习] 所有端点都已在字典中")
        return
    
    default_logger.info(f"🎓 [学习] 发现 {len(new_paths)} 个新端点: {', '.join(list(new_paths)[:5])}...")
    
    # 4. 保存到学习文件
    _save_learned_paths(new_paths)
    
    # 5. 更新 Docker 容器中的字典
    _update_docker_wordlist(new_paths)
    
    default_logger.info(f"✅ [学习] 已将 {len(new_paths)} 个新端点添加到字典")


def _load_known_paths() -> set:
    """加载已知路径（直接从 Docker 容器的字典文件读取）"""
    known = set()
    
    try:
        executor = DockerExecutor.get_instance()
        
        # 直接读取 dirb 字典文件
        read_cmd = "cat /usr/share/wordlists/dirb/common.txt 2>/dev/null || echo ''"
        result = executor.execute(read_cmd)
        
        # 解析字典内容
        for line in result.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # 只保留路径名（去除前导斜杠）
                path = line.strip('/')
                if path:
                    known.add(path)
        
        default_logger.debug(f"🎓 [学习] 从字典加载了 {len(known)} 个已知路径")
    
    except Exception as e:
        default_logger.warning(f"🎓 [学习] 读取字典失败: {e}")
    
    return known


def _save_learned_paths(new_paths: set):
    """保存新学习的路径到文件"""
    # 确保目录存在
    LEARNED_PATHS_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    # 追加写入
    with open(LEARNED_PATHS_FILE, 'a') as f:
        for path in sorted(new_paths):
            f.write(f"{path}\n")


def _update_docker_wordlist(new_paths: set):
    """更新 Docker 容器中的 dirb 字典"""
    try:
        executor = DockerExecutor.get_instance()
        
        # 构建追加命令
        for path in new_paths:
            # 检查是否已存在
            check_cmd = f"grep -q '^{path}$' /usr/share/wordlists/dirb/common.txt 2>/dev/null && echo 'exists' || echo 'new'"
            result = executor.execute(check_cmd)
            
            if 'new' in result:
                # 追加到字典
                add_cmd = f"echo '{path}' >> /usr/share/wordlists/dirb/common.txt"
                executor.execute(add_cmd)
                default_logger.debug(f"🎓 [学习] 已添加: {path}")
    
    except Exception as e:
        default_logger.warning(f"🎓 [学习] 更新 Docker 字典失败: {e}")


def get_learned_paths() -> list:
    """获取所有已学习的路径"""
    if not LEARNED_PATHS_FILE.exists():
        return []
    
    paths = []
    with open(LEARNED_PATHS_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                paths.append(line)
    
    return paths
