"""
Docker执行器
在Kali Linux容器中执行命令和Python代码

参考H-Pentest项目优化：
1. 修复超时问题（Docker SDK exec_run不支持timeout参数）
2. 添加工作目录隔离
3. 支持异步执行
"""
import os
import uuid
import asyncio
import docker
from typing import Optional, Tuple
from docker.models.containers import Container
from src.utils.logger import default_logger
from concurrent.futures import ThreadPoolExecutor

# 线程池用于异步执行
_executor_pool = ThreadPoolExecutor(max_workers=4)


class DockerExecutor:
    """
    Docker执行器单例
    
    管理Docker容器的生命周期，提供命令和Python代码执行能力
    """
    _instance: Optional['DockerExecutor'] = None
    _container: Optional[Container] = None
    
    def __init__(self):
        """初始化Docker客户端"""
        try:
            # 自动检测 Docker socket（支持 Colima、Docker Desktop 等）
            self._setup_docker_host()
            
            self.client = docker.from_env()
            self.container_name = os.getenv("DOCKER_CONTAINER_NAME", "shadowagent-kali")
            self.image_name = os.getenv("DOCKER_IMAGE", "h-pentest/kali:latest")
            self._ensure_container()
        except Exception as e:
            default_logger.error(f"Docker初始化失败: {e}")
            raise
    
    def _setup_docker_host(self):
        """自动检测并设置 DOCKER_HOST 环境变量"""
        if os.getenv("DOCKER_HOST"):
            return  # 已经设置，不覆盖
        
        # 常见的 Docker socket 路径
        socket_paths = [
            "/var/run/docker.sock",  # Docker Desktop (Linux/Mac)
            os.path.expanduser("~/.colima/default/docker.sock"),  # Colima
            os.path.expanduser("~/.docker/run/docker.sock"),  # Docker Desktop (Mac)
        ]
        
        for socket_path in socket_paths:
            if os.path.exists(socket_path):
                os.environ["DOCKER_HOST"] = f"unix://{socket_path}"
                default_logger.info(f"自动检测到 Docker socket: {socket_path}")
                return
        
        default_logger.warning("未找到 Docker socket，将使用默认配置")
    
    @classmethod
    def get_instance(cls) -> 'DockerExecutor':
        """获取单例实例"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def _ensure_container(self):
        """确保容器存在并运行"""
        try:
            # 尝试获取现有容器
            try:
                container = self.client.containers.get(self.container_name)
                if container.status != "running":
                    default_logger.info(f"启动容器: {self.container_name}")
                    container.start()
                self._container = container
                return
            except docker.errors.NotFound:
                pass
            
            # 容器不存在，创建新容器
            default_logger.info(f"创建新容器: {self.container_name}")
            self._container = self.client.containers.run(
                self.image_name,
                name=self.container_name,
                detach=True,
                tty=True,
                stdin_open=True,
                command="/bin/bash",
                remove=False,
                network_mode="bridge"
            )
            
            # 安装必要的工具
            self._install_tools()
            
        except Exception as e:
            default_logger.error(f"容器管理失败: {e}")
            raise
    
    def _install_tools(self):
        """在容器中安装必要的工具"""
        tools_to_install = [
            "python3",
            "python3-pip",
            "curl",
            "wget",
            "nmap",
            "sqlmap",
            "nikto",
        ]
        
        default_logger.info("安装基础工具...")
        install_cmd = f"apt-get update && apt-get install -y {' '.join(tools_to_install)}"
        
        try:
            exec_result = self._container.exec_run(
                install_cmd,
                user="root"
            )
            if exec_result.exit_code != 0:
                default_logger.warning(f"工具安装可能失败: {exec_result.output.decode()}")
        except Exception as e:
            default_logger.warning(f"工具安装异常: {e}")
    
    def _exec_sync(self, command: str) -> Tuple[int, str]:
        """同步执行命令（内部方法）"""
        # 注意：Docker SDK的exec_run不支持timeout参数
        # 使用 /bin/bash -c 包装命令，确保 cd 等内置命令可用
        result = self._container.exec_run(
            ["/bin/bash", "-c", command],
            user="root"
        )
        return result.exit_code, result.output.decode('utf-8', errors='ignore')
    
    def execute(self, command: str, timeout: int = 120, workdir: str = "/workspace") -> str:
        """
        在Kali容器中执行命令（带超时控制）
        
        Args:
            command: 要执行的命令（如 nmap, sqlmap, curl 等）
            timeout: 超时时间（秒），默认 120 秒（sqlmap 等工具可能需要更长时间）
            workdir: 工作目录，默认 /workspace
        
        Returns:
            命令输出
        """
        if not self._container:
            self._ensure_container()
        
        try:
            default_logger.debug(f"执行命令: {command}")
            
            # 在指定工作目录执行命令（保持 Kali 工具的正常使用）
            full_command = f"cd {workdir} && {command}"
            
            # 使用线程池+asyncio实现真正的超时控制
            loop = asyncio.new_event_loop()
            try:
                future = loop.run_in_executor(_executor_pool, self._exec_sync, full_command)
                exit_code, output = loop.run_until_complete(
                    asyncio.wait_for(asyncio.wrap_future(future), timeout=timeout)
                )
            except asyncio.TimeoutError:
                default_logger.warning(f"命令执行超时 ({timeout}s): {command}")
                return f"Error: Command timed out after {timeout} seconds"
            finally:
                loop.close()
            
            if exit_code != 0:
                default_logger.warning(f"命令执行失败 (exit_code={exit_code}): {command}")
            
            return output
        
        except asyncio.TimeoutError:
            error_msg = f"命令执行超时 ({timeout}s): {command}"
            default_logger.warning(error_msg)
            return f"Error: {error_msg}"
        except Exception as e:
            error_msg = f"命令执行异常: {str(e)}"
            default_logger.error(error_msg)
            return error_msg
    
    async def execute_async(self, command: str, timeout: int = 60, workdir: str = "/workspace") -> str:
        """
        异步执行Kali命令
        
        Args:
            command: 要执行的命令（如 nmap, sqlmap, curl 等）
            timeout: 超时时间（秒）
            workdir: 工作目录，默认 /workspace
        
        Returns:
            命令输出
        """
        if not self._container:
            self._ensure_container()
        
        try:
            default_logger.debug(f"[异步] 执行命令: {command}")
            
            # 在指定工作目录执行命令
            full_command = f"cd {workdir} && {command}"
            loop = asyncio.get_event_loop()
            
            try:
                exit_code, output = await asyncio.wait_for(
                    loop.run_in_executor(_executor_pool, self._exec_sync, full_command),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                default_logger.warning(f"命令执行超时 ({timeout}s): {command}")
                return f"Error: Command timed out after {timeout} seconds"
            
            if exit_code != 0:
                default_logger.warning(f"命令执行失败 (exit_code={exit_code}): {command}")
            
            return output
        
        except Exception as e:
            error_msg = f"命令执行异常: {str(e)}"
            default_logger.error(error_msg)
            return error_msg
    
    # 持久化会话脚本路径
    _SESSION_SCRIPT = "/tmp/shadowagent_session.py"
    _SESSION_INITIALIZED = False
    
    def _init_python_session(self):
        """初始化 Python 持久化会话脚本"""
        if DockerExecutor._SESSION_INITIALIZED:
            return
        
        # 创建空的会话脚本
        self.execute(f"echo '# ShadowAgent Python Session' > {self._SESSION_SCRIPT}", timeout=5)
        DockerExecutor._SESSION_INITIALIZED = True
        default_logger.info("Python 持久化会话已初始化")
    
    def execute_python(self, code: str, timeout: int = 60) -> str:
        """
        在容器中执行Python代码（持久化会话，共享变量和函数）
        
        所有代码会追加到会话脚本中，每次执行整个脚本。
        使用特殊标记来只输出本次执行的结果。
        
        Args:
            code: Python代码字符串
            timeout: 超时时间（秒）
        
        Returns:
            代码执行输出
        """
        import base64
        
        # 确保会话初始化
        self._init_python_session()
        
        # 生成唯一标记
        marker_start = f"__START_{uuid.uuid4().hex[:8]}__"
        marker_end = f"__END_{uuid.uuid4().hex[:8]}__"
        
        # 包装用户代码，添加输出标记
        wrapped_code = f'''
print("{marker_start}")
{code}
print("{marker_end}")
'''
        
        # 编码并追加到会话脚本
        code_b64 = base64.b64encode(wrapped_code.encode('utf-8')).decode('utf-8')
        
        # 追加代码到会话脚本，执行整个脚本，提取本次输出
        command = f"""
echo '{code_b64}' | base64 -d >> {self._SESSION_SCRIPT}
python3 {self._SESSION_SCRIPT} 2>&1 | sed -n '/{marker_start}/,/{marker_end}/p' | grep -v '{marker_start}' | grep -v '{marker_end}'
"""
        
        return self.execute(command.strip(), timeout=timeout)
    
    def reset_python_session(self) -> str:
        """
        重置 Python 会话（清空所有代码和变量）
        
        Returns:
            操作结果
        """
        DockerExecutor._SESSION_INITIALIZED = False
        command = f"rm -f {self._SESSION_SCRIPT} && echo 'Python session reset'"
        return self.execute(command, timeout=10)
    
    async def execute_python_async(self, code: str, timeout: int = 60) -> str:
        """
        异步执行Python代码（持久化会话）
        
        Args:
            code: Python代码字符串
            timeout: 超时时间（秒）
        
        Returns:
            代码执行输出
        """
        import base64
        
        # 确保会话初始化
        self._init_python_session()
        
        marker_start = f"__START_{uuid.uuid4().hex[:8]}__"
        marker_end = f"__END_{uuid.uuid4().hex[:8]}__"
        
        wrapped_code = f'''
print("{marker_start}")
{code}
print("{marker_end}")
'''
        
        code_b64 = base64.b64encode(wrapped_code.encode('utf-8')).decode('utf-8')
        
        command = f"""
echo '{code_b64}' | base64 -d >> {self._SESSION_SCRIPT}
python3 {self._SESSION_SCRIPT} 2>&1 | sed -n '/{marker_start}/,/{marker_end}/p' | grep -v '{marker_start}' | grep -v '{marker_end}'
"""
        
        return await self.execute_async(command.strip(), timeout=timeout)
    
    def cleanup(self):
        """清理容器（可选）"""
        if self._container:
            try:
                self._container.stop()
                default_logger.info("容器已停止")
            except Exception as e:
                default_logger.warning(f"停止容器失败: {e}")

