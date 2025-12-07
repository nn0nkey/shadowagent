#!/bin/bash
# Kali容器启动脚本 - Root权限版本

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 打印欢迎信息
print_welcome() {
    echo -e "${RED}"
    echo "=========================================="
    echo "  H-Pentest Kali Container (ROOT)"
    echo "  Version: 2.0.0"
    echo "  User: root (超级权限)"
    echo "  Working Directory: /workspace"
    echo "=========================================="
    echo -e "${NC}"
}

# 初始化工作空间
init_workspace() {
    echo -e "${YELLOW}[INFO]${NC} Initializing workspace with full permissions..."
    
    # 创建工作目录结构
    mkdir -p /workspace/{scans,exploits,loot,reports,temp,logs,tools,sessions}
    
    # 设置最大权限
    chmod -R 777 /workspace
    
    # 创建健康检查文件
    touch /workspace/.health
    chmod 777 /workspace/.health
    
    # 创建自定义工具目录
    mkdir -p /root/.local/bin
    chmod -R 777 /root/.local
    
    echo -e "${GREEN}[SUCCESS]${NC} Workspace initialized with full permissions"
}

# 检查工具可用性
check_tools() {
    echo -e "${YELLOW}[INFO]${NC} Checking essential tools..."
    
    tools=("nmap" "nikto" "gobuster" "hydra" "sqlmap" "msfconsole" "metasploit-framework")
    available=0
    total=${#tools[@]}
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "${GREEN}[OK]${NC} $tool is available"
            ((available++))
        else
            echo -e "${RED}[MISSING]${NC} $tool is not available"
        fi
    done
    
    echo -e "${BLUE}[SUMMARY]${NC} $available/$total essential tools are available"
}

# 设置环境变量
setup_env() {
    export TERM=xterm-256color
    export HISTFILE=/workspace/.bash_history
    export HISTSIZE=10000
    export HISTCONTROL=ignoredups:erasedups
    export EDITOR=nano
    export PAGER=less
    
    # 添加PATH
    export PATH=$PATH:/opt/tools:/root/.local/bin
    
    # 设置红色提示符（标识root）
    echo 'export PS1="\[\033[01;31m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\\$ "' >> ~/.bashrc
    
    # 设置别名
    echo "alias ll='ls -la'" >> ~/.bashrc
    echo "alias la='ls -la'" >> ~/.bashrc
    echo "alias l='ls -l'" >> ~/.bashrc
    echo "alias ..='cd ..'" >> ~/.bashrc
    echo "alias ...='cd ../..'" >> ~/.bashrc
    echo "alias grep='grep --color=auto'" >> ~/.bashrc
    
    # 禁用安全警告
    echo 'export PYTHONWARNINGS="ignore"' >> ~/.bashrc
}

# 创建快捷功能
create_shortcuts() {
    echo -e "${YELLOW}[INFO]${NC} Creating shortcut functions..."
    
    cat >> ~/.bashrc << 'EOF'

# 快捷扫描函数
quick-scan() {
    if [ -z "$1" ]; then
        echo "Usage: quick-scan <target>"
        return 1
    fi
    /root/.local/bin/quick-scan "$1"
}

# 快速端口扫描
quick-port() {
    if [ -z "$1" ]; then
        echo "Usage: quick-port <target>"
        return 1
    fi
    echo "Scanning ports on $1..."
    nmap -sS -T4 --open -Pn --min-rate=1000 "$1"
}

# 快速Web扫描
quick-web() {
    if [ -z "$1" ]; then
        echo "Usage: quick-web <target>"
        return 1
    fi
    echo "Web scanning $1..."
    nikto -h "http://$1"
}

# 设置C2监听器
setup-c2() {
    local port=${1:-4444}
    local lhost=${2:-0.0.0.0}
    echo "Setting up C2 listener on port $port..."
    msfconsole -q -x "use exploit/multi/handler; set payload linux/x86/meterpreter/reverse_tcp; set LHOST $lhost; set LPORT $port; exploit"
}

# 进入工作目录
cdws() {
    cd /workspace
}

# 清理临时文件
cleanup() {
    rm -rf /workspace/temp/* /workspace/logs/*
    echo "Cleanup complete"
}

EOF
}

# 主函数
main() {
    # 保持root用户，不切换
    
    # 执行初始化
    print_welcome
    setup_env
    init_workspace
    check_tools
    create_shortcuts
    
    echo -e "${RED}"
    echo "🚀 H-Pentest Kali容器已就绪！(ROOT权限)"
    echo ""
    echo "快捷命令:"
    echo "  quick-scan <target>    - 快速综合扫描"
    echo "  quick-port <target>    - 快速端口扫描"
    echo "  quick-web <target>     - Web漏洞扫描"
    echo "  setup-c2 <port>        - 设置C2监听器"
    echo "  cdws                   - 进入工作目录"
    echo "  cleanup                - 清理临时文件"
    echo ""
    echo "工作目录: /workspace"
    echo "=================================="
    echo -e "${NC}"
    
    # 进入工作目录
    cd /workspace
    
    # 如果有参数，执行命令
    if [ $# -gt 0 ]; then
        echo -e "${YELLOW}[INFO]${NC} Executing: $*"
        exec "$@"
    else
        # 否则启动交互式shell
        exec /bin/bash
    fi
}

# 执行主函数
main "$@"