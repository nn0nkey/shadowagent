#!/bin/bash
# H-Pentest Kali镜像构建脚本

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 配置
IMAGE_NAME="h-pentest/kali"
IMAGE_TAG="latest"
FULL_IMAGE_NAME="${IMAGE_NAME}:${IMAGE_TAG}"
DOCKERFILE_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$DOCKERFILE_DIR/../.." && pwd)"
LOG_FILE="$PROJECT_ROOT/logs/kali_build.log"

# 日志函数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# 检查Docker
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker未安装或不在PATH中"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        print_error "无法连接到Docker守护进程"
        exit 1
    fi
    
    print_success "Docker检查通过"
}

# 构建镜像
build_image() {
    print_info "开始构建Kali镜像: ${FULL_IMAGE_NAME}"
    
    # 使用buildx构建以支持多平台
    if docker buildx version &> /dev/null; then
        print_info "使用buildx构建"
        # 修复：只构建当前平台，避免多平台导出问题
        docker buildx build \
            --tag "${FULL_IMAGE_NAME}" \
            --file "${DOCKERFILE_DIR}/Dockerfile" \
            "${DOCKERFILE_DIR}" \
            --load
    else
        print_info "使用传统方式构建"
        docker build \
            --tag "${FULL_IMAGE_NAME}" \
            --file "${DOCKERFILE_DIR}/Dockerfile" \
            "${DOCKERFILE_DIR}"
    fi
    
    log "镜像构建完成"
}

# 验证镜像
verify_image() {
    print_info "验证镜像..."
    
    # 检查镜像是否存在
    if ! docker image inspect "${FULL_IMAGE_NAME}" &> /dev/null; then
        print_error "镜像验证失败: 镜像不存在"
        exit 1
    fi
    
    # 获取镜像信息
    IMAGE_SIZE=$(docker image inspect "${FULL_IMAGE_NAME}" --format='{{.Size}}' | numfmt --to=iec-i --suffix=B)
    IMAGE_ID=$(docker image inspect "${FULL_IMAGE_NAME}" --format='{{.Id}}' | cut -d: -f2 | cut -c1-12)
    
    print_success "镜像验证通过"
    print_info "  镜像ID: ${IMAGE_ID}"
    print_info "  镜像大小: ${IMAGE_SIZE}"
}

# 运行测试容器
test_container() {
    print_info "运行测试容器..."
    
    TEST_CONTAINER="kali-test-$(date +%s)"
    
    # 启动容器
    docker run --rm -d \
        --name "${TEST_CONTAINER}" \
        "${FULL_IMAGE_NAME}" \
        sleep 30
    
    # 等待容器启动
    sleep 5
    
    # 测试命令
    if docker exec "${TEST_CONTAINER}" which nmap &> /dev/null; then
        print_success "✓ nmap 安装成功"
    else
        print_error "✗ nmap 未找到"
    fi
    
    if docker exec "${TEST_CONTAINER}" which nikto &> /dev/null; then
        print_success "✓ nikto 安装成功"
    else
        print_error "✗ nikto 未找到"
    fi
    
    if docker exec "${TEST_CONTAINER}" which gobuster &> /dev/null; then
        print_success "✓ gobuster 安装成功"
    else
        print_error "✗ gobuster 未找到"
    fi
    
    if docker exec "${TEST_CONTAINER}" which hydra &> /dev/null; then
        print_success "✓ hydra 安装成功"
    else
        print_error "✗ hydra 未找到"
    fi
    
    # Python环境测试
    if docker exec "${TEST_CONTAINER}" python3 -c "import pwntools" 2>/dev/null; then
        print_success "✓ pwntools 安装成功"
    else
        print_error "✗ pwntools 未找到"
    fi
    
    # 清理测试容器
    docker stop "${TEST_CONTAINER}" &> /dev/null || true
    
    print_info "容器测试完成"
}

# 导出镜像（可选）
export_image() {
    if [ "${1}" = "export" ]; then
        print_info "导出镜像到文件..."
        EXPORT_FILE="${PROJECT_ROOT}/h-pentest-kali-${IMAGE_TAG}.tar"
        
        docker save "${FULL_IMAGE_NAME}" -o "${EXPORT_FILE}"
        
        EXPORT_SIZE=$(du -h "${EXPORT_FILE}" | cut -f1)
        print_info "镜像已导出到: ${EXPORT_FILE} (${EXPORT_SIZE})"
    fi
}

# 生成镜像信息
generate_info() {
    print_info "生成镜像信息..."
    
    cat > "${DOCKERFILE_DIR}/image-info.txt" << EOF
H-Pentest Kali镜像信息
========================

镜像名称: ${FULL_IMAGE_NAME}
构建时间: $(date)
构建主机: $(hostname)

预装工具:
- 网络: nmap, masscan, netcat, sslscan
- Web扫描: nikto, gobuster, dirb, wpscan, whatweb
- 密码攻击: hydra, john, hashcat
- 漏洞扫描: nuclei
- 漏洞利用: metasploit-framework
- 信息收集: amass, recon-ng, subfinder, theharvester
- 数据库: sqlmap
- 其他工具: yara, radare2, binwalk, exiftool
- Python库: pwntools, requests, beautifulsoup4

使用方法:
1. 加载镜像: docker load < h-pentest-kali.tar
2. 运行容器: docker run -it h-pentest/kali
3. 快速扫描: docker run h-pentest/kali quick-scan <target>

注意:
- 默认用户: pentester (UID:1000)
- 工作目录: /workspace
- 包含快速扫描脚本: quick-scan
EOF
    
    print_info "镜像信息已保存到: ${DOCKERFILE_DIR}/image-info.txt"
}

# 主函数
main() {
    echo "🚀 H-Pentest Kali镜像构建开始"
    print_header
    echo ""
    
    # 创建日志目录
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # 检查Docker
    check_docker
    
    # 创建临时目录（如果需要）
    mkdir -p "${DOCKERFILE_DIR}/scripts" 2>/dev/null || true
    
    # 构建镜像
    build_image
    
    # 验证镜像
    verify_image
    
    # 测试容器
    test_container
    
    # 导出镜像
    export_image "$1"
    
    # 生成信息
    generate_info
    
    print_header "构建完成"
    
    echo ""
    print_success "构建完成！"
    print_info "镜像名称: ${FULL_IMAGE_NAME}"
    print_info "使用方法: docker run -it ${FULL_IMAGE_NAME}"
}

# 帮助信息
help() {
    echo "用法: $0 [export]"
    echo ""
    echo "选项:"
    echo "  export   构建后导出镜像到tar文件"
    echo ""
    echo "示例:"
    echo "  $0              # 仅构建镜像"
    echo "  $0 export       # 构建并导出镜像"
}

# 帮助信息函数
print_header() {
    echo ""
    echo "========================================"
    echo "  $1"
    echo "========================================"
}

# 执行主函数
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    help
    exit 0
fi

main "$@"