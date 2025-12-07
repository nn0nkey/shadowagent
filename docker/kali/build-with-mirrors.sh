#!/bin/bash
# H-Pentest Kali镜像构建脚本 - 支持选择镜像源

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

# 可选的镜像源
MIRROR_SOURCES=("tsinghua" "aliyun" "ustc" "huawei" "163" "official")
DEFAULT_MIRROR="tsinghua"  # 清华源通常最稳定

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

# 显示使用帮助
show_help() {
    echo "用法: $0 [选项] [export]"
    echo ""
    echo "选项:"
    echo "  -m, --mirror SOURCE    选择镜像源 (可选: ${MIRROR_SOURCES[*]})"
    echo "  -h, --help             显示帮助信息"
    echo ""
    echo "镜像源说明:"
    echo "  tsinghua   - 清华大学镜像源 (默认，推荐)"
    echo "  aliyun     - 阿里云镜像源"
    echo "  ustc       - 中科大镜像源"
    echo "  huawei     - 华为云镜像源"
    echo "  163        - 网易镜像源"
    echo "  official   - Kali官方源"
    echo ""
    echo "示例:"
    echo "  $0                         # 使用默认源(tsinghua)构建"
    echo "  $0 -m aliyun               # 使用阿里源构建"
    echo "  $0 -m huawei export        # 使用华为源构建并导出"
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
    local mirror=$1
    
    print_info "开始构建Kali镜像: ${FULL_IMAGE_NAME}"
    print_info "使用镜像源: ${mirror}"
    
    # 使用支持镜像源的Dockerfile
    docker build \
        --build-arg MIRROR_SOURCE="${mirror}" \
        --tag "${FULL_IMAGE_NAME}" \
        --file "${DOCKERFILE_DIR}/Dockerfile-with-mirrors" \
        "${DOCKERFILE_DIR}"
    
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

# 主函数
main() {
    local mirror="${DEFAULT_MIRROR}"
    local export_flag=""
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -m|--mirror)
                mirror="$2"
                if [[ ! " ${MIRROR_SOURCES[*]} " =~ " ${mirror} " ]]; then
                    print_error "无效的镜像源: ${mirror}"
                    print_info "可用镜像源: ${MIRROR_SOURCES[*]}"
                    exit 1
                fi
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            export)
                export_flag="export"
                shift
                ;;
            *)
                print_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    echo "🚀 H-Pentest Kali镜像构建开始"
    echo "========================================"
    echo ""
    
    # 创建日志目录
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # 检查Docker
    check_docker
    
    # 构建镜像
    build_image "${mirror}"
    
    # 验证镜像
    verify_image
    
    # 测试容器
    test_container
    
    # 导出镜像
    export_image "${export_flag}"
    
    print_success "构建完成！"
    print_info "镜像名称: ${FULL_IMAGE_NAME}"
    print_info "使用方法: docker run -it ${FULL_IMAGE_NAME}"
    echo ""
    print_info "如果需要重新构建并选择其他镜像源:"
    print_info "  $0 -m tsinghua    # 使用清华源"
    print_info "  $0 -m ustc        # 使用中科大源"
    print_info "  $0 -m official    # 使用官方源"
}

# 执行主函数
main "$@"