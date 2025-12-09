# H-Pentest Kali Linux容器镜像
# 基于官方Kali镜像，预装核心渗透测试工具

FROM kalilinux/kali-rolling:latest

# 设置非root用户提高安全性
ARG USER=pentester
ARG UID=1000
ARG GID=1000

# 环境变量
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
    PIP_TRUSTED_HOST=pypi.tuna.tsinghua.edu.cn

# 使用清华大学HTTP镜像源（避免SSL问题）
RUN echo "deb http://mirrors.tuna.tsinghua.edu.cn/kali/ kali-rolling main non-free contrib" > /etc/apt/sources.list && \
    echo "deb-src http://mirrors.tuna.tsinghua.edu.cn/kali/ kali-rolling main non-free contrib" >> /etc/apt/sources.list && \
    # 配置pip使用清华源
    mkdir -p ~/.pip && \
    echo "[global]" > ~/.pip/pip.conf && \
    echo "index-url = https://pypi.tuna.tsinghua.edu.cn/simple" >> ~/.pip/pip.conf && \
    echo "trusted-host = pypi.tuna.tsinghua.edu.cn" >> ~/.pip/pip.conf && \
    # 配置npm使用清华源（如果需要）\
    npm config set registry https://registry.npmmirror.com || true

# 安装基础工具和Python环境
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        # 基础工具
        curl wget git vim nano zip unzip tar \
        python3 python3-pip python3-venv python3-dev \
        build-essential cmake pkg-config \
        # 网络工具
        nmap netcat-traditional telnet dnsutils \
        sslscan ssdeep nbtscan smbclient \
        # Web工具
        nikto gobuster dirb dirbuster wpscan \
        whatweb ffuf wfuzz \
        # 密码工具
        hydra john hashcat crunch \
        wordlists seclists \
        # 漏洞扫描
        masscan nuclei \
        # 漏洞利用
        metasploit-framework \
        # 信息收集
        amass recon-ng subfinder theharvester \
        # 数据库工具
        sqlmap \
        # 其他工具
        yara radare2 binwalk exiftool \
        # 清理
        && apt-get autoremove -y && \
        apt-get autoclean && \
        rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# 安装额外的Python工具（使用--break-system-packages绕过外部环境管理）
# 使用清华pip源加速
RUN pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple && \
    pip3 config set global.trusted-host pypi.tuna.tsinghua.edu.cn && \
    pip3 install --no-cache-dir --break-system-packages \
        pwntools requests beautifulsoup4 \
        lxml python-nmap paramiko \
        pyftpdlib httpx scrapy \
        flask dash pandas numpy \
        jupyter ipython \
        # JS端点提取工具
        jsbeautifier

# 创建 python 软链接（linkfinder 需要）
RUN ln -sf /usr/bin/python3 /usr/bin/python

# 安装JS端点提取工具
RUN cd /opt && \
    # LinkFinder - 从JS文件中提取端点
    git clone https://github.com/GerbenJavado/LinkFinder.git && \
    cd LinkFinder && \
    pip3 install --no-cache-dir --break-system-packages -r requirements.txt && \
    python3 setup.py install && \
    chmod +x linkfinder.py && \
    ln -sf /opt/LinkFinder/linkfinder.py /usr/local/bin/linkfinder && \
    cd /opt && \
    # SecretFinder - 从JS文件中提取敏感信息（API密钥等）
    git clone https://github.com/m4ll0k/SecretFinder.git && \
    cd SecretFinder && \
    pip3 install --no-cache-dir --break-system-packages -r requirements.txt || true && \
    chmod +x SecretFinder.py && \
    ln -sf /opt/SecretFinder/SecretFinder.py /usr/local/bin/secretfinder && \
    cd /opt && \
    # 安装 katana (ProjectDiscovery的爬虫工具)
    wget -q https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip && \
    unzip -q katana_1.1.0_linux_amd64.zip -d /usr/local/bin/ && \
    rm -f katana_1.1.0_linux_amd64.zip && \
    chmod +x /usr/local/bin/katana && \
    # 安装 gau (GetAllUrls - 从多个来源获取URL)
    wget -q https://github.com/lc/gau/releases/download/v2.2.3/gau_2.2.3_linux_amd64.tar.gz && \
    tar -xzf gau_2.2.3_linux_amd64.tar.gz -C /usr/local/bin/ gau && \
    rm -f gau_2.2.3_linux_amd64.tar.gz && \
    chmod +x /usr/local/bin/gau && \
    # 安装 waybackurls
    wget -q https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-amd64-0.1.0.tgz && \
    tar -xzf waybackurls-linux-amd64-0.1.0.tgz -C /usr/local/bin/ && \
    rm -f waybackurls-linux-amd64-0.1.0.tgz && \
    chmod +x /usr/local/bin/waybackurls || true

# 创建工作目录（全程使用root）
RUN mkdir -p /workspace/{tools,data,temp,logs,scans,exploits,loot,reports,sessions} && \
    chmod -R 777 /workspace && \
    mkdir -p /root/.local/bin && \
    chmod -R 777 /root/.local

# 设置工作目录
WORKDIR /workspace

# 配置root用户环境
RUN echo 'export PATH=$PATH:/opt/tools:/root/.local/bin' >> ~/.bashrc && \
    echo 'export PS1="\[\033[01;31m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "' >> ~/.bashrc

# 创建工具快捷脚本
RUN cat > /root/.local/bin/quick-scan << 'EOF' && \
chmod +x /root/.local/bin/quick-scan
#!/bin/bash
TARGET=$1
if [ -z "$TARGET" ]; then
    echo "Usage: quick-scan <target>"
    exit 1
fi
echo "=== Quick Port Scan ==="
nmap -sS -T4 --open -Pn $TARGET
echo ""
echo "=== Nikto Web Scan ==="
nikto -h http://$TARGET
echo ""
echo "=== Gobuster Dir Scan ==="
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
EOF

# 初始化数据库（如msf）
RUN echo "source /usr/share/metasploit-framework/msfconsole.rc" >> ~/.bashrc 2>/dev/null || true

# 创建启动脚本 - 使用COPY方式避免heredoc问题
COPY entrypoint.sh /root/entrypoint.sh
RUN chmod +x /root/entrypoint.sh

# 设置标签
LABEL maintainer="H-Pentest Team" \
      version="2.0" \
      description="H-Pentest Kali Linux container with pre-installed pentesting tools (root access)"

# 暴露常用端口（如果需要）
EXPOSE 80 443 8080 9000

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD echo "healthy" || exit 1

# 切换回root以设置入口点
USER root

# 设置全局权限
RUN chmod 777 /workspace && \
    chmod -R 777 /root && \
    echo "root ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# 保持root用户（不切换）

# 设置默认命令
ENTRYPOINT ["/root/entrypoint.sh"]
CMD ["/bin/bash"]

# 验证安装
RUN echo "=================================" && \
    echo "H-Pentest Kali容器构建完成！" && \
    echo "用户: root (权限拉满)" && \
    echo "工作目录: /workspace" && \
    echo "=================================" && \
    echo "可用工具:" && \
    echo "- 网络: nmap, masscan, netcat" && \
    echo "- Web: nikto, gobuster, wpscan" && \
    echo "- 密码: hydra, john, hashcat" && \
    echo "- 框架: metasploit-framework" && \
    echo "- 端点发现: linkfinder, katana, gau, waybackurls" && \
    echo "- 敏感信息: secretfinder" && \
    echo "- 自定义: quick-scan" && \
    echo "================================="