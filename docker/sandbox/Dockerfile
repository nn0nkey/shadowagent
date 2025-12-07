FROM python:3.11-slim

# 🔥 配置APT清华源
RUN sed -i 's/deb.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list.d/debian.sources && \
    sed -i 's/security.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list.d/debian.sources

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    curl \
    wget \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# 🔥 配置PIP清华源
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

# 🔥 分阶段安装渗透测试库（避免依赖冲突）
# 第一阶段：核心HTTP和解析库
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir \
    requests httpx aiohttp urllib3 \
    beautifulsoup4 lxml html5lib \
    pyyaml pycryptodome cryptography \
    pyjwt chardet

# 第二阶段：Web框架和工具
RUN pip install --no-cache-dir \
    flask jinja2 \
    pymysql redis \
    python-dateutil pytz \
    colorama tqdm click \
    validators

# 第三阶段：网络和渗透工具
RUN pip install --no-cache-dir \
    websocket-client pysocks \
    pillow

# 创建工作目录
WORKDIR /sandbox

# 🔥 非root用户执行（增加安全性）
RUN useradd -m -u 1000 sandbox && chown -R sandbox:sandbox /sandbox
USER sandbox

# 设置环境变量
ENV PYTHONUNBUFFERED=1
ENV PYTHONIOENCODING=utf-8

CMD ["python3"]