FROM ubuntu:22.04

# 安装依赖: masscan 需要编译，prips 在 iprange 包里
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential libpcap-dev \
    iprange python3 python3-pip curl iproute2 \
    && rm -rf /var/lib/apt/lists/*

# 手动编译 masscan (apt 里的版本太老)
RUN git clone --depth 1 https://github.com/robertdavidgraham/masscan /tmp/masscan \
    && cd /tmp/masscan && make -j$(nproc) \
    && cp bin/masscan /usr/local/bin/ \
    && rm -rf /tmp/masscan

# 复制 ASNIPtest 项目
COPY . /opt/ASNIPtest/
WORKDIR /opt/ASNIPtest

# cf-scanner 加执行权限
RUN chmod +x cf-scanner 2>/dev/null; true

ENTRYPOINT ["python3", "run.py"]
