在mac上有src.rpm解包的需求，又不想污染开发环境，考虑用docker内的容器进行解包，同时把解包后的文件拿出来。
创建一个文件夹 fedora-rpm-tools写入Dockerfile


```
# 使用官方的 Fedora 镜像作为基础
FROM fedora:latest

# 步骤 1: 更新系统并安装 dnf5 的 group 命令插件
RUN dnf -y upgrade --refresh && \
    dnf -y install 'dnf5-command(group)'

# 步骤 2: 使用正确的组ID "development-tools" 来安装开发工具集
RUN dnf -y group install "development-tools"

# 步骤 3: 安装其他非常常见的开发库和工具
RUN dnf -y install \
      cmake \
      openssl-devel \
      zlib-devel \
      pcre-devel \
      pcre2-devel \
      libcurl-devel \
      libxml2-devel \
      apr-devel \
      apr-util-devel \
      systemd-devel \
      lua-devel \
      brotli-devel \
      jansson-devel \
      libselinux-devel \
      perl-generators && \
    # 清理缓存，减小最终镜像的体积
    dnf clean all

# 设置一个环境变量，方便以后查看镜像版本
ENV FEDORA_TOOLS_VERSION="2025-08-05"
```
然后用docker 来构建
```
docker build -t fedora-rpm-tools .
```

<img width="1818" height="520" alt="Image" src="https://github.com/user-attachments/assets/8353c91a-8930-459f-9d2d-6bf63e723d9d" />

编写一个脚本实现在容器内build,并将解包后的文件夹移出来
```
#!/bin/bash

# --- unrpm.sh ---
# 用法：./unrpm.sh /path/to/your-package.src.rpm

# 检查是否提供了文件路径参数
if [ -z "$1" ]; then
  echo "错误: 请提供 src.rpm 文件的路径。"
  echo "用法: $0 /path/to/your-package.src.rpm"
  exit 1
fi

# 检查文件是否存在
if [ ! -f "$1" ]; then
  echo "错误: 文件 '$1' 不存在。"
  exit 1
fi

# 从完整路径中获取工作目录和文件名
SRC_RPM_PATH=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
WORK_DIR=$(dirname "$SRC_RPM_PATH")
RPM_FILE=$(basename "$SRC_RPM_PATH")

echo "=================================================="
echo "正在处理文件: $RPM_FILE"
echo "工作目录: $WORK_DIR"
echo "=================================================="

# 使用我们预先构建好的本地镜像 fedora-rpm-tools
docker run --rm -v "$WORK_DIR:/work" fedora-rpm-tools sh -c '
  set -e

  echo "--> 1/4: 工具已预装，跳过安装步骤。"

  echo "--> 2/4: 正在安装 src.rpm 包..."
  rpm -i "/work/'"$RPM_FILE"'" >/dev/null 2>&1 # 将警告信息重定向，保持界面干净

  echo "--> 3/4: 正在查找 .spec 文件并应用补丁 (忽略依赖)..."
  SPEC_FILE=$(find ~/rpmbuild/SPECS -type f -name "*.spec")
  if [ -z "$SPEC_FILE" ]; then echo "错误：在 src.rpm 中未找到 .spec 文件。"; exit 1; fi
  
  # 核心改动：增加了 --nodeps 来跳过构建依赖检查
  rpmbuild -bp --nodeps "$SPEC_FILE"

  echo "--> 4/4: 正在查找并移动源码目录..."
  BUILD_DIR=$(find ~/rpmbuild/BUILD -mindepth 1 -maxdepth 1 -type d)
  if [ -z "$BUILD_DIR" ]; then echo "错误：未能找到构建目录。"; exit 1; fi
  OUTPUT_DIR_NAME="$(basename "$BUILD_DIR")_patched"
  mv "$BUILD_DIR" "/work/$OUTPUT_DIR_NAME"

  echo "=================================================="
  echo "✅ 处理完成！源码文件夹: $OUTPUT_DIR_NAME"
  echo "=================================================="
'

# 检查 Docker 命令是否成功执行
if [ $? -eq 0 ]; then
  echo "🎉 成功！请检查目录: $WORK_DIR"
else
  echo "❌ 处理失败。请检查上面的 Docker 输出信息。"
fi
```
简单来说通过 Docker 动态创建一个隔离且纯净的 Linux 环境，在此环境中自动执行源码解包、补丁应用。
可以自行将脚本添加进环境变量，传入src.rpm路径后将自动移动源码文件夹到该路径。

<img width="1810" height="872" alt="Image" src="https://github.com/user-attachments/assets/95f49b05-5364-4a82-a154-256d2e9d67da" />