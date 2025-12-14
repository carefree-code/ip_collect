#!/bin/bash
#
# IP威胁收集分析服务 - 安装脚本
# 支持: CentOS/RHEL, Ubuntu/Debian, 宝塔环境
#
# 作者: sinma
# 网站: https://www.carefreecode.com/
# QQ: 42033223
# 版本: 1.0.0
#

set -e

# 版本信息
VERSION="1.0.0"
AUTHOR="sinma"
WEBSITE="https://www.carefreecode.com/"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 最低 Python 版本要求
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=7

# 安装目录
INSTALL_DIR="/www/server/ipcollect"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  IP威胁收集分析服务 - 安装脚本${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${CYAN}  版本: ${VERSION}${NC}"
echo -e "${CYAN}  作者: ${AUTHOR}${NC}"
echo -e "${CYAN}  网站: ${WEBSITE}${NC}"
echo -e "${GREEN}========================================${NC}"
echo

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}请使用root权限运行此脚本${NC}"
    exit 1
fi

#==============================================================================
# 检测系统环境
#==============================================================================
detect_environment() {
    echo -e "${YELLOW}[1/7] 检测系统环境${NC}"

    # 检测系统类型
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$ID
        OS_VERSION=$VERSION_ID
        OS_NAME=$PRETTY_NAME
    elif [ -f /etc/redhat-release ]; then
        OS_ID="centos"
        OS_NAME=$(cat /etc/redhat-release)
    elif [ -f /etc/debian_version ]; then
        OS_ID="debian"
        OS_VERSION=$(cat /etc/debian_version)
        OS_NAME="Debian $OS_VERSION"
    else
        OS_ID="unknown"
        OS_NAME="Unknown"
    fi

    # 检测是否有宝塔环境
    HAS_BT_PANEL=false
    BT_PYTHON=""
    if [ -d "/www/server/panel" ]; then
        HAS_BT_PANEL=true
        # 查找宝塔 Python 环境
        for p in /www/server/pyporject_evn/versions/*/bin/python3; do
            if [ -x "$p" ] 2>/dev/null; then
                version=$("$p" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
                major=$(echo $version | cut -d. -f1)
                minor=$(echo $version | cut -d. -f2)
                if [ "$major" -ge "$MIN_PYTHON_MAJOR" ] && [ "$minor" -ge "$MIN_PYTHON_MINOR" ]; then
                    BT_PYTHON="$p"
                    break
                fi
            fi
        done
    fi

    # 检测是否需要虚拟环境 (PEP 668)
    NEED_VENV=false
    if [ -f /usr/lib/python3*/EXTERNALLY-MANAGED ] 2>/dev/null || \
       [ -f /usr/lib/python3/EXTERNALLY-MANAGED ] 2>/dev/null; then
        NEED_VENV=true
    fi

    # 检测包管理器
    PKG_MANAGER=""
    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
    fi

    # 输出检测结果
    echo -e "  系统: ${BLUE}$OS_NAME${NC}"
    echo -e "  包管理器: ${BLUE}${PKG_MANAGER:-未知}${NC}"
    echo -e "  宝塔面板: ${BLUE}$([ "$HAS_BT_PANEL" = true ] && echo "已安装" || echo "未安装")${NC}"
    echo -e "  需要虚拟环境: ${BLUE}$([ "$NEED_VENV" = true ] && echo "是 (PEP 668)" || echo "否")${NC}"
    echo
}

#==============================================================================
# 查找符合要求的最佳 Python
#==============================================================================
find_best_python() {
    local best_python=""
    local best_version="0.0"

    # Python 搜索路径（按优先级排序）
    local python_paths=(
        # 宝塔 Python 环境（优先）
        /www/server/pyporject_evn/versions/*/bin/python3
        # 系统版本（从高到低）
        /usr/bin/python3.12
        /usr/bin/python3.11
        /usr/bin/python3.10
        /usr/bin/python3.9
        /usr/bin/python3.8
        /usr/bin/python3.7
        /usr/bin/python3
        /usr/local/bin/python3.12
        /usr/local/bin/python3.11
        /usr/local/bin/python3.10
        /usr/local/bin/python3.9
        /usr/local/bin/python3.8
        /usr/local/bin/python3.7
        /usr/local/bin/python3
        # pyenv
        ~/.pyenv/versions/*/bin/python3
        /root/.pyenv/versions/*/bin/python3
        # Anaconda/Miniconda
        /opt/anaconda3/bin/python3
        /opt/miniconda3/bin/python3
        ~/anaconda3/bin/python3
        ~/miniconda3/bin/python3
    )

    for python_path in ${python_paths[@]}; do
        for p in $python_path; do
            if [ -x "$p" ] 2>/dev/null; then
                version=$("$p" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
                if [ -n "$version" ] && [ "$version" != "0.0" ]; then
                    major=$(echo $version | cut -d. -f1)
                    minor=$(echo $version | cut -d. -f2)

                    if [ "$major" -ge "$MIN_PYTHON_MAJOR" ] && [ "$minor" -ge "$MIN_PYTHON_MINOR" ]; then
                        if [ "$(printf '%s\n' "$best_version" "$version" | sort -V | tail -n1)" = "$version" ]; then
                            if [ "$version" != "$best_version" ]; then
                                best_version=$version
                                best_python=$p
                            fi
                        fi
                    fi
                fi
            fi
        done
    done

    echo "$best_python"
}

#==============================================================================
# 安装系统依赖
#==============================================================================
install_system_deps() {
    echo -e "${YELLOW}[3/7] 检查系统依赖${NC}"

    case "$PKG_MANAGER" in
        apt)
            # Debian/Ubuntu 系统
            local packages_needed=""

            # 检查 python3-venv
            if [ "$NEED_VENV" = true ]; then
                if ! dpkg -l | grep -q python3-venv 2>/dev/null; then
                    packages_needed="$packages_needed python3-venv"
                fi
                # 检查对应版本的 venv
                local py_minor=$("$PYTHON_PATH" -c "import sys; print(sys.version_info.minor)" 2>/dev/null)
                local venv_pkg="python3.${py_minor}-venv"
                if ! dpkg -l | grep -q "$venv_pkg" 2>/dev/null; then
                    packages_needed="$packages_needed $venv_pkg"
                fi
            fi

            if [ -n "$packages_needed" ]; then
                echo "安装依赖包: $packages_needed"
                apt-get update -qq 2>/dev/null || true
                # 安装依赖，忽略其他包的配置错误
                apt-get install -y $packages_needed 2>/dev/null || {
                    echo -e "${YELLOW}警告: apt 有错误，尝试继续...${NC}"
                    # 尝试单独安装每个包
                    for pkg in $packages_needed; do
                        apt-get install -y "$pkg" 2>/dev/null || true
                    done
                }
            else
                echo "系统依赖已满足"
            fi
            ;;

        yum|dnf)
            # CentOS/RHEL 系统
            # 通常不需要额外安装 venv，Python 自带
            echo "系统依赖已满足"
            ;;

        *)
            echo "未知包管理器，跳过系统依赖安装"
            ;;
    esac
}

#==============================================================================
# 显示 Python 安装指南
#==============================================================================
show_python_install_guide() {
    echo
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  未找到符合要求的 Python 版本${NC}"
    echo -e "${RED}  需要 Python >= ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}${NC}"
    echo -e "${RED}========================================${NC}"
    echo
    echo -e "${YELLOW}请根据您的系统安装 Python:${NC}"
    echo

    case "$OS_ID" in
        centos|rhel|rocky|alma|fedora)
            echo -e "${GREEN}【CentOS / RHEL / Rocky / Alma / Fedora】${NC}"
            echo
            echo "方法1: 使用包管理器安装"
            if [ "$PKG_MANAGER" = "dnf" ]; then
                echo "  dnf install -y python39 python39-pip"
            else
                echo "  yum install -y epel-release"
                echo "  yum install -y python39 python39-pip"
            fi
            echo
            echo "方法2: 使用宝塔面板 Python 项目管理器"
            ;;

        ubuntu)
            echo -e "${GREEN}【Ubuntu】${NC}"
            echo
            echo "方法1: 使用 apt 安装"
            echo "  apt update"
            echo "  apt install -y python3 python3-venv python3-pip"
            echo
            echo "方法2: 使用 deadsnakes PPA (获取更新版本)"
            echo "  add-apt-repository ppa:deadsnakes/ppa"
            echo "  apt update"
            echo "  apt install -y python3.11 python3.11-venv"
            ;;

        debian)
            echo -e "${GREEN}【Debian】${NC}"
            echo
            echo "使用 apt 安装:"
            echo "  apt update"
            echo "  apt install -y python3 python3-venv python3-pip"
            ;;

        alinux|aliyun|anolis)
            echo -e "${GREEN}【阿里云 Linux / Anolis】${NC}"
            echo
            echo "使用 yum 安装:"
            echo "  yum install -y python39 python39-pip"
            ;;

        *)
            echo -e "${GREEN}【通用方法】${NC}"
            echo
            echo "1. 使用宝塔面板 Python 项目管理器"
            echo "2. 或编译安装 Python 3.9+"
            ;;
    esac

    echo
    echo -e "${YELLOW}安装完成后，请重新运行: ./install.sh${NC}"
    echo
    exit 1
}

#==============================================================================
# 安装 Python 依赖
#==============================================================================
install_python_deps() {
    echo -e "${YELLOW}[5/7] 安装 Python 依赖${NC}"

    if [ "$NEED_VENV" = true ]; then
        # 需要虚拟环境的系统 (Debian 12+, Ubuntu 23.04+ 等)
        echo "检测到 PEP 668 限制，使用虚拟环境安装"

        VENV_DIR="$INSTALL_DIR/venv"

        if [ ! -d "$VENV_DIR" ]; then
            echo "创建虚拟环境: $VENV_DIR"
            "$PYTHON_PATH" -m venv "$VENV_DIR" || {
                echo -e "${RED}创建虚拟环境失败${NC}"
                echo "尝试安装 python3-venv 包..."
                if [ "$PKG_MANAGER" = "apt" ]; then
                    apt-get install -y python3-venv python3-full 2>/dev/null || true
                    "$PYTHON_PATH" -m venv "$VENV_DIR"
                else
                    exit 1
                fi
            }
        fi

        # 使用虚拟环境
        FINAL_PYTHON="$VENV_DIR/bin/python"
        FINAL_PIP="$VENV_DIR/bin/pip"

        # 升级 pip
        "$FINAL_PIP" install --upgrade pip -q 2>/dev/null || true

        # 安装依赖
        "$FINAL_PIP" install -r "$INSTALL_DIR/requirements.txt" -q
        echo "依赖已安装到虚拟环境"

    elif [ -n "$BT_PYTHON" ]; then
        # 宝塔环境，直接使用宝塔 Python
        echo "使用宝塔 Python 环境"
        FINAL_PYTHON="$PYTHON_PATH"
        BT_PIP=$(dirname "$PYTHON_PATH")/pip3
        if [ ! -x "$BT_PIP" ]; then
            BT_PIP="$PYTHON_PATH -m pip"
        fi
        $BT_PIP install -r "$INSTALL_DIR/requirements.txt" -q --root-user-action=ignore
        echo "依赖安装完成"

    else
        # 传统系统，尝试直接安装或使用虚拟环境
        echo "尝试安装依赖..."

        # 先尝试直接安装
        if "$PYTHON_PATH" -m pip install -r "$INSTALL_DIR/requirements.txt" -q --root-user-action=ignore 2>/dev/null; then
            FINAL_PYTHON="$PYTHON_PATH"
            echo "依赖安装完成"
        else
            # 失败则使用虚拟环境
            echo "直接安装失败，切换到虚拟环境模式"
            VENV_DIR="$INSTALL_DIR/venv"
            "$PYTHON_PATH" -m venv "$VENV_DIR"
            FINAL_PYTHON="$VENV_DIR/bin/python"
            "$VENV_DIR/bin/pip" install --upgrade pip -q 2>/dev/null || true
            "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
            echo "依赖已安装到虚拟环境"
        fi
    fi
}

#==============================================================================
# 主安装流程
#==============================================================================

# 1. 检测环境
detect_environment

# 2. 查找 Python
echo -e "${YELLOW}[2/7] 检测 Python 环境${NC}"

# 优先使用宝塔 Python
if [ -n "$BT_PYTHON" ]; then
    PYTHON_PATH="$BT_PYTHON"
    echo -e "  使用宝塔 Python: ${BLUE}$PYTHON_PATH${NC}"
else
    PYTHON_PATH=$(find_best_python)
fi

if [ -z "$PYTHON_PATH" ]; then
    show_python_install_guide
fi

PYTHON_VERSION=$("$PYTHON_PATH" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")
echo -e "  Python 版本: ${GREEN}$PYTHON_VERSION${NC}"
echo -e "  Python 路径: ${GREEN}$PYTHON_PATH${NC}"
echo

# 3. 安装系统依赖
install_system_deps

# 4. 创建安装目录并复制文件
echo -e "${YELLOW}[4/7] 复制程序文件${NC}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/data"
mkdir -p "$INSTALL_DIR/logs"

if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
    cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
    echo "文件已复制到 $INSTALL_DIR"
else
    echo "已在安装目录中运行，跳过复制"
fi
chmod +x "$INSTALL_DIR/main.py"

# 5. 安装 Python 依赖
FINAL_PYTHON="$PYTHON_PATH"
install_python_deps

# 6. 配置开机自启服务
echo -e "${YELLOW}[6/7] 配置开机自启服务${NC}"

# 检测初始化系统类型
INIT_SYSTEM=""
if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
    INIT_SYSTEM="systemd"
elif command -v rc-service &>/dev/null; then
    INIT_SYSTEM="openrc"
elif [ -f /etc/init.d/functions ] || [ -d /etc/init.d ]; then
    INIT_SYSTEM="sysvinit"
else
    INIT_SYSTEM="unknown"
fi

echo "  检测到初始化系统: $INIT_SYSTEM"

case "$INIT_SYSTEM" in
    systemd)
        # systemd (大多数现代 Linux: Ubuntu 16+, CentOS 7+, Debian 8+)
        echo "  配置 systemd 服务..."
        cat > /etc/systemd/system/ipcollect.service << EOF
[Unit]
Description=IP Threat Collector Service
Documentation=https://github.com/your-repo/ipcollect
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$FINAL_PYTHON $INSTALL_DIR/main.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=append:$INSTALL_DIR/logs/service.log
StandardError=append:$INSTALL_DIR/logs/service.log

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable ipcollect
        echo "  服务已配置: /etc/systemd/system/ipcollect.service"
        ;;

    openrc)
        # OpenRC (Alpine Linux, Gentoo)
        echo "  配置 OpenRC 服务..."
        cat > /etc/init.d/ipcollect << 'INITEOF'
#!/sbin/openrc-run

name="ipcollect"
description="IP Threat Collector Service"
command="FINAL_PYTHON_PLACEHOLDER"
command_args="INSTALL_DIR_PLACEHOLDER/main.py"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
directory="INSTALL_DIR_PLACEHOLDER"
output_log="INSTALL_DIR_PLACEHOLDER/logs/service.log"
error_log="INSTALL_DIR_PLACEHOLDER/logs/service.log"

depend() {
    need net
    after firewall
}
INITEOF
        # 替换占位符
        sed -i "s|FINAL_PYTHON_PLACEHOLDER|$FINAL_PYTHON|g" /etc/init.d/ipcollect
        sed -i "s|INSTALL_DIR_PLACEHOLDER|$INSTALL_DIR|g" /etc/init.d/ipcollect
        chmod +x /etc/init.d/ipcollect
        rc-update add ipcollect default
        echo "  服务已配置: /etc/init.d/ipcollect"
        ;;

    sysvinit)
        # SysVinit (老版本 CentOS 6, Debian 7)
        echo "  配置 SysVinit 服务..."
        cat > /etc/init.d/ipcollect << 'INITEOF'
#!/bin/bash
# chkconfig: 2345 95 05
# description: IP Threat Collector Service
### BEGIN INIT INFO
# Provides:          ipcollect
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: IP Threat Collector
# Description:       IP Threat Collector Service for analyzing logs
### END INIT INFO

DAEMON="FINAL_PYTHON_PLACEHOLDER"
DAEMON_ARGS="INSTALL_DIR_PLACEHOLDER/main.py"
PIDFILE="/var/run/ipcollect.pid"
LOGFILE="INSTALL_DIR_PLACEHOLDER/logs/service.log"
WORKDIR="INSTALL_DIR_PLACEHOLDER"

start() {
    echo -n "Starting ipcollect: "
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        echo "already running"
        return 1
    fi
    cd "$WORKDIR"
    nohup $DAEMON $DAEMON_ARGS >> "$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    echo "started"
}

stop() {
    echo -n "Stopping ipcollect: "
    if [ -f "$PIDFILE" ]; then
        kill $(cat "$PIDFILE") 2>/dev/null
        rm -f "$PIDFILE"
        echo "stopped"
    else
        echo "not running"
    fi
}

restart() {
    stop
    sleep 2
    start
}

status() {
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        echo "ipcollect is running (PID: $(cat $PIDFILE))"
    else
        echo "ipcollect is not running"
    fi
}

case "$1" in
    start)   start ;;
    stop)    stop ;;
    restart) restart ;;
    status)  status ;;
    *)       echo "Usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
exit 0
INITEOF
        # 替换占位符
        sed -i "s|FINAL_PYTHON_PLACEHOLDER|$FINAL_PYTHON|g" /etc/init.d/ipcollect
        sed -i "s|INSTALL_DIR_PLACEHOLDER|$INSTALL_DIR|g" /etc/init.d/ipcollect
        chmod +x /etc/init.d/ipcollect

        # 根据系统添加开机启动
        if command -v chkconfig &>/dev/null; then
            chkconfig --add ipcollect
            chkconfig ipcollect on
        elif command -v update-rc.d &>/dev/null; then
            update-rc.d ipcollect defaults
        fi
        echo "  服务已配置: /etc/init.d/ipcollect"
        ;;

    *)
        # 未知系统，创建 rc.local 启动
        echo -e "  ${YELLOW}未识别的初始化系统，使用 rc.local 方式${NC}"

        # 创建启动脚本
        cat > "$INSTALL_DIR/start.sh" << EOF
#!/bin/bash
cd $INSTALL_DIR
nohup $FINAL_PYTHON $INSTALL_DIR/main.py >> $INSTALL_DIR/logs/service.log 2>&1 &
echo \$! > /var/run/ipcollect.pid
EOF
        chmod +x "$INSTALL_DIR/start.sh"

        # 添加到 rc.local
        if [ -f /etc/rc.local ]; then
            if ! grep -q "ipcollect" /etc/rc.local; then
                sed -i "/^exit 0/i $INSTALL_DIR/start.sh" /etc/rc.local 2>/dev/null || \
                echo "$INSTALL_DIR/start.sh" >> /etc/rc.local
            fi
        else
            echo "#!/bin/bash" > /etc/rc.local
            echo "$INSTALL_DIR/start.sh" >> /etc/rc.local
            echo "exit 0" >> /etc/rc.local
            chmod +x /etc/rc.local
        fi
        echo "  已添加到 /etc/rc.local"
        ;;
esac

echo "  使用 Python: $FINAL_PYTHON"

# 7. 调整配置文件
echo -e "${YELLOW}[7/7] 调整配置文件${NC}"
# 修改配置文件中的相对路径为绝对路径
if grep -q "path: \./data/" "$INSTALL_DIR/config.yaml" 2>/dev/null; then
    sed -i "s|path: \./data/|path: $INSTALL_DIR/data/|g" "$INSTALL_DIR/config.yaml"
fi
if grep -q "file: \./logs/" "$INSTALL_DIR/config.yaml" 2>/dev/null; then
    sed -i "s|file: \./logs/|file: $INSTALL_DIR/logs/|g" "$INSTALL_DIR/config.yaml"
fi
if grep -q "state_file: \./data/" "$INSTALL_DIR/config.yaml" 2>/dev/null; then
    sed -i "s|state_file: \./data/|state_file: $INSTALL_DIR/data/|g" "$INSTALL_DIR/config.yaml"
fi
if grep -q "file: \./ip.txt" "$INSTALL_DIR/config.yaml" 2>/dev/null; then
    sed -i "s|file: \./ip.txt|file: $INSTALL_DIR/ip.txt|g" "$INSTALL_DIR/config.yaml"
fi
echo "配置文件已更新"

#==============================================================================
# 完成
#==============================================================================
echo
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  安装完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo
echo -e "系统类型:       ${BLUE}$OS_NAME${NC}"
echo -e "初始化系统:     ${BLUE}$INIT_SYSTEM${NC}"
echo -e "Python 版本:    ${BLUE}$PYTHON_VERSION${NC}"
echo -e "运行环境:       ${BLUE}$FINAL_PYTHON${NC}"
echo -e "安装目录:       ${BLUE}$INSTALL_DIR${NC}"
if [ -d "$INSTALL_DIR/venv" ]; then
echo -e "虚拟环境:       ${BLUE}$INSTALL_DIR/venv${NC}"
fi
echo

# 根据初始化系统显示不同的服务管理命令
echo "服务管理命令:"
case "$INIT_SYSTEM" in
    systemd)
        echo "  启动服务:    systemctl start ipcollect"
        echo "  停止服务:    systemctl stop ipcollect"
        echo "  重启服务:    systemctl restart ipcollect"
        echo "  查看状态:    systemctl status ipcollect"
        echo "  禁用自启:    systemctl disable ipcollect"
        START_CMD="systemctl start ipcollect"
        ;;
    openrc)
        echo "  启动服务:    rc-service ipcollect start"
        echo "  停止服务:    rc-service ipcollect stop"
        echo "  重启服务:    rc-service ipcollect restart"
        echo "  查看状态:    rc-service ipcollect status"
        echo "  禁用自启:    rc-update del ipcollect default"
        START_CMD="rc-service ipcollect start"
        ;;
    sysvinit)
        echo "  启动服务:    service ipcollect start"
        echo "  停止服务:    service ipcollect stop"
        echo "  重启服务:    service ipcollect restart"
        echo "  查看状态:    service ipcollect status"
        START_CMD="service ipcollect start"
        ;;
    *)
        echo "  启动服务:    $INSTALL_DIR/start.sh"
        echo "  停止服务:    kill \$(cat /var/run/ipcollect.pid)"
        echo "  查看状态:    ps aux | grep ipcollect"
        START_CMD="$INSTALL_DIR/start.sh"
        ;;
esac

echo
echo "查看日志:      tail -f $INSTALL_DIR/logs/ipcollect.log"
echo
echo "手动执行:"
echo "  单次扫描:    $FINAL_PYTHON $INSTALL_DIR/main.py --once"
echo "  查看统计:    $FINAL_PYTHON $INSTALL_DIR/main.py --stats"
echo "  导出IP:      $FINAL_PYTHON $INSTALL_DIR/main.py --export"
echo
echo "配置文件:      $INSTALL_DIR/config.yaml"
echo "白名单文件:    $INSTALL_DIR/white.txt"
echo "威胁IP输出:    $INSTALL_DIR/ip.txt"
echo
echo -e "${YELLOW}提示: 运行 '$START_CMD' 启动服务${NC}"
echo
echo -e "${GREEN}----------------------------------------${NC}"
echo -e "${CYAN}作者: $AUTHOR${NC}"
echo -e "${CYAN}网站: $WEBSITE${NC}"
echo -e "${CYAN}QQ: 42033223${NC}"
echo -e "${GREEN}----------------------------------------${NC}"
echo
