#!/bin/bash
#
# IP威胁收集分析服务 - 卸载脚本
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}  IP威胁收集分析服务 - 卸载脚本${NC}"
echo -e "${YELLOW}========================================${NC}"
echo

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}请使用root权限运行此脚本${NC}"
    exit 1
fi

INSTALL_DIR="/www/server/ipcollect"

read -p "确定要卸载吗？这将删除所有数据 [y/N]: " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "取消卸载"
    exit 0
fi

echo -e "${YELLOW}[1/3] 停止服务${NC}"
systemctl stop ipcollect 2>/dev/null || true
systemctl disable ipcollect 2>/dev/null || true

echo -e "${YELLOW}[2/3] 删除服务文件${NC}"
rm -f /etc/systemd/system/ipcollect.service
systemctl daemon-reload

echo -e "${YELLOW}[3/3] 删除程序文件${NC}"
rm -rf "$INSTALL_DIR"

echo
echo -e "${GREEN}卸载完成！${NC}"
echo
echo "注意: /ip.txt 文件未删除，如需删除请手动执行: rm /ip.txt"
echo
