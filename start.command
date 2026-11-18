#!/bin/zsh
# 75EC 改键台：启动本地桥接，并用 Chrome 打开页面。
# Chrome 的 WebHID 不允许网页直接访问键盘类 HID 设备，所以由本地
# Node 进程通过 node-hid 和键盘通信，网页只访问 127.0.0.1。
cd "$(dirname "$0")" || exit 1

if ! command -v node >/dev/null 2>&1; then
  echo "没有找到 Node.js。请先安装 Node.js 20 或更高版本，再双击本文件。"
  read -k 1 "?按任意键关闭…"
  exit 1
fi

if [ ! -d node_modules/node-hid ]; then
  echo "第一次运行，正在安装 node-hid…"
  npm install --no-audit --no-fund || {
    echo "安装失败。请在项目目录手动运行 npm install。"
    read -k 1 "?按任意键关闭…"
    exit 1
  }
fi

exec node bridge.mjs --open
