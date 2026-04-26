# 3x-ui Cloudflare 部署器

`xui_cf_deployer.py` 是一个基于 Python 3 标准库实现的本地脚本，用于在已安装 3x-ui 的 VPS 上自动完成：

- 按需创建 VLESS / Trojan / VMess 节点
- 写入 3x-ui SQLite 数据库并重启 `x-ui`
- 配置 Cloudflare DNS、SSL、Origin Rules
- 生成 `yx-auto.pages.dev` 订阅链接
- 检测上次配置并支持一键卸载回滚

## 前置条件（必须）

- 目标 VPS **必须已安装并可正常运行 3x-ui 面板**
- 系统中必须存在数据库文件：`/etc/x-ui/x-ui.db`
- 系统服务 `x-ui` 必须可被 `systemctl restart x-ui` 正常重启

> 未满足以上条件时，请先完成 3x-ui 安装与可用性验证，再运行本脚本。

## 运行环境

- Python 3（无需安装第三方依赖）
- 已安装并可用的 `3x-ui`（服务名通常为 `x-ui`）
- 脚本运行用户具备 root 权限（或可用 `sudo`）
- Cloudflare 账号邮箱 + Global API Key

## 文件说明

- 脚本：`xui_cf_deployer.py`
- 3x-ui 数据库：`/etc/x-ui/x-ui.db`
- 状态记录：`/etc/x-ui/cf_auto_state.json`

## 运行命令

```bash
command -v python3 >/dev/null 2>&1 || (sudo apt update && sudo apt install -y python3)
curl -fsSL -o xui_cf_deployer.py https://raw.githubusercontent.com/byJoey/xui-cf-deployer/main/xui_cf_deployer.py
chmod +x xui_cf_deployer.py
sudo python3 xui_cf_deployer.py
```

或：

```bash
command -v python3 >/dev/null 2>&1 || (sudo apt update && sudo apt install -y python3)
curl -fsSL -o xui_cf_deployer.py https://raw.githubusercontent.com/byJoey/xui-cf-deployer/main/xui_cf_deployer.py
chmod +x xui_cf_deployer.py
sudo ./xui_cf_deployer.py
```

## 交互流程

脚本启动后会先选择模式：

- `1`：安装（默认）
- `2`：卸载

### 安装模式

按提示输入：

1. 绑定域名（如 `node.example.com`）
2. Cloudflare 邮箱
3. Cloudflare Global API Key（隐藏输入）
4. 创建协议（`1=vless,2=trojan,3=vmess`，逗号分隔，回车=全部）

脚本会自动：

- 生成 UUID、短路径、随机高位端口
- 向 `inbounds` 注入所选协议节点
- 重启 `x-ui`
- 配置 CF DNS（A 记录 + 代理）
- 设置 CF SSL 为 `flexible`
- 下发/合并 Origin Rules（路径转发到对应端口）
- 输出对应协议订阅链接

### 卸载模式

脚本会读取上次安装状态并回滚：

- 删除上次创建的 x-ui 入站配置
- 恢复 Cloudflare Origin Rules 到安装前状态
- 恢复 Cloudflare SSL 到安装前值
- 恢复/删除该子域名 DNS 记录
- 删除本地状态文件

## 订阅链接参数

脚本输出的链接参数基线为：

- `epd=yes`
- `epi=yes`
- `egi=no`
- `dkby=yes`

并显式带三协议开关：

- 当前协议：`yes`
- 未启用协议：`no`

同时附带 URL Encode 后的 `path`。

## 常见问题

- 提示 Zone 匹配失败：检查输入的绑定域名是否在该 Cloudflare 账号下
- 提示数据库写入失败：确认系统已安装 3x-ui 且数据库路径正确
- 提示权限不足：使用 `sudo` 运行脚本
- 已存在上次配置无法安装：先用卸载模式清理后再重新安装
