# lanmgr — 基于 C 语言的 Windows 局域网管理系统

用 C11 + Win32 API 实现的局域网管理系统：探测局域网结构（上级路由器 + 活动设备树）、
通过 API Key 接入 AI Agent 操控设备、所有风险操作必须由用户确认、用户名/密码/密钥
DPAPI 加密存储（绝不落明文）、支持逐命令提权（Linux 目标 sudo -i / sudo -S）。

demo 阶段用网页预览；正式使用时通过 Inno Setup 打包为桌面安装包并注册为 Windows 服务。

## 快速开始（demo 网页预览）

    # 1) 一次性引导工具链（免管理员：下载便携 MinGW-w64 + CMake）
    pwsh -File .\scripts\bootstrap.ps1

    # 2) 编译（输出到 E:\Chengdu_DB_soft\build\lanmgr.exe）
    pwsh -File .\build.ps1

    # 3) 启动演示（自动打开浏览器 http://127.0.0.1:8686）
    E:\Chengdu_DB_soft\build\lanmgr.exe --demo

注意：--demo / --serve 需在项目根目录运行（web/、vault.dat、audit.log 相对当前目录）。
生产安装包会把 web/ 一起安装到程序目录。

## 命令行

    --help / --version          帮助 / 版本
    --discover                  扫描并打印局域网拓扑 JSON（网关 + 活动设备树）
    --demo / --serve            启动 Web 演示（--demo 附打开浏览器）
    --cred-add <标签> <类型> <目标> <用户> <密码>   保存凭据（DPAPI 加密）
    --cred-ls / --cred-get / --cred-del            列出/读取/删除凭据
    --exec-local <命令> / --exec-ssh <ip> <凭据id> <命令>   本地/远程执行
    --provider-ls / --provider-add <名> <base_url> <endpoint> <模型>   管理提供方
    --provider-use <名> / --provider-del <名>                         切换/删除提供方
    --apikey-set <名> <KEY> / --apikey-ls                             独立 API Key(加密)
    --agent <需求> / --tool-test / --risk-test     Agent / 工具 / 风险自测
    --service-install / --service-uninstall        注册/删除 Windows 服务（需管理员）
    --service                   以 Windows 服务方式运行

## 需求对照

1. 局域网探索 — src/net/：GetAdaptersAddresses + 路由表取上级路由器(默认网关)；ARP 邻居表
   判断“正在使用”的设备；IcmpSendEcho 存活扫描；忽略局域网外网段（仅保留 RFC1918 私网，丢弃
   代理 fake-IP / 组播 / 广播 / 空子网）；输出树状 JSON。
2. Agent 接入 — src/agent/：OpenAI 兼容 tool-calling 循环（WinHTTP）。调用地址(base_url)、请求地址
   (endpoint)、模型、API Key 全部由用户本地配置，CC Switch 风格支持多提供方切换；用户只提自然语言
   需求，具体控制细节由工具处理器完成。
3. 风险由用户决定 + 凭据加密 — src/sec/：风险分级闸门（读/写/高危），变更必须人工确认
   （网页弹窗，超时自动拒绝）；vault.dat 中用户名与密码均经 DPAPI 加密，store_plaintext
   默认 false，绝不擅自明文存储。
4. 逐命令提权 — src/exec/：Linux 目标 ssh + sudo -S（密码经 stdin 一次性注入并零化），
   支持 sudo -i 交互；本机用 Windows 24H2 自带 sudo。
5. demo 网页 / 生产安装包 — src/web/ 内嵌 HTTP 服务 + 静态前端（demo）；
   packaging/installer.iss + src/svc/ Windows 服务（生产，需 Inno Setup 打包）。

## 目录结构

    src/core   配置/日志/工具/任务队列      src/net   发现/邻居/探测/拓扑
    src/sec    vault(DPAPI)/risk/audit     src/exec  本地/SSH/sudo
    src/agent  LLM(WinHTTP)/工具/循环       src/web   HTTP服务器/前端API
    src/svc    Windows 服务                web/      前端(HTML/JS/CSS)
    third_party/cJSON                         tests/   单元测试
    packaging/installer.iss                  scripts/ 编译/引导脚本

## Agent 提供方配置（CC Switch 风格）

API Key 与设备凭据分离、独立加密存储：

- providers.json —— 提供方元数据（不带密钥）：name、base_url(调用地址)、endpoint(请求地址)、model。
- apikeys.dat —— 每个提供方的 API Key 独立存放，DPAPI 加密，绝不落明文。
- 网页「Agent 提供方」面板 或 命令行均可增删改、切换当前提供方、设置 Key。
- Agent 运行时读取「当前(active)」提供方，拼成 base_url+endpoint 完整请求地址，密钥经内存解密即用即零化。

示例（网页或 CLI 二选一）：

    lanmgr --provider-add deepseek https://api.deepseek.com /v1/chat/completions deepseek-chat
    lanmgr --apikey-set deepseek sk-your-key-here
    lanmgr --agent "ping 一下 192.168.31.1"

## 安全说明

- 凭据统一以 DPAPI（CryptProtectData，机器级）加密落盘；vault.dat 不含任何明文。
- 所有密钥在内存中使用后调用 SecureZeroMemory 归零；日志对密钥做脱敏(redact)。
- 高风险操作生成 Confirmation，用户批准后才执行，全程写入 audit.log（JSON 行）。
- config.json 中 store_plaintext 仅显式开启才允许明文（并打 WARN 审计）。

## 构建与生产

- 开发：build.ps1（MinGW-w64 直连编译；输出到 ASCII 目录规避 ld 对 GBK 路径的缺陷）。
- 正式：cmake -S . -B build-cmake -G "MinGW Makefiles" && cmake --build build-cmake（含 ctest）。
- 安装包：安装 Inno Setup 6 后运行 iscc packaging\installer.iss，
  产出 build\installer\lanmgr-setup-*.exe。

## 已知限制

- 远程 SSH 需目标开启 SSH 服务；sudo 提权需目标用户具备 sudo 权限（本机未做端到端验证）。
- Windows 目标走 WinRM 为占位(stub)，后续接入 PowerShell Remoting / WinRS。
- 中文凭据标签经命令行参数（ANSI argv）会乱码；网页端（UTF-8 JSON）正常。
- 单线程 HTTP 服务，面向本地 demo 足够；并发/生产可换 civetweb。
