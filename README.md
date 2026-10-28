# lanlord · Windows 局域网管理系统

用 **C11 + Win32 API** 编写的局域网探测与管控工具：自动摸清「上级路由器 → 交换机 / AP → 活动主机」的网络结构，
再通过 **AI Agent（OpenAI 兼容 tool-calling）** 用自然语言操控设备。所有变更类操作都必须由用户在界面上确认，
所有凭据（用户名 / 密码 / API Key）均经 **DPAPI 加密**落盘，不保存明文。

- 语言 / 运行时：C11，无第三方运行时依赖（仅内置 cJSON）
- 平台：Windows 10 / 11 x64
- 形态：命令行 + 本地 Web 控制台（`http://127.0.0.1:8686`），可注册为 Windows 服务并打安装包
- 当前版本：`0.1.0`（可执行文件名 `lanmgr.exe`，程序标识 `lanlord`）

---

## 功能一览

| 能力 | 说明 |
| --- | --- |
| 局域网发现 | 路由表取上级路由器，`GetAdaptersAddresses` 枚举接口 / 前缀，ARP 邻居表识别在线设备，`IcmpSendEcho` 补扫存活主机 |
| 拓扑构建 | 向上探测多级网关（含品牌识别），向下挂载活动主机，输出树状 JSON；MAC 前缀识别厂商 |
| Web 控制台 | 拓扑树、Agent 对话、命令执行、提供方 / 凭据设置、Docker 容器查看、风险确认弹窗 |
| AI Agent | 兼容 OpenAI 的 `chat/completions` tool-calling，多轮循环，工具结果回填 |
| 凭据保险箱 | 设备凭据 `vault.dat`、API Key `apikeys.dat` 分离存储，均 DPAPI 加密 |
| 风险闸门 | READ / WRITE / DESTRUCTIVE 三级；WRITE 及以上需人工确认，超时自动拒绝 |
| 审计 | `audit.log` 逐行 JSON 记录操作人、动作、目标、决策；日志对密钥做脱敏 |
| 远程执行 | 本机 `cmd.exe /c`；Linux 目标走系统 `ssh.exe`，支持 `sudo -S` 逐命令提权 |
| 运维辅助 | 通过 SSH 查看目标机 Docker 容器；Windows 服务安装 / 卸载 |

---

## 快速开始

前置条件：Windows 10/11 x64、PowerShell 5.1+。构建工具链（MinGW-w64 16.2.0 + CMake 4.4.4）已内置在项目 `tools\` 目录，无需联网下载或单独安装。

```powershell
# 编译：工具链缺失时会自动下载，之后无需重复下载
pwsh -File .\build.ps1

# 启动演示（后台静默启动，无命令行窗口，自动打开 http://127.0.0.1:8686）
.\build\lanmgr.exe --demo
```

> `--demo` / `--serve` 采用后台静默启动：从资源管理器 / 快捷方式 / `start` 启动时不弹出命令行窗口，仅在浏览器中呈现；
> 结束进程请用任务管理器或 `taskkill`（也可用 `--service-install` 注册为 Windows 服务）。从既有终端手动运行时日志仍会打印到该终端。

> 工具链与产物会自动解析到 **ASCII 路径**（规避 MinGW `ld` 对非 ASCII/GBK 路径的缺陷）：
> - 项目路径为 ASCII → 工具链在项目内 `tools\`，产物在 `build\`；
> - 项目路径含中文 → 工具链在项目旁的 `..\lanlord-tools\`，产物在 `..\build\`。
>
> 本机项目路径为 ASCII（`E:\Chengdu_DB_soft\lanlord`），工具链已内置在项目内 `tools\`（`tools\mingw64` + `tools\cmake`），产物在 `build\`。
> 也可手动引导：`pwsh -File .\scripts\bootstrap.ps1`，再 `. .\scripts\env.ps1` 加入 PATH。
>
> `--demo` / `--serve` 请在项目根目录运行（`web/`、`vault.dat`、`audit.log` 相对于当前工作目录）。

也可以直接用 CMake（需先引导好工具链）：

```powershell
cmake -S . -B build-cmake -G "MinGW Makefiles"
cmake --build build-cmake
ctest --test-dir build-cmake --output-on-failure
```

---

## Web 控制台

`http://127.0.0.1:8686`（仅绑定回环地址，默认不对外网开放）：

- **网络拓扑**：光猫 / 路由器为根，自上而下展开设备树；点击设备可查看其 Docker 容器
- **Agent 助手**：只输入自然语言需求，由模型自行选择工具
- **执行命令**：本地 / 远程命令，变更类操作弹出确认框
- **设置**：Agent 提供方（选供应商自动填地址、一键拉取模型列表）、设备凭据管理、Agent 授权模式、操作回滚

对应接口（`src/web/server.c`）：

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/status` | 版本 / 当前提供方 / 授权模式 / 回滚数等状态 |
| GET | `/api/topology` | 读取最近一次拓扑 |
| POST | `/api/discover` | 触发后台扫描（异步任务） |
| GET | `/api/job/<id>` | 查询异步任务进度 |
| POST | `/api/agent` | 提交自然语言需求，走 Agent 循环 |
| POST | `/api/exec` | 执行命令（按风险级别决定是否挂起确认） |
| GET | `/api/confirmations` | 待确认的风险操作 |
| POST | `/api/confirm` | 批准 / 拒绝确认单 |
| GET/POST | `/api/credentials` | 凭据列表 / 新增 |
| GET/POST | `/api/providers` | 提供方列表 / 新增 |
| POST | `/api/provider/active`、`/api/provider/key`、`/api/provider/delete`、`/api/provider/models` | 切换、设置 Key、删除、拉取模型 |
| GET | `/api/vendors` | 内置供应商预设 |
| POST | `/api/device/docker` | SSH 到目标机执行 `docker ps` |
| POST | `/api/auth` | 切换 Agent 授权模式 `semi` / `full` |
| GET/POST | `/api/rollback` | 列出可回滚操作 / 执行回滚 |

---

## 命令行

```text
lanmgr <命令> [参数]
```

### 运行与拓扑

| 命令 | 说明 |
| --- | --- |
| `--help` / `-h` | 显示帮助 |
| `--version` / `-v` | 显示版本号 |
| `--discover` | 扫描并打印局域网拓扑 JSON 后退出 |
| `--demo` | 启动 Web 演示并打开浏览器 |
| `--serve` | 仅启动 Web 服务（不打开浏览器） |
| `--service` | 以 Windows 服务方式运行 |
| `--service-install` / `--service-uninstall` | 注册 / 删除 Windows 服务（需管理员） |

### 凭据（DPAPI 加密）

| 命令 | 说明 |
| --- | --- |
| `--cred-ls` | 列出凭据（仅标签与目标，不含密码） |
| `--cred-add <label> <type> <target> <user> <secret>` | 新增凭据；`type` 取值 `ssh` / `winrm` / `http` / `apitoken` |
| `--cred-get <id>` | 读取凭据（开发自测，打印后立即零化） |
| `--cred-del <id>` | 删除凭据 |

### 执行

| 命令 | 说明 |
| --- | --- |
| `--exec-local <命令>` | 在本机执行（`cmd.exe /c`） |
| `--exec-ssh <ip> <cred-id> <命令>` | 在 Linux 目标上执行 |
| `--exec-ssh-sudo <ip> <cred-id> <命令>` | 同上，并用 `sudo -S` 提权（密码经 stdin 一次性注入） |

### Agent 与提供方

| 命令 | 说明 |
| --- | --- |
| `--agent <需求>` | 执行一次 Agent 会话 |
| `--vendor-ls` | 列出内置供应商预设 |
| `--provider-ls` | 列出已配置提供方 |
| `--provider-add <名> <base_url> <endpoint> <模型>` | 新增提供方 |
| `--provider-use <名>` / `--provider-del <名>` | 切换 / 删除提供方 |
| `--provider-models <名>` | 拉取该提供方可用模型 |
| `--apikey-set <名> <KEY>` / `--apikey-ls` | 独立加密存储 / 列出 API Key |
| `--tool-test` / `--risk-test` | 工具表 / 风险确认流程自测 |

示例：

```powershell
lanmgr --provider-add deepseek https://api.deepseek.com /v1/chat/completions deepseek-chat
lanmgr --apikey-set deepseek sk-your-key-here
lanmgr --agent "扫一下局域网，告诉我网关和在线设备"
```

---

## 配置

首次运行会按 `config.example.json` 生成 `config.json`（`config.json` 已被 `.gitignore` 忽略）。

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `port` | `8686` | Web 控制台端口（绑定 `127.0.0.1`） |
| `scan_max_hosts` | `256` | 单个网段存活扫描上限 |
| `scan_timeout_ms` | `400` | 单主机探测超时 |
| `confirm_timeout_s` | `120` | 风险确认等待时长，超时自动拒绝 |
| `store_plaintext` | `false` | 是否允许明文存储凭据（仅调试用，会写 WARN 审计） |
| `authorization` | `semi` | Agent 授权模式：`semi` 半授权 / `full` 完全授权 |
| `agent.max_turns` | `10` | Agent 工具调用最大轮数 |
| `agent.timeout_s` | `60` | 单次模型请求超时 |
| `vault_path` | `vault.dat` | 凭据保险箱 |
| `audit_path` | `audit.log` | 审计日志（JSON 行） |
| `log_path` | `lanmgr.log` | 运行日志 |
| `web_root` | `web` | 前端静态资源目录 |
| `providers_path` | `providers.json` | 提供方元数据（不含密钥） |
| `apikeys_path` | `apikeys.dat` | API Key 加密库 |
| `rollback_path` | `rollback.log` | Agent 回滚日志（JSON 行，可回滚操作历史） |

---

## Agent 提供方（CC Switch 风格）

提供方元数据与密钥分离：`providers.json` 只存地址与模型名，API Key 单独加密进 `apikeys.dat`。

内置预设（`src/agent/vendors.c`）：DeepSeek、OpenAI、Moonshot/Kimi、火山方舟 ARK（豆包）、OpenRouter、Groq、
SiliconFlow、Ollama（本地）。选择预设后自动填充 `base_url` / `endpoint`，并可一键拉取模型列表。

Agent 运行时读取「当前（active）」提供方，把 `base_url + endpoint` 拼成完整请求地址，密钥解密后即用即零化。

---

## Agent 可调用工具

工具定义见 `src/agent/tools.c`：

| 工具 | 风险 | 说明 |
| --- | --- | --- |
| `topology.get` | READ | 获取局域网拓扑树 |
| `ping` | READ | Ping 指定 IP 判断在线 |
| `exec.local` | WRITE | 在管理机本机执行命令（可选 `rollback` 逆向命令以便回滚） |
| `exec.remote` | WRITE（动态） | 在远程设备执行；`escalate=true` 时 sudo 提权，风险等级随参数上调（可选 `rollback`） |
| `docker.ps` | READ | 经 SSH 列出目标机 Docker 容器 |
| `credential.list` | READ | 列出凭据（不含密码） |
| `credential.add` | DESTRUCTIVE | 新增设备凭据（自动可回滚：回滚即删除该凭据） |

## Agent 授权模式（半授权 / 完全授权）

Agent 权限与操作用户等价，在设置面板或 `config.json` 的 `authorization` 字段切换：

- **半授权 `semi`（默认）**：`WRITE` / `DESTRUCTIVE` 操作逐次弹出人工确认，批准后执行。
- **完全授权 `full`**：可直接执行风险指令，但**必须可回滚**——仅「可回滚」操作自动执行并进入回滚历史；
  无可回滚方案的操作仍自动降级为人工确认。可一键回滚（`/api/rollback`）。

回滚能力来源：`exec.*` 由模型提供的 `rollback` 逆向命令；`credential.add` 由系统自动推导（删除该凭据）。
所有自动化执行与回滚动作均写入 `audit.log`。

---

## 安全模型

- **加密存储**：用户名、密码、API Key 全部经 DPAPI（机器级）加密；`vault.dat` 含魔数头，无明文。
- **密钥分离**：设备凭据与 Agent API Key 分别存于 `vault.dat` 与 `apikeys.dat`。
- **风险分级**：`READ` 直通，`WRITE` / `DESTRUCTIVE` 生成确认单，等待用户批准，超时自动拒绝。
- **授权分级**：半授权 = 风险操作逐次确认；完全授权 = 可回滚操作自动执行、不可回滚操作仍确认；回滚历史落 `rollback.log`。
- **审计留痕**：`audit.log` 每行一条 JSON，记录 actor / action / target / decision。
- **内存卫生**：密钥使用后 `SecureZeroMemory` 归零，日志对密钥做 redact。
- **网络暴露面**：Web 服务仅监听 `127.0.0.1`，不默认对局域网开放。

---

## 目录结构

```
src/core     配置、日志、IP 数学、任务队列、错误码
src/net      接口/网关、ARP 邻居、存活扫描、厂商识别、拓扑构树、traceroute（预留）
src/sec      vault(DPAPI)、keystore(API Key)、风险闸门、审计
src/exec     本地执行、SSH / sudo 提权、Docker
src/agent    WinHTTP 客户端、工具表、Agent 循环、供应商预设
src/web      单线程 HTTP 服务与 JSON API
src/svc      Windows 服务封装
web/         前端页面（HTML / JS / CSS）
third_party  cJSON
tests/       单元测试（IP 数学）
packaging/   Inno Setup 安装脚本
scripts/     工具链引导与编译脚本
docs/        设计文档
```

---

## 构建与打包

- **开发编译**：`build.ps1`（MinGW-w64 直连编译，速度快，产物输出到 ASCII 目录）
- **CMake 构建**：`cmake -S . -B build-cmake -G "MinGW Makefiles"`，含 `ctest` 单元测试
- **安装包**：安装 Inno Setup 6 后执行 `iscc packaging\installer.iss`，
  产出 `build\installer\lanmgr-setup-0.1.0.exe`；安装时自动注册 Windows 服务并把 `web/` 一并部署

链接的系统库：`ws2_32 iphlpapi crypt32 winhttp advapi32 user32 shell32 bcrypt`

---

## 已知限制

- 远程执行依赖目标机开启 SSH；`sudo` 提权要求目标用户具备 sudo 权限（尚未做端到端验证）。
- Windows 目标远程执行（WinRM / WinRS）目前是占位实现，仅支持 Linux over SSH。
- `traceroute` 与 NetBIOS/mDNS 主机名解析已具备代码，尚未接入拓扑流程。
- 中文凭据标签经命令行参数（ANSI argv）可能乱码；网页端（UTF-8 JSON）正常。
- HTTP 服务为单线程，面向本机单用户场景；多用户 / 高并发需替换为 civetweb 等实现。
- 拓扑扫描为主动 ICMP + ARP，可能被防火墙或隔离策略影响，结果以实际网络环境为准。

---

## 相关文档

- 架构、模块划分与数据模型：[docs/DESIGN.md](docs/DESIGN.md)
