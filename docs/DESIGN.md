# lanmgr 设计文档

## 1. 架构

单进程、C11、Win32 原生 API，分模块分层。demo 以控制台 + 内嵌 HTTP 服务运行，生产编译为 Windows 服务。

- 发现：路由表(默认网关=上级路由器) + GetAdaptersAddresses(接口/前缀/网关) -> ARP 邻居表(活动设备)
  -> IcmpSendEcho 存活扫描 -> 构树(cJSON 序列化)。
- 控制：Web/Agent 意图 -> risk 分级闸门 -> exec(SSH/WinRM) -> 结果 -> audit。
- Agent：messages+tools -> WinHTTP POST 兼容端点 -> 解析 tool_calls -> 工具处理器 -> 高危挂起等确认 -> 回填循环。

## 2. 模块

- core/：config(cJSON)、log(带脱敏)、util(IP 数学/zeroize)、jobs(后台任务线程)、error。
- net/：iface(接口+网关)、neighbor(ARP)、probe(存活扫描)、name(OUI)、topo(构树+序列化)。
- sec/：vault(DPAPI)、risk(确认闸门)、audit(JSON 审计)。
- exec/：exec(本机 cmd + ssh + askpass)、sudo 提权。
- agent/：llm_http(WinHTTP)、tools(工具表)、agent(循环)。
- web/：server(HTTP+路由)、前端静态资源。
- svc/：Windows 服务(安装/卸载/运行)。

## 3. 安全模型

- 凭据：用户名 + 密码 + API Key 全部 DPAPI 加密、vault.dat(magic LANMVLT1 + 二进制)。
- 风险分级：READ(直通)、WRITE(确认)、DESTRUCTIVE(确认)；超时自动拒绝。
- 审计：JSON 行日志，记录 actor/action/target/decision。
- 内存：SecureZeroMemory 归零；日志 redact 密钥。

## 4. 数据模型要点

- Subnet{ip,prefix,gateway,ifindex,ifname}。
- DeviceNode{type(root|subnet|gateway|switch|ap|host), ip, mac, vendor, children}。
- CredPlain{id, type(ssh|winrm|http|apitoken), label, target, username, secret}；磁盘存密文。
- Confirmation{id, level, summary, detail, created_ms, timeout_s, decided}。

## 5. 待办（生产阶段）

- WinRM 实装（PowerShell Remoting/WinRS）。
- SSH 内嵌 libssh2（替代系统 ssh.exe）。
- Web 加 TLS/鉴权后开放 LAN 访问；civetweb 替换单线程 HTTP。
- mDNS/NetBIOS 主机名、LLDP/SNMP 拓扑丰富。
- 桌面托盘壳（WebView2）+ 安装包（installer.iss 已就绪）。
