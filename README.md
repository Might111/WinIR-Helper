# WinIR-Helper v0.6.8-beta

本版本为 v0.6 系列的阶段性发布版，重点增强了**恶意用户排查展示、账户误报降噪、挖矿配置追踪、持久化识别和 ATT&CK 时间线复盘能力**。

> 工具定位：Windows 应急响应辅助脚本，用于快速收集本机安全线索、整理攻击时间线和生成 HTML 报告。  
> 本工具不执行查杀、不修改系统配置、不替代专业 EDR/杀软/取证工具。

---

## 核心更新

### 1. 账户与恶意用户排查增强

新增独立的 HTML 展示区域：

- 可疑本地账户
- Winlogon 隐藏账户
- 管理员组成员
- 远程桌面用户组成员
- 本地用户列表
- 账户相关安全事件

支持识别：

- 可疑命名账户，例如 `hacker`、`backdoor`、`support`、`backup`、`svc_`、`$` 结尾账户
- Winlogon `SpecialAccounts\UserList` 隐藏账户
- 管理员组异常成员
- 远程桌面用户组异常成员
- 启用且密码永不过期的可疑账户
- 用户不可修改密码等异常属性

### 2. 修复账户误报问题

v0.6.7 中普通管理员组成员可能会被误判为中危账户。  
v0.6.8 修复了该问题：

- 普通管理员组成员不再仅因属于 `Administrators` 被判为可疑账户
- 当前登录用户不会仅因“管理员组 + 描述为空”进入可疑账户列表
- 禁用的内置 `Administrator` 不再作为可疑账户展示
- 管理员组成员仍会在审计表中展示，便于人工复核

### 3. 挖矿配置与 IOC 提取增强

继续保留并优化以下能力：

- 提取矿池地址
- 提取钱包地址候选
- 提取下载/投放 URL 候选
- 支持 `stratum+tcp://`、`ssl://`、`tcp://`、`host:port`
- 支持 `.conf`、`.ini`、`.db`、`.bak`、无扩展配置文件
- 支持 Public 镜像目录中的配置线索
- 下载/投放 URL 与矿池地址分开展示，避免分类混乱

### 4. 持久化识别增强

支持排查：

- 可疑服务安装
- 可疑计划任务
- 注册表 Run / RunOnce
- HKLM / HKCU 启动项
- WOW6432Node 启动项
- Startup 文件夹
- Startup LNK 快捷方式解析
- PowerShell / VBS / HTA / BAT / CMD 脚本链

### 5. ATT&CK 时间线复盘

报告中会自动生成攻击时间线，并映射常见 ATT&CK 技术，例如：

- T1110 Brute Force
- T1059.001 PowerShell
- T1059.005 Visual Basic
- T1053.005 Scheduled Task
- T1543.003 Windows Service
- T1547.001 Registry Run Keys / Startup Folder
- T1496 Resource Hijacking
- T1021.001 Remote Desktop Protocol

---

## 使用方法

以管理员身份打开 PowerShell，执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\WinIR-Helper-v0.6.8-beta-account-noise-hotfix2.ps1 -ExportDetails -CpuSampleSeconds 15
