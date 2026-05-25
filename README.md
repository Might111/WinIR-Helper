# WinIR-Helper v0.7.1-beta

本版本为 WinIR-Helper 第七代 beta 版本，重点增强了证据链评分、处置建议生成和高危文件 Hash 建议能力，并修复 v0.7.0 中部分处置命令生成不严谨的问题。

> 工具定位：Windows 应急响应辅助脚本，用于快速收集本机安全线索、整理攻击时间线、生成 HTML/TXT/CSV 报告。  
> 本工具不执行查杀、不自动清理系统，不替代 EDR、杀毒软件或专业取证工具。

---

## 核心更新

### 1. 新增证据链评分

v0.7 系列新增证据链评分模块，可对不同攻击场景进行综合评分，包括：

- 挖矿 / 资源滥用
- 持久化后门 / 自启动控制
- 账户入侵 / 隐藏用户
- 口令猜测 / 凭证攻击
- 脚本执行 / 投放链路

评分会结合进程、服务、计划任务、启动项、账户、日志、矿池配置、投放 URL 等线索，辅助判断风险优先级。

### 2. 新增处置建议生成器

报告中新增处置建议区域，支持生成以下类型建议：

- 可疑服务禁用建议
- 可疑计划任务禁用建议
- 可疑启动项删除建议
- Winlogon 隐藏账户注册表项移除建议
- 可疑账户禁用建议
- 高危文件 Hash 计算建议

所有处置命令仅作为人工复核参考，不会自动执行。

### 3. 修复 Startup LNK 处置建议

修复 v0.7.0 中 Startup LNK 处置建议错误指向系统解释器的问题。

现在对于 Startup 目录下的 `.lnk` 文件，会建议删除 `.lnk` 本体，而不是误删 `wscript.exe`、`powershell.exe` 等系统解释器。

### 4. 修复服务处置建议

服务处置建议现在优先使用 `Win32_Service.Name`，避免仅使用 DisplayName 导致 `sc.exe stop` / `sc.exe config` 命令执行失败。

### 5. 优化高危文件 Hash 建议

降低系统解释器本体的噪音，例如：

- `wscript.exe`
- `cmd.exe`
- `powershell.exe`
- `mshta.exe`

重点关注它们执行的脚本、配置文件和样本文件。

### 6. 增强隐藏账户评分

当发现 Winlogon `SpecialAccounts\UserList` 隐藏账户项时，账户入侵证据链会提升到高危级别，避免隐藏账户被低估。

---

## 使用方法

以管理员身份打开 PowerShell，运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\WinIR-Helper.ps1 -ExportDetails -CpuSampleSeconds 15
