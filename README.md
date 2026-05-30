# WinIR-Helper v0.8.8-beta

## Release Title

WinIR-Helper v0.8.8-beta：模块化重构收口版

## Release Notes

本版本是 v0.8 模块化重构系列的收口修正版。v0.8 的主要目标不是继续堆叠检测规则，而是将 WinIR-Helper 从单文件应急脚本整理为更容易维护、更容易交付、更适合后续扩展的模块化工具。

v0.8.8-beta 重点修复了 v0.8.7 中摘要建议文本换行导致的 PowerShell ParserError，并继续完善事件读取状态判断、虚拟化组件降噪和报告可信度。

## 主要变化

### 1. 修复 v0.8.7 ParserError

修复 v0.8.7 中摘要建议文本跨行写入导致的 PowerShell 解析错误。

现在 `dist/WinIR-Helper.ps1` 可以在 Windows PowerShell 5.1 下正常运行。

### 2. 区分 NoMatch 与 Failed

事件读取状态现在分为：

```text
完成：成功读取到事件
无匹配：日志可读取，但时间窗口内没有指定事件
失败：权限、参数、通道不可读或查询语法异常
```

这可以避免将“没有 RDP 1149 事件”或“没有 PowerShell 4103/4104 事件”误判为日志读取失败。

### 3. 数据完整性判断优化

报告新增并完善“数据完整性与事件日志读取状态”模块，会展示：

* 日志通道是否可读取
* 日志是否启用
* 记录数量
* 最新事件时间
* 最新事件 ID
* 每组查询的读取状态
* 是否存在真正读取异常

只有真实查询失败才会影响数据完整性判断。

### 4. Hyper-V / WSL / Docker / vmswitch 降噪

v0.8.8 默认对常见虚拟化和容器相关组件进行降噪，包括：

* Hyper-V
* WSL
* Docker Desktop
* vmswitch.sys
* VMSMP
* 虚拟交换机相关服务

这些组件不再被误判为随机命名驱动服务，也不会直接生成禁用建议。

### 5. 安全测试组件降噪

继续对常见安全测试组件进行降噪，例如：

* Acunetix
* Nessus / Tenable
* Npcap
* BurpSuite / PortSwigger
* 本地 localhost 服务
* 本地代理和测试浏览器

减少安全测试环境中的误报。

### 6. 威胁项与暴露面风险分开

报告首页现在分开展示：

```text
威胁高危项
威胁中危项
暴露面风险
数据完整性
```

端口监听不再直接等同于入侵威胁。
例如 3306、445、135、139 等端口会归入暴露面风险，需要结合 Windows 防火墙、云安全组、NAT、端口映射进一步确认是否对外开放。

### 7. 处置建议更加保守

所有处置命令仍然只作为人工复核建议，不会自动执行。

对于系统服务、虚拟化组件、安全工具、反作弊驱动、扫描器组件，默认只建议复核签名、Hash、路径、创建时间和业务归属，不直接建议禁用。

## 使用方式

解压后运行：

```powershell
.\Run-WinIR-Helper.cmd
```

或者运行 dist 单文件版：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\dist\WinIR-Helper.ps1"
```

指定扫描天数：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\dist\WinIR-Helper.ps1" -Days 30
```

导出详细 CSV：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\dist\WinIR-Helper.ps1" -ExportDetails
```

## 输出文件

运行完成后会生成：

```text
WinIR_Report.html       HTML 应急响应报告
WinIR_Summary.txt       文本摘要
攻击场景判断.csv
重点关注项.csv
其他明细 CSV
```

## 项目结构

```text
WinIR-Helper.ps1                  模块化主入口
modules/                          功能模块
config/                           配置文件
build/                            单文件打包脚本
dist/WinIR-Helper.ps1             发布用单文件版
Run-WinIR-Helper.cmd              一键运行入口
```

## 注意事项

WinIR-Helper 是 Windows 应急响应辅助工具，不是杀毒软件，不会自动查杀或清理系统。

报告中的风险项、评分和处置建议都需要人工复核。生产环境中请先留证，再确认业务归属和变更窗口，最后再执行禁用服务、删除任务或停止进程等操作。

## 推荐升级

建议 v0.8.x 用户升级到 v0.8.8-beta。
该版本修复了 v0.8.7 的语法错误，并完成了 v0.8 模块化重构阶段的主要收口工作。
