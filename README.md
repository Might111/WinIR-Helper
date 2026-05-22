# WinIR-Helper

> 基于 PowerShell 的 Windows 应急响应辅助分析脚本，用于蓝队初期排查、靶场复盘和应急响应线索整理。

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![Version](https://img.shields.io/badge/Version-v0.5.0--beta-orange)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 项目简介

**WinIR-Helper** 是一个基于 PowerShell 编写的 Windows 应急响应辅助分析脚本。

本工具主要用于在应急响应初期快速收集和分析 Windows 主机中的关键安全线索，包括登录失败、远程登录、服务安装、计划任务、启动项、危险端口、资源异常进程以及挖矿相关配置等内容。

从 `v0.5.0-beta` 开始，工具不再只是简单导出日志，而是尝试将分散的安全事件、进程、服务、端口和持久化信息进行聚合，形成更适合复盘分析的攻击场景判断。

---

## 当前版本

```text
v0.5.0-beta
v0.4 为内部测试版本，主要用于规则重构、误报修复和场景聚合逻辑验证，未单独发布。
v0.5 在 v0.3 的基础上进行了较大重构，因此作为 beta 版本发布。

主要功能
1. Windows 登录行为分析
登录失败事件分析
登录成功事件分析
登录失败来源 IP 统计
疑似攻击开始时间判断
目标账户统计
登录方式识别

支持重点分析：

4624 登录成功
4625 登录失败
4648 显式凭据登录
4672 特权登录
2. RDP 远程登录攻击分析

支持关联以下事件和线索：

4625 登录失败
4624 登录成功
1149 RDP 认证成功
21 RDP 会话连接成功
24 RDP 会话断开
25 RDP 会话重连
3389 端口监听

可辅助判断：

疑似 RDP 暴力破解
疑似远程桌面登录成功
同源 IP 登录失败后成功
RDP 相关事件是否与攻击 IP 对应
3. SMB / NTLM 网络登录爆破辅助判断

当发现大量 LogonType 3 登录失败，并且主机存在 SMB 相关端口监听时，工具会辅助判断是否存在：

SMB / NTLM 网络登录爆破

重点关注端口：

445 SMB
135 RPC
139 NetBIOS
4. 危险监听端口扫描

工具会检测主机当前监听的高风险端口，例如：

3389  RDP 远程桌面
445   SMB 文件共享
5985  WinRM HTTP
5986  WinRM HTTPS
135   RPC
139   NetBIOS
3306  MySQL
1433  MSSQL
6379  Redis
9200  Elasticsearch
27017 MongoDB

注意：端口处于监听状态不代表一定公网可访问，还需要结合 Windows 防火墙、云安全组、路由器端口映射等信息综合判断。

5. 服务安装事件分析

支持分析：

7045 新服务安装

可辅助发现：

可疑服务安装
随机命名驱动服务
挖矿相关服务
WinRing0 驱动服务
nssm 服务包装器
服务型持久化线索
6. 启动项与计划任务检查

支持检查：

注册表 Run 启动项
RunOnce 启动项
Startup 启动文件夹
Windows 计划任务

重点关注：

AppData
ProgramData
Users\Public
Windows\Temp
Temp
.bat
.cmd
.ps1
.vbs
.js
.hta

可辅助发现：

可疑启动项持久化
可疑计划任务持久化
脚本型启动项
挖矿或后门程序自启动
7. 资源异常进程综合评分

工具会结合以下因素对进程进行综合评分：

CPU 占用
内存占用
公网连接数量
进程路径
命令行特征
是否命中挖矿相关路径或关键词

不会单纯因为 cmd.exe、powershell.exe 等系统工具进程名就直接报警。

重点关注：

xmrig
miner
c3pool
WinRing0
nssm
stratum
monero
8. 挖矿配置提取

当工具识别到疑似挖矿目录后，会进一步尝试从相关配置文件中提取：

矿池地址
钱包地址
配置文件路径
启动参数
相关上下文

支持分析常见配置文件：

.json
.conf
.config
.txt
.bat
.cmd
.ps1
.ini
.yml
.yaml
.xml

示例输出：

矿池地址：auto.c3pool.org:80
钱包地址：xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
配置文件：C:\Users\Administrator\c3pool\config.json
攻击场景聚合判断

当前版本支持以下场景判断：

疑似 RDP 暴力破解 / 远程桌面攻击
疑似 SMB / NTLM 网络登录爆破
疑似挖矿木马 / 资源滥用
疑似持久化行为
疑似账户权限变更

工具会将登录日志、RDP 事件、端口状态、进程、服务、启动项、计划任务和挖矿配置进行聚合，尽量输出更接近应急响应复盘的结论。

使用方式
1. 管理员权限运行 PowerShell

建议右键 PowerShell，选择：

以管理员身份运行
2. 临时绕过执行策略
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
3. 运行脚本
.\WinIR-Helper.ps1
4. 指定分析时间范围

例如分析最近 1000 天：

.\WinIR-Helper.ps1 -Days 1000
5. 导出详细 CSV
.\WinIR-Helper.ps1 -Days 1000 -ExportDetails
常用参数
参数	说明
-Days	指定向前分析多少天，默认 365 天
-StartTime	指定开始时间
-EndTime	指定结束时间
-OutputDir	指定输出目录
-ExportDetails	导出详细 CSV 明细
-AllowNonAdmin	允许非管理员权限运行，但结果可能不完整
-NoHash	不计算文件 Hash，提高运行速度
-CpuSampleSeconds	CPU 采样秒数，默认 3 秒
输出文件

默认输出：

WinIR_Report.html
WinIR_Summary.txt
攻击场景判断.csv
重点关注项.csv

开启 -ExportDetails 后，会额外输出详细 CSV，例如：

安全事件明细.csv
登录失败来源IP统计.csv
RDP事件.csv
7045_服务安装事件.csv
进程明细.csv
网络连接.csv
资源异常进程.csv
危险监听端口.csv
挖矿配置提取.csv
可疑启动项.csv
可疑计划任务.csv
报告查看建议

优先查看：

WinIR_Report.html

重点关注以下模块：

一、攻击场景判断
二、重点关注项
四、登录失败来源 IP Top
五、RDP 相关事件
六、危险监听端口
七、资源异常进程综合评分
八、挖矿配置提取
九、服务安装线索
十、可疑启动项
十一、可疑计划任务
使用场景

本工具适合用于：

Windows 应急响应初期排查
蓝队靶场复盘
登录爆破分析
RDP 远程登录排查
挖矿木马线索分析
可疑持久化排查
主机基础安全巡检
安全学习与博客复盘
注意事项

本工具只做：

辅助取证
线索整理
场景聚合
报告生成

本工具不做：

木马查杀
WebShell 查杀
病毒清除
自动处置
最终定性

请不要将本工具作为杀毒软件、EDR、D盾、河马等专业安全工具的替代品。

最终结论仍需要结合：

业务环境
防火墙日志
EDR / 杀软告警
网络流量
文件 Hash
人工分析

进行综合判断。

版本演进
版本	状态	说明
v0.1	早期测试	基础 Windows 日志采集
v0.2	早期测试	增加账户、管理员组、登录失败统计
v0.3	已发布	增加 Web 应急线索、Web 目录识别、挖矿 IOC 初步提取
v0.4	内部测试	重构 Windows 安全事件、进程、端口和资源异常规则，未单独发布
v0.5.0-beta	当前版本	新增攻击场景聚合分析、RDP 爆破判断、挖矿配置提取、持久化线索聚合
后续计划
v0.5.1
攻击时间线自动生成
服务安装事件去重
4648 显式凭据登录进一步降噪
挖矿组件和真正挖矿进程分类展示
v0.5.2
增加白名单机制
支持用户自定义忽略项
支持规则开关
v0.6
强化离线 EVTX 文件夹分析
更适合 BTLO、CyberDefenders、蓝队靶场题目复盘
v0.7
GUI Lite 图形化界面
支持选择日志目录
支持表格筛选
支持一键打开报告
免责声明

本项目仅用于合法授权环境下的安全学习、蓝队应急响应和靶场复盘。

请勿将本工具用于未授权系统。
使用者应自行承担因使用本工具造成的任何风险与后果。

License

MIT License
