# WinIR-Helper
基于 PowerShell 的 Windows 应急响应信息收集脚本

param(
    [int]$Days = 7,
    [int]$FailedThreshold = 10
)

# ==============================
# WinIR-Helper v0.1
# Windows 应急响应信息收集脚本
# 功能：登录日志、来源IP统计、高危IP筛选、危险端口警报、用户、启动项、计划任务、网络连接
# ==============================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$采集时间 = Get-Date -Format "yyyyMMdd_HHmmss"
$输出目录 = Join-Path (Get-Location) "WinIR_应急响应结果_$采集时间"

New-Item -ItemType Directory -Path $输出目录 -Force | Out-Null

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "        WinIR-Helper  应急采集工具" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "[+] 输出目录：$输出目录" -ForegroundColor Green
Write-Host "[+] 日志范围：最近 $Days 天" -ForegroundColor Green
Write-Host "[+] 高危 IP 阈值：单个 IP 登录失败次数 >= $FailedThreshold" -ForegroundColor Green
Write-Host ""

# 检查是否管理员权限运行
$当前用户 = [Security.Principal.WindowsIdentity]::GetCurrent()
$权限对象 = New-Object Security.Principal.WindowsPrincipal($当前用户)
$是否管理员 = $权限对象.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $是否管理员) {
    Write-Host "[!] 当前不是管理员权限，部分日志可能无法正常导出。" -ForegroundColor Yellow
    Write-Host "[!] 建议右键 PowerShell，选择“以管理员身份运行”。" -ForegroundColor Yellow
    Write-Host ""
}

# CSV 导出函数，尽量避免中文乱码
function 导出CSV {
    param(
        [Parameter(ValueFromPipeline = $true)]
        $输入对象,

        [Parameter(Mandatory = $true)]
        [string]$路径
    )

    begin {
        $集合 = @()
    }

    process {
        if ($null -ne $输入对象) {
            $集合 += $输入对象
        }
    }

    end {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $集合 | Export-Csv -Path $路径 -NoTypeInformation -Encoding utf8BOM
        } else {
            $集合 | Export-Csv -Path $路径 -NoTypeInformation -Encoding UTF8
        }
    }
}

# 将 Windows 事件日志中的 EventData 转换为对象
function 转换事件数据 {
    param(
        [Parameter(Mandatory = $true)]
        $事件
    )

    [xml]$Xml = $事件.ToXml()
    $数据 = [ordered]@{}
    $序号 = 0

    foreach ($项 in $Xml.Event.EventData.Data) {
        $名称 = [string]$项.Name

        if ([string]::IsNullOrWhiteSpace($名称)) {
            $名称 = "Data$序号"
        }

        if ($数据.Contains($名称)) {
            $名称 = "$名称$序号"
        }

        $数据[$名称] = $项.'#text'
        $序号++
    }

    return [PSCustomObject]$数据
}

# 获取登录事件
function 获取登录事件 {
    param(
        [int]$事件ID,
        [int]$天数
    )

    $开始时间 = (Get-Date).AddDays(-$天数)

    try {
        $事件列表 = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = $事件ID
            StartTime = $开始时间
        } -ErrorAction Stop
    } catch {
        Write-Host "[!] 读取安全日志失败，事件 ID：$事件ID" -ForegroundColor Yellow
        return @()
    }

    $结果 = foreach ($事件 in $事件列表) {
        $数据 = 转换事件数据 -事件 $事件

        [PSCustomObject]@{
            时间       = $事件.TimeCreated
            事件ID     = $事件.Id
            用户名     = $数据.TargetUserName
            域名       = $数据.TargetDomainName
            登录类型   = $数据.LogonType
            来源IP     = $数据.IpAddress
            工作站名   = $数据.WorkstationName
            进程名     = $数据.ProcessName
            状态码     = $数据.Status
            子状态码   = $数据.SubStatus
        }
    }

    return $结果
}

# ==============================
# 1. 导出 4624 登录成功日志
# ==============================

Write-Host "[+] 正在导出 4624 登录成功日志..." -ForegroundColor Cyan
$登录成功日志 = 获取登录事件 -事件ID 4624 -天数 $Days
$登录成功日志 | 导出CSV -路径 "$输出目录\4624_登录成功日志.csv"

# ==============================
# 2. 导出 4625 登录失败日志
# ==============================

Write-Host "[+] 正在导出 4625 登录失败日志..." -ForegroundColor Cyan
$登录失败日志 = 获取登录事件 -事件ID 4625 -天数 $Days
$登录失败日志 | 导出CSV -路径 "$输出目录\4625_登录失败日志.csv"

# ==============================
# 3. 统计来源 IP
# ==============================

Write-Host "[+] 正在统计来源 IP..." -ForegroundColor Cyan

$排除IP = @("-", "127.0.0.1", "::1", "::", "0.0.0.0", "")

$全部IP记录 = @()

$全部IP记录 += $登录成功日志 | Where-Object {
    $_.来源IP -and ($排除IP -notcontains $_.来源IP)
} | Select-Object 时间, 事件ID, 用户名, 来源IP, 登录类型

$全部IP记录 += $登录失败日志 | Where-Object {
    $_.来源IP -and ($排除IP -notcontains $_.来源IP)
} | Select-Object 时间, 事件ID, 用户名, 来源IP, 登录类型

$中危阈值 = [Math]::Max(3, [int][Math]::Ceiling($FailedThreshold / 2))

$来源IP统计 = foreach ($分组 in ($全部IP记录 | Group-Object 来源IP)) {

    $成功次数 = @($分组.Group | Where-Object { $_.事件ID -eq 4624 }).Count
    $失败次数 = @($分组.Group | Where-Object { $_.事件ID -eq 4625 }).Count
    $总次数 = $分组.Count

    $首次发现 = ($分组.Group | Sort-Object 时间 | Select-Object -First 1).时间
    $最后发现 = ($分组.Group | Sort-Object 时间 -Descending | Select-Object -First 1).时间

    $风险等级 = "低危"
    $风险原因 = "暂未发现明显异常"

    if ($失败次数 -ge $FailedThreshold -and $成功次数 -gt 0) {
        $风险等级 = "高危"
        $风险原因 = "该 IP 出现大量登录失败后又出现登录成功，疑似爆破成功"
    } elseif ($失败次数 -ge $FailedThreshold) {
        $风险等级 = "高危"
        $风险原因 = "该 IP 登录失败次数超过阈值，疑似暴力破解"
    } elseif ($失败次数 -ge $中危阈值) {
        $风险等级 = "中危"
        $风险原因 = "该 IP 存在多次登录失败，建议继续观察"
    } elseif ($失败次数 -gt 0 -and $成功次数 -gt 0) {
        $风险等级 = "中危"
        $风险原因 = "该 IP 同时存在登录失败和登录成功，需要核对是否为正常管理员行为"
    }

    [PSCustomObject]@{
        来源IP   = $分组.Name
        总次数   = $总次数
        成功次数 = $成功次数
        失败次数 = $失败次数
        首次发现 = $首次发现
        最后发现 = $最后发现
        风险等级 = $风险等级
        风险原因 = $风险原因
    }
}

$来源IP统计 = $来源IP统计 | Sort-Object 失败次数, 总次数 -Descending
$来源IP统计 | 导出CSV -路径 "$输出目录\来源IP统计.csv"

# ==============================
# 4. 高危 IP 筛选
# ==============================

Write-Host "[+] 正在筛选高危 IP..." -ForegroundColor Cyan

$高危IP = $来源IP统计 | Where-Object {
    $_.风险等级 -eq "高危"
}

if (@($高危IP).Count -gt 0) {
    $高危IP | 导出CSV -路径 "$输出目录\高危IP筛选.csv"
    Write-Host "[!] 发现高危 IP：$(@($高危IP).Count) 个" -ForegroundColor Red
} else {
    [PSCustomObject]@{
        提示 = "未发现高危 IP"
        判断规则 = "单个 IP 登录失败次数 >= $FailedThreshold，或大量失败后出现登录成功"
    } | 导出CSV -路径 "$输出目录\高危IP筛选.csv"

    Write-Host "[+] 未发现高危 IP。" -ForegroundColor Green
}

# ==============================
# 5. 查看本地用户
# ==============================

Write-Host "[+] 正在导出本地用户..." -ForegroundColor Cyan

try {
    Get-LocalUser |
        Select-Object @{
            Name = "用户名"
            Expression = { $_.Name }
        }, @{
            Name = "是否启用"
            Expression = { $_.Enabled }
        }, @{
            Name = "最后登录时间"
            Expression = { $_.LastLogon }
        }, @{
            Name = "密码最后设置时间"
            Expression = { $_.PasswordLastSet }
        }, @{
            Name = "是否需要密码"
            Expression = { $_.PasswordRequired }
        }, @{
            Name = "用户是否可改密码"
            Expression = { $_.UserMayChangePassword }
        }, @{
            Name = "描述"
            Expression = { $_.Description }
        } |
        导出CSV -路径 "$输出目录\本地用户.csv"
} catch {
    Write-Host "[!] 本地用户导出失败。" -ForegroundColor Yellow
    "本地用户导出失败。" | Out-File "$输出目录\本地用户_错误.txt" -Encoding UTF8
}

# ==============================
# 6. 查看管理员组成员
# ==============================

Write-Host "[+] 正在导出管理员组成员..." -ForegroundColor Cyan

try {
    $管理员组 = Get-LocalGroup | Where-Object {
        $_.SID.Value -eq "S-1-5-32-544" -or $_.SID -eq "S-1-5-32-544"
    }

    if ($管理员组) {
        Get-LocalGroupMember -Group $管理员组.Name |
            Select-Object @{
                Name = "成员名称"
                Expression = { $_.Name }
            }, @{
                Name = "对象类型"
                Expression = { $_.ObjectClass }
            }, @{
                Name = "来源"
                Expression = { $_.PrincipalSource }
            } |
            导出CSV -路径 "$输出目录\管理员组成员.csv"
    } else {
        "未找到本地管理员组。" | Out-File "$输出目录\管理员组成员.txt" -Encoding UTF8
    }
} catch {
    Write-Host "[!] 管理员组成员导出失败。" -ForegroundColor Yellow
    "管理员组成员导出失败。" | Out-File "$输出目录\管理员组成员_错误.txt" -Encoding UTF8
}

# ==============================
# 7. 查看启动项
# ==============================

Write-Host "[+] 正在导出启动项..." -ForegroundColor Cyan

try {
    Get-CimInstance Win32_StartupCommand |
        Select-Object @{
            Name = "启动项名称"
            Expression = { $_.Name }
        }, @{
            Name = "启动命令"
            Expression = { $_.Command }
        }, @{
            Name = "启动位置"
            Expression = { $_.Location }
        }, @{
            Name = "所属用户"
            Expression = { $_.User }
        } |
        导出CSV -路径 "$输出目录\启动项.csv"
} catch {
    Write-Host "[!] 启动项导出失败。" -ForegroundColor Yellow
    "启动项导出失败。" | Out-File "$输出目录\启动项_错误.txt" -Encoding UTF8
}

# ==============================
# 8. 查看计划任务
# ==============================

Write-Host "[+] 正在导出计划任务..." -ForegroundColor Cyan

try {
    Get-ScheduledTask |
        Select-Object @{
            Name = "任务名称"
            Expression = { $_.TaskName }
        }, @{
            Name = "任务路径"
            Expression = { $_.TaskPath }
        }, @{
            Name = "任务状态"
            Expression = { $_.State }
        }, @{
            Name = "作者"
            Expression = { $_.Author }
        }, @{
            Name = "执行动作"
            Expression = {
                ($_.Actions | ForEach-Object {
                    "$($_.Execute) $($_.Arguments)"
                }) -join " | "
            }
        } |
        导出CSV -路径 "$输出目录\计划任务.csv"
} catch {
    Write-Host "[!] 计划任务导出失败。" -ForegroundColor Yellow
    "计划任务导出失败。" | Out-File "$输出目录\计划任务_错误.txt" -Encoding UTF8
}

# ==============================
# 9. 当前网络连接
# ==============================

Write-Host "[+] 正在导出当前网络连接..." -ForegroundColor Cyan

try {
    $网络连接 = Get-NetTCPConnection |
        ForEach-Object {
            $连接 = $_

            try {
                $进程名 = (Get-Process -Id $连接.OwningProcess -ErrorAction Stop).ProcessName
            } catch {
                $进程名 = "未知进程"
            }

            [PSCustomObject]@{
                本地地址 = $连接.LocalAddress
                本地端口 = $连接.LocalPort
                远程地址 = $连接.RemoteAddress
                远程端口 = $连接.RemotePort
                连接状态 = $连接.State
                进程ID   = $连接.OwningProcess
                进程名   = $进程名
            }
        }

    $网络连接 | 导出CSV -路径 "$输出目录\当前网络连接.csv"
} catch {
    Write-Host "[!] 当前网络连接导出失败。" -ForegroundColor Yellow
    "当前网络连接导出失败。" | Out-File "$输出目录\当前网络连接_错误.txt" -Encoding UTF8
    $网络连接 = @()
}

# ==============================
# 10. 危险端口警报
# ==============================

Write-Host "[+] 正在进行危险端口检查..." -ForegroundColor Cyan

$危险端口说明 = @{
    21    = @{ 服务 = "FTP"; 风险等级 = "高危"; 说明 = "文件传输服务，可能存在弱口令或明文传输风险" }
    22    = @{ 服务 = "SSH"; 风险等级 = "中危"; 说明 = "远程管理服务，需确认是否允许外部访问" }
    23    = @{ 服务 = "Telnet"; 风险等级 = "高危"; 说明 = "明文远程登录服务，风险较高" }
    25    = @{ 服务 = "SMTP"; 风险等级 = "中危"; 说明 = "邮件服务端口，需确认是否为正常业务" }
    53    = @{ 服务 = "DNS"; 风险等级 = "中危"; 说明 = "域名解析服务，需确认是否为正常业务" }
    80    = @{ 服务 = "HTTP"; 风险等级 = "中危"; 说明 = "Web 服务端口，需确认是否为正常业务" }
    110   = @{ 服务 = "POP3"; 风险等级 = "中危"; 说明 = "邮件接收服务，可能存在明文认证风险" }
    135   = @{ 服务 = "RPC"; 风险等级 = "高危"; 说明 = "Windows RPC 服务，暴露到公网风险较高" }
    139   = @{ 服务 = "NetBIOS"; 风险等级 = "高危"; 说明 = "Windows 文件共享相关端口，暴露风险较高" }
    143   = @{ 服务 = "IMAP"; 风险等级 = "中危"; 说明 = "邮件服务端口，需确认是否为正常业务" }
    389   = @{ 服务 = "LDAP"; 风险等级 = "高危"; 说明 = "目录服务端口，域环境中需要重点关注" }
    443   = @{ 服务 = "HTTPS"; 风险等级 = "中危"; 说明 = "Web 加密服务端口，需确认是否为正常业务" }
    445   = @{ 服务 = "SMB"; 风险等级 = "高危"; 说明 = "Windows 文件共享端口，常被用于横向移动和漏洞利用" }
    1433  = @{ 服务 = "MSSQL"; 风险等级 = "高危"; 说明 = "SQL Server 数据库端口，需排查弱口令和公网暴露" }
    1521  = @{ 服务 = "Oracle"; 风险等级 = "高危"; 说明 = "Oracle 数据库端口，需确认访问来源" }
    3306  = @{ 服务 = "MySQL"; 风险等级 = "高危"; 说明 = "MySQL 数据库端口，需排查弱口令和公网暴露" }
    3389  = @{ 服务 = "RDP"; 风险等级 = "高危"; 说明 = "远程桌面端口，常见爆破目标" }
    5432  = @{ 服务 = "PostgreSQL"; 风险等级 = "高危"; 说明 = "PostgreSQL 数据库端口，需排查弱口令和公网暴露" }
    5900  = @{ 服务 = "VNC"; 风险等级 = "高危"; 说明 = "远程控制服务端口，需确认是否授权" }
    6379  = @{ 服务 = "Redis"; 风险等级 = "高危"; 说明 = "Redis 服务端口，公网暴露风险极高" }
    8080  = @{ 服务 = "HTTP-Proxy/Tomcat"; 风险等级 = "中危"; 说明 = "常见 Web 或代理端口，需确认是否为正常业务" }
    9200  = @{ 服务 = "Elasticsearch"; 风险等级 = "高危"; 说明 = "Elasticsearch 服务端口，未授权访问风险较高" }
    11211 = @{ 服务 = "Memcached"; 风险等级 = "高危"; 说明 = "Memcached 服务端口，公网暴露风险较高" }
    27017 = @{ 服务 = "MongoDB"; 风险等级 = "高危"; 说明 = "MongoDB 数据库端口，需排查未授权访问" }
}

$危险端口告警 = @()

foreach ($连接 in $网络连接) {

    $本地端口 = [int]$连接.本地端口
    $远程端口 = [int]$连接.远程端口

    if ($危险端口说明.ContainsKey($本地端口)) {
        $端口信息 = $危险端口说明[$本地端口]

        $建议 = "确认该本地端口是否为业务必需；如果不需要，建议关闭对应服务或使用防火墙限制访问来源。"

        if ($连接.连接状态 -eq "Listen") {
            $建议 = "该端口处于监听状态，建议重点确认是否对外开放，以及是否存在弱口令或未授权访问风险。"
        }

        $危险端口告警 += [PSCustomObject]@{
            检测位置 = "本地端口"
            端口 = $本地端口
            服务 = $端口信息["服务"]
            风险等级 = $端口信息["风险等级"]
            风险说明 = $端口信息["说明"]
            本地地址 = $连接.本地地址
            本地端口 = $连接.本地端口
            远程地址 = $连接.远程地址
            远程端口 = $连接.远程端口
            连接状态 = $连接.连接状态
            进程ID = $连接.进程ID
            进程名 = $连接.进程名
            安全建议 = $建议
        }
    }

    if ($远程端口 -ne 0 -and $危险端口说明.ContainsKey($远程端口)) {
        $端口信息 = $危险端口说明[$远程端口]

        $危险端口告警 += [PSCustomObject]@{
            检测位置 = "远程端口"
            端口 = $远程端口
            服务 = $端口信息["服务"]
            风险等级 = $端口信息["风险等级"]
            风险说明 = $端口信息["说明"]
            本地地址 = $连接.本地地址
            本地端口 = $连接.本地端口
            远程地址 = $连接.远程地址
            远程端口 = $连接.远程端口
            连接状态 = $连接.连接状态
            进程ID = $连接.进程ID
            进程名 = $连接.进程名
            安全建议 = "本机正在连接该远程端口，建议确认是否为正常业务连接，排查异常外联或远程控制行为。"
        }
    }
}

if (@($危险端口告警).Count -gt 0) {
    $危险端口告警 |
        Sort-Object 风险等级, 端口 |
        导出CSV -路径 "$输出目录\危险端口警报.csv"

    Write-Host "[!] 发现危险端口告警：$(@($危险端口告警).Count) 条" -ForegroundColor Red
} else {
    [PSCustomObject]@{
        提示 = "未发现危险端口连接或监听"
    } | 导出CSV -路径 "$输出目录\危险端口警报.csv"

    Write-Host "[+] 未发现危险端口告警。" -ForegroundColor Green
}

# ==============================
# 11. 生成采集摘要
# ==============================

$登录成功数量 = @($登录成功日志).Count
$登录失败数量 = @($登录失败日志).Count
$来源IP数量 = @($来源IP统计).Count
$高危IP数量 = @($高危IP).Count
$危险端口数量 = @($危险端口告警).Count

$摘要 = @"
WinIR-Helper v0.1 应急响应采集摘要

采集时间：$(Get-Date)
日志范围：最近 $Days 天
高危 IP 判断阈值：单个 IP 登录失败次数 >= $FailedThreshold

一、登录日志统计
4624 登录成功日志数量：$登录成功数量
4625 登录失败日志数量：$登录失败数量

二、来源 IP 统计
来源 IP 数量：$来源IP数量
高危 IP 数量：$高危IP数量

三、危险端口检查
危险端口告警数量：$危险端口数量

四、输出文件说明
1. 4624_登录成功日志.csv：Windows 登录成功日志
2. 4625_登录失败日志.csv：Windows 登录失败日志
3. 来源IP统计.csv：统计每个来源 IP 的成功和失败次数
4. 高危IP筛选.csv：自动筛选疑似爆破或异常登录 IP
5. 本地用户.csv：当前主机本地用户
6. 管理员组成员.csv：本地管理员组成员
7. 启动项.csv：系统启动项
8. 计划任务.csv：系统计划任务
9. 当前网络连接.csv：当前 TCP 网络连接
10. 危险端口警报.csv：危险端口连接或监听情况

五、注意
该工具只做自动化初筛，不能直接作为最终结论。
高危 IP 和危险端口需要结合实际业务、登录时间、用户名、进程路径进一步判断。
"@

$摘要 | Out-File "$输出目录\采集摘要.txt" -Encoding UTF8

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "[+] 信息采集完成！" -ForegroundColor Green
Write-Host "[+] 登录成功日志数量：$登录成功数量" -ForegroundColor Green
Write-Host "[+] 登录失败日志数量：$登录失败数量" -ForegroundColor Green
Write-Host "[+] 高危 IP 数量：$高危IP数量" -ForegroundColor Green
Write-Host "[+] 危险端口告警数量：$危险端口数量" -ForegroundColor Green
Write-Host "[+] 结果目录：$输出目录" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
