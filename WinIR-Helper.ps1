param(
    [int]$Days = 7,
    [int]$FailedThreshold = 10,
    [switch]$AllowNonAdmin
)

# ==============================
# WinIR-Helper v0.2
# Windows 应急响应信息收集脚本
# 更新重点：管理员权限检测增强、危险端口初筛降噪
# 注意：建议使用 UTF-8 with BOM 保存本脚本
# ==============================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$Version = "v0.2"
$CollectTime = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputDir = Join-Path (Get-Location) "WinIR_应急响应结果_$CollectTime"

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "        WinIR-Helper $Version 应急采集工具" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "[+] 输出目录：$OutputDir" -ForegroundColor Green
Write-Host "[+] 日志范围：最近 $Days 天" -ForegroundColor Green
Write-Host "[+] 高危 IP 阈值：单个 IP 登录失败次数 >= $FailedThreshold" -ForegroundColor Green
Write-Host ""

# ==============================
# 0. 管理员权限检测
# ==============================

$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
$IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin -and -not $AllowNonAdmin) {
    Write-Host "[!] 当前不是管理员权限，无法可靠读取 Security 安全日志。" -ForegroundColor Red
    Write-Host "[!] 请右键 PowerShell，选择“以管理员身份运行”后重新执行脚本。" -ForegroundColor Yellow
    Write-Host "[!] 如果只是测试非日志功能，可以使用参数：-AllowNonAdmin" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "示例：" -ForegroundColor Cyan
    Write-Host "    .\WinIR-Helper.ps1" -ForegroundColor Cyan
    Write-Host "    .\WinIR-Helper.ps1 -Days 30 -FailedThreshold 20" -ForegroundColor Cyan
    Write-Host "    .\WinIR-Helper.ps1 -AllowNonAdmin" -ForegroundColor Cyan
    Write-Host ""

    $PermissionNotice = @"
WinIR-Helper $Version 权限检测结果

当前运行状态：非管理员权限
处理结果：脚本已主动退出
原因说明：读取 Windows Security 安全日志通常需要管理员权限。为了避免生成关键日志为空的误导性结果，v0.2 默认在非管理员权限下停止执行。

解决方法：
1. 右键 PowerShell
2. 选择“以管理员身份运行”
3. 重新执行脚本

测试参数：
如果仅需测试非日志采集功能，可以运行：
.\WinIR-Helper.ps1 -AllowNonAdmin
"@

    $PermissionNotice | Out-File "$OutputDir\权限检测说明.txt" -Encoding UTF8
    Start-Sleep -Seconds 3
    exit 1
}

if (-not $IsAdmin -and $AllowNonAdmin) {
    Write-Host "[!] 当前为非管理员权限，但已启用 -AllowNonAdmin，脚本将继续执行。" -ForegroundColor Yellow
    Write-Host "[!] 注意：Security 安全日志可能无法正常读取。" -ForegroundColor Yellow
    Write-Host ""
}

# ==============================
# 通用函数
# ==============================

function Export-ChineseCsv {
    param(
        [Parameter(ValueFromPipeline = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    begin {
        $List = @()
    }

    process {
        if ($null -ne $InputObject) {
            $List += $InputObject
        }
    }

    end {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $List | Export-Csv -Path $Path -NoTypeInformation -Encoding utf8BOM
        } else {
            $List | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        }
    }
}

function Convert-EventData {
    param(
        [Parameter(Mandatory = $true)]
        $Event
    )

    [xml]$Xml = $Event.ToXml()
    $Data = [ordered]@{}
    $Index = 0

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Name = [string]$Item.Name

        if ([string]::IsNullOrWhiteSpace($Name)) {
            $Name = "Data$Index"
        }

        if ($Data.Contains($Name)) {
            $Name = "$Name$Index"
        }

        $Data[$Name] = $Item.'#text'
        $Index++
    }

    return [PSCustomObject]$Data
}

function Get-LoginEvents {
    param(
        [int]$EventId,
        [int]$Days
    )

    $StartTime = (Get-Date).AddDays(-$Days)

    try {
        $Events = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = $EventId
            StartTime = $StartTime
        } -ErrorAction Stop
    } catch {
        Write-Host "[!] 读取安全日志失败，事件 ID：$EventId" -ForegroundColor Yellow
        return @()
    }

    $Result = foreach ($Event in $Events) {
        $Data = Convert-EventData -Event $Event

        [PSCustomObject]@{
            "时间"       = $Event.TimeCreated
            "事件ID"     = $Event.Id
            "用户名"     = $Data.TargetUserName
            "域名"       = $Data.TargetDomainName
            "登录类型"   = $Data.LogonType
            "来源IP"     = $Data.IpAddress
            "工作站名"   = $Data.WorkstationName
            "进程名"     = $Data.ProcessName
            "状态码"     = $Data.Status
            "子状态码"   = $Data.SubStatus
        }
    }

    return $Result
}

function Test-InvalidAddress {
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return $true }

    $InvalidAddresses = @(
        "-",
        "*",
        "0.0.0.0",
        "::",
        "::1",
        "127.0.0.1",
        "localhost"
    )

    return ($InvalidAddresses -contains $Address)
}

function Test-PrivateIPv4 {
    param([string]$Address)

    $Ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$Ip)) {
        return $false
    }

    if ($Ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }

    $Bytes = $Ip.GetAddressBytes()

    # 10.0.0.0/8
    if ($Bytes[0] -eq 10) { return $true }

    # 172.16.0.0/12
    if ($Bytes[0] -eq 172 -and $Bytes[1] -ge 16 -and $Bytes[1] -le 31) { return $true }

    # 192.168.0.0/16
    if ($Bytes[0] -eq 192 -and $Bytes[1] -eq 168) { return $true }

    # 169.254.0.0/16
    if ($Bytes[0] -eq 169 -and $Bytes[1] -eq 254) { return $true }

    return $false
}

function Test-PublicRemoteAddress {
    param([string]$Address)

    if (Test-InvalidAddress -Address $Address) { return $false }
    if (Test-PrivateIPv4 -Address $Address) { return $false }

    $Ip = $null
    if ([System.Net.IPAddress]::TryParse($Address, [ref]$Ip)) {
        return $true
    }

    return $false
}

function Get-ProcessNameById {
    param([int]$ProcessId)

    try {
        return (Get-Process -Id $ProcessId -ErrorAction Stop).ProcessName
    } catch {
        return "未知进程"
    }
}

# ==============================
# 1. 导出 4624 登录成功日志
# ==============================

Write-Host "[+] 正在导出 4624 登录成功日志..." -ForegroundColor Cyan
$SuccessLogons = Get-LoginEvents -EventId 4624 -Days $Days
$SuccessLogons | Export-ChineseCsv -Path "$OutputDir\4624_登录成功日志.csv"

# ==============================
# 2. 导出 4625 登录失败日志
# ==============================

Write-Host "[+] 正在导出 4625 登录失败日志..." -ForegroundColor Cyan
$FailedLogons = Get-LoginEvents -EventId 4625 -Days $Days
$FailedLogons | Export-ChineseCsv -Path "$OutputDir\4625_登录失败日志.csv"

# ==============================
# 3. 统计来源 IP
# ==============================

Write-Host "[+] 正在统计来源 IP..." -ForegroundColor Cyan

$ExcludeIps = @("-", "127.0.0.1", "::1", "::", "0.0.0.0", "")
$AllIpRecords = @()

$AllIpRecords += $SuccessLogons | Where-Object {
    $_."来源IP" -and ($ExcludeIps -notcontains $_."来源IP")
} | Select-Object "时间", "事件ID", "用户名", "来源IP", "登录类型"

$AllIpRecords += $FailedLogons | Where-Object {
    $_."来源IP" -and ($ExcludeIps -notcontains $_."来源IP")
} | Select-Object "时间", "事件ID", "用户名", "来源IP", "登录类型"

$MediumThreshold = [Math]::Max(3, [int][Math]::Ceiling($FailedThreshold / 2))

$IpStats = foreach ($Group in ($AllIpRecords | Group-Object "来源IP")) {
    $SuccessCount = @($Group.Group | Where-Object { $_."事件ID" -eq 4624 }).Count
    $FailedCount = @($Group.Group | Where-Object { $_."事件ID" -eq 4625 }).Count
    $TotalCount = $Group.Count
    $FirstSeen = ($Group.Group | Sort-Object "时间" | Select-Object -First 1)."时间"
    $LastSeen = ($Group.Group | Sort-Object "时间" -Descending | Select-Object -First 1)."时间"

    $RiskLevel = "低危"
    $RiskReason = "暂未发现明显异常"

    if ($FailedCount -ge $FailedThreshold -and $SuccessCount -gt 0) {
        $RiskLevel = "高危"
        $RiskReason = "该 IP 出现大量登录失败后又出现登录成功，疑似爆破成功"
    } elseif ($FailedCount -ge $FailedThreshold) {
        $RiskLevel = "高危"
        $RiskReason = "该 IP 登录失败次数超过阈值，疑似暴力破解"
    } elseif ($FailedCount -ge $MediumThreshold) {
        $RiskLevel = "中危"
        $RiskReason = "该 IP 存在多次登录失败，建议继续观察"
    } elseif ($FailedCount -gt 0 -and $SuccessCount -gt 0) {
        $RiskLevel = "中危"
        $RiskReason = "该 IP 同时存在登录失败和登录成功，需要核对是否为正常管理员行为"
    }

    [PSCustomObject]@{
        "来源IP"   = $Group.Name
        "总次数"   = $TotalCount
        "成功次数" = $SuccessCount
        "失败次数" = $FailedCount
        "首次发现" = $FirstSeen
        "最后发现" = $LastSeen
        "风险等级" = $RiskLevel
        "风险原因" = $RiskReason
    }
}

$IpStats = $IpStats | Sort-Object "失败次数", "总次数" -Descending
$IpStats | Export-ChineseCsv -Path "$OutputDir\来源IP统计.csv"

# ==============================
# 4. 高危 IP 筛选
# ==============================

Write-Host "[+] 正在筛选高危 IP..." -ForegroundColor Cyan

$HighRiskIps = $IpStats | Where-Object {
    $_."风险等级" -eq "高危"
}

if (@($HighRiskIps).Count -gt 0) {
    $HighRiskIps | Export-ChineseCsv -Path "$OutputDir\高危IP筛选.csv"
    Write-Host "[!] 发现高危 IP：$(@($HighRiskIps).Count) 个" -ForegroundColor Red
} else {
    [PSCustomObject]@{
        "提示" = "未发现高危 IP"
        "判断规则" = "单个 IP 登录失败次数 >= $FailedThreshold，或大量失败后出现登录成功"
    } | Export-ChineseCsv -Path "$OutputDir\高危IP筛选.csv"

    Write-Host "[+] 未发现高危 IP。" -ForegroundColor Green
}

# ==============================
# 5. 本地用户
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
        Export-ChineseCsv -Path "$OutputDir\本地用户.csv"
} catch {
    Write-Host "[!] 本地用户导出失败。" -ForegroundColor Yellow
    "本地用户导出失败。" | Out-File "$OutputDir\本地用户_错误.txt" -Encoding UTF8
}

# ==============================
# 6. 管理员组成员
# ==============================

Write-Host "[+] 正在导出管理员组成员..." -ForegroundColor Cyan

try {
    $AdminGroup = Get-LocalGroup | Where-Object {
        $_.SID.Value -eq "S-1-5-32-544" -or $_.SID -eq "S-1-5-32-544"
    }

    if ($AdminGroup) {
        Get-LocalGroupMember -Group $AdminGroup.Name |
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
            Export-ChineseCsv -Path "$OutputDir\管理员组成员.csv"
    } else {
        "未找到本地管理员组。" | Out-File "$OutputDir\管理员组成员.txt" -Encoding UTF8
    }
} catch {
    Write-Host "[!] 管理员组成员导出失败。" -ForegroundColor Yellow
    "管理员组成员导出失败。" | Out-File "$OutputDir\管理员组成员_错误.txt" -Encoding UTF8
}

# ==============================
# 7. 启动项
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
        Export-ChineseCsv -Path "$OutputDir\启动项.csv"
} catch {
    Write-Host "[!] 启动项导出失败。" -ForegroundColor Yellow
    "启动项导出失败。" | Out-File "$OutputDir\启动项_错误.txt" -Encoding UTF8
}

# ==============================
# 8. 计划任务
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
        Export-ChineseCsv -Path "$OutputDir\计划任务.csv"
} catch {
    Write-Host "[!] 计划任务导出失败。" -ForegroundColor Yellow
    "计划任务导出失败。" | Out-File "$OutputDir\计划任务_错误.txt" -Encoding UTF8
}

# ==============================
# 9. 当前网络连接
# ==============================

Write-Host "[+] 正在导出当前网络连接..." -ForegroundColor Cyan

try {
    $NetConnections = Get-NetTCPConnection |
        ForEach-Object {
            $Conn = $_
            $ProcessName = Get-ProcessNameById -ProcessId $Conn.OwningProcess

            [PSCustomObject]@{
                "本地地址" = $Conn.LocalAddress
                "本地端口" = $Conn.LocalPort
                "远程地址" = $Conn.RemoteAddress
                "远程端口" = $Conn.RemotePort
                "连接状态" = $Conn.State
                "进程ID"   = $Conn.OwningProcess
                "进程名"   = $ProcessName
            }
        }

    $NetConnections | Export-ChineseCsv -Path "$OutputDir\当前网络连接.csv"
} catch {
    Write-Host "[!] 当前网络连接导出失败。" -ForegroundColor Yellow
    "当前网络连接导出失败。" | Out-File "$OutputDir\当前网络连接_错误.txt" -Encoding UTF8
    $NetConnections = @()
}

# ==============================
# 10. 危险端口初筛降噪
# ==============================

Write-Host "[+] 正在进行危险端口初筛降噪..." -ForegroundColor Cyan

$DangerPorts = @{
    21    = @{ Service = "FTP"; Risk = "高危"; Desc = "文件传输服务，可能存在弱口令或明文传输风险"; Outbound = $true }
    22    = @{ Service = "SSH"; Risk = "中危"; Desc = "远程管理服务，需确认是否允许外部访问"; Outbound = $true }
    23    = @{ Service = "Telnet"; Risk = "高危"; Desc = "明文远程登录服务，风险较高"; Outbound = $true }
    25    = @{ Service = "SMTP"; Risk = "中危"; Desc = "邮件服务端口，需确认是否为正常业务"; Outbound = $false }
    53    = @{ Service = "DNS"; Risk = "中危"; Desc = "域名解析服务，需确认是否为正常业务"; Outbound = $false }
    80    = @{ Service = "HTTP"; Risk = "中危"; Desc = "Web 服务端口，需确认是否为正常业务"; Outbound = $false }
    110   = @{ Service = "POP3"; Risk = "中危"; Desc = "邮件接收服务，可能存在明文认证风险"; Outbound = $false }
    135   = @{ Service = "RPC"; Risk = "高危"; Desc = "Windows RPC 服务，暴露到公网风险较高"; Outbound = $true }
    139   = @{ Service = "NetBIOS"; Risk = "高危"; Desc = "Windows 文件共享相关端口，暴露风险较高"; Outbound = $true }
    143   = @{ Service = "IMAP"; Risk = "中危"; Desc = "邮件服务端口，需确认是否为正常业务"; Outbound = $false }
    389   = @{ Service = "LDAP"; Risk = "高危"; Desc = "目录服务端口，域环境中需要重点关注"; Outbound = $true }
    443   = @{ Service = "HTTPS"; Risk = "中危"; Desc = "Web 加密服务端口，需确认是否为正常业务"; Outbound = $false }
    445   = @{ Service = "SMB"; Risk = "高危"; Desc = "Windows 文件共享端口，常被用于横向移动和漏洞利用"; Outbound = $true }
    1433  = @{ Service = "MSSQL"; Risk = "高危"; Desc = "SQL Server 数据库端口，需排查弱口令和公网暴露"; Outbound = $true }
    1521  = @{ Service = "Oracle"; Risk = "高危"; Desc = "Oracle 数据库端口，需确认访问来源"; Outbound = $true }
    3306  = @{ Service = "MySQL"; Risk = "高危"; Desc = "MySQL 数据库端口，需排查弱口令和公网暴露"; Outbound = $true }
    3389  = @{ Service = "RDP"; Risk = "高危"; Desc = "远程桌面端口，常见爆破目标"; Outbound = $true }
    5432  = @{ Service = "PostgreSQL"; Risk = "高危"; Desc = "PostgreSQL 数据库端口，需排查弱口令和公网暴露"; Outbound = $true }
    5900  = @{ Service = "VNC"; Risk = "高危"; Desc = "远程控制服务端口，需确认是否授权"; Outbound = $true }
    6379  = @{ Service = "Redis"; Risk = "高危"; Desc = "Redis 服务端口，公网暴露风险极高"; Outbound = $true }
    8080  = @{ Service = "HTTP-Proxy/Tomcat"; Risk = "中危"; Desc = "常见 Web 或代理端口，需确认是否为正常业务"; Outbound = $false }
    9200  = @{ Service = "Elasticsearch"; Risk = "高危"; Desc = "Elasticsearch 服务端口，未授权访问风险较高"; Outbound = $true }
    11211 = @{ Service = "Memcached"; Risk = "高危"; Desc = "Memcached 服务端口，公网暴露风险较高"; Outbound = $true }
    27017 = @{ Service = "MongoDB"; Risk = "高危"; Desc = "MongoDB 数据库端口，需排查未授权访问"; Outbound = $true }
}

$AllDangerPortRecords = @()
$HighRiskListeningPorts = @()
$SuspiciousOutboundConnections = @()

foreach ($Conn in $NetConnections) {
    $LocalPort = 0
    $RemotePort = 0

    [int]::TryParse([string]$Conn."本地端口", [ref]$LocalPort) | Out-Null
    [int]::TryParse([string]$Conn."远程端口", [ref]$RemotePort) | Out-Null

    # 本地危险端口命中
    if ($DangerPorts.ContainsKey($LocalPort)) {
        $Info = $DangerPorts[$LocalPort]
        $IsListening = ([string]$Conn."连接状态" -eq "Listen")

        $Record = [PSCustomObject]@{
            "分类" = if ($IsListening) { "本地危险端口监听" } else { "本地危险端口连接" }
            "检测位置" = "本地端口"
            "端口" = $LocalPort
            "服务" = $Info.Service
            "风险等级" = $Info.Risk
            "风险说明" = $Info.Desc
            "本地地址" = $Conn."本地地址"
            "本地端口" = $Conn."本地端口"
            "远程地址" = $Conn."远程地址"
            "远程端口" = $Conn."远程端口"
            "连接状态" = $Conn."连接状态"
            "进程ID" = $Conn."进程ID"
            "进程名" = $Conn."进程名"
            "安全建议" = if ($IsListening) { "该端口处于监听状态，建议确认是否业务必需；如无必要，应关闭服务或通过防火墙限制访问来源。" } else { "该连接命中本地高风险端口，建议结合远程地址和进程信息进一步判断。" }
        }

        $AllDangerPortRecords += $Record

        if ($IsListening) {
            $HighRiskListeningPorts += $Record
        }
    }

    # 远程危险端口命中：降噪逻辑，只重点记录高风险远程服务端口，排除普通 80/443/DNS 等高频正常连接
    if ($RemotePort -ne 0 -and $DangerPorts.ContainsKey($RemotePort)) {
        $Info = $DangerPorts[$RemotePort]
        $IsPublicRemote = Test-PublicRemoteAddress -Address ([string]$Conn."远程地址")
        $IsEstablishedOrConnecting = ([string]$Conn."连接状态" -in @("Established", "SynSent", "SynReceived"))

        $Record = [PSCustomObject]@{
            "分类" = "远程危险端口连接"
            "检测位置" = "远程端口"
            "端口" = $RemotePort
            "服务" = $Info.Service
            "风险等级" = $Info.Risk
            "风险说明" = $Info.Desc
            "本地地址" = $Conn."本地地址"
            "本地端口" = $Conn."本地端口"
            "远程地址" = $Conn."远程地址"
            "远程端口" = $Conn."远程端口"
            "连接状态" = $Conn."连接状态"
            "进程ID" = $Conn."进程ID"
            "进程名" = $Conn."进程名"
            "安全建议" = "本机正在连接远程高风险服务端口，建议确认是否为正常业务连接，排查异常外联、远程控制或数据库连接行为。"
        }

        $AllDangerPortRecords += $Record

        if ($Info.Outbound -eq $true -and $IsPublicRemote -and $IsEstablishedOrConnecting) {
            $SuspiciousOutboundConnections += $Record
        }
    }
}

if (@($AllDangerPortRecords).Count -gt 0) {
    $AllDangerPortRecords |
        Sort-Object "风险等级", "端口" |
        Export-ChineseCsv -Path "$OutputDir\全部危险端口记录.csv"
} else {
    [PSCustomObject]@{
        "提示" = "未发现危险端口连接或监听"
    } | Export-ChineseCsv -Path "$OutputDir\全部危险端口记录.csv"
}

if (@($HighRiskListeningPorts).Count -gt 0) {
    $HighRiskListeningPorts |
        Sort-Object "风险等级", "端口" |
        Export-ChineseCsv -Path "$OutputDir\高危端口监听.csv"
    Write-Host "[!] 发现高危端口监听：$(@($HighRiskListeningPorts).Count) 条" -ForegroundColor Red
} else {
    [PSCustomObject]@{
        "提示" = "未发现高危端口监听"
    } | Export-ChineseCsv -Path "$OutputDir\高危端口监听.csv"
    Write-Host "[+] 未发现高危端口监听。" -ForegroundColor Green
}

if (@($SuspiciousOutboundConnections).Count -gt 0) {
    $SuspiciousOutboundConnections |
        Sort-Object "风险等级", "端口" |
        Export-ChineseCsv -Path "$OutputDir\可疑外联连接.csv"
    Write-Host "[!] 发现可疑外联连接：$(@($SuspiciousOutboundConnections).Count) 条" -ForegroundColor Red
} else {
    [PSCustomObject]@{
        "提示" = "未发现可疑外联连接"
        "说明" = "当前降噪规则主要关注连接公网高风险服务端口的 Established / SynSent / SynReceived 连接"
    } | Export-ChineseCsv -Path "$OutputDir\可疑外联连接.csv"
    Write-Host "[+] 未发现可疑外联连接。" -ForegroundColor Green
}

# 兼容 v0.1 文件名，方便博客或旧习惯查看
$AllDangerPortRecords | Export-ChineseCsv -Path "$OutputDir\危险端口警报.csv"

# ==============================
# 11. 生成重点关注项
# ==============================

Write-Host "[+] 正在生成重点关注项..." -ForegroundColor Cyan

$FocusItems = @()

foreach ($Item in $HighRiskIps) {
    $FocusItems += [PSCustomObject]@{
        "类型" = "高危IP"
        "风险等级" = $Item."风险等级"
        "对象" = $Item."来源IP"
        "原因" = $Item."风险原因"
        "建议" = "结合用户名、登录时间、登录类型进一步确认是否为爆破或异常登录"
    }
}

foreach ($Item in $HighRiskListeningPorts) {
    $FocusItems += [PSCustomObject]@{
        "类型" = "高危端口监听"
        "风险等级" = $Item."风险等级"
        "对象" = "$($Item."服务")/$($Item."端口")"
        "原因" = $Item."风险说明"
        "建议" = $Item."安全建议"
    }
}

foreach ($Item in $SuspiciousOutboundConnections) {
    $FocusItems += [PSCustomObject]@{
        "类型" = "可疑外联"
        "风险等级" = $Item."风险等级"
        "对象" = "$($Item."远程地址"):$($Item."远程端口")"
        "原因" = $Item."风险说明"
        "建议" = $Item."安全建议"
    }
}

if (@($FocusItems).Count -gt 0) {
    $FocusItems | Export-ChineseCsv -Path "$OutputDir\重点关注项.csv"
} else {
    [PSCustomObject]@{
        "提示" = "暂未发现需要重点关注的高危 IP、端口监听或可疑外联"
    } | Export-ChineseCsv -Path "$OutputDir\重点关注项.csv"
}

# ==============================
# 12. 生成采集摘要
# ==============================

$SuccessCountTotal = @($SuccessLogons).Count
$FailedCountTotal = @($FailedLogons).Count
$IpCountTotal = @($IpStats).Count
$HighRiskIpCount = @($HighRiskIps).Count
$AllDangerPortCount = @($AllDangerPortRecords).Count
$HighRiskListeningCount = @($HighRiskListeningPorts).Count
$SuspiciousOutboundCount = @($SuspiciousOutboundConnections).Count
$FocusItemCount = @($FocusItems).Count

$Summary = @"
WinIR-Helper $Version 应急响应采集摘要

采集时间：$(Get-Date)
日志范围：最近 $Days 天
高危 IP 判断阈值：单个 IP 登录失败次数 >= $FailedThreshold
管理员权限：$IsAdmin

一、登录日志统计
4624 登录成功日志数量：$SuccessCountTotal
4625 登录失败日志数量：$FailedCountTotal

二、来源 IP 统计
来源 IP 数量：$IpCountTotal
高危 IP 数量：$HighRiskIpCount

三、危险端口初筛降噪
全部危险端口记录数量：$AllDangerPortCount
高危端口监听数量：$HighRiskListeningCount
可疑外联连接数量：$SuspiciousOutboundCount

四、重点关注项
重点关注项数量：$FocusItemCount

五、v0.2 更新说明
1. 增强管理员权限检测：默认非管理员权限下主动退出，避免 Security 日志读取失败后生成误导性结果。
2. 优化危险端口初筛：将原本混合输出的危险端口记录拆分为全部危险端口记录、高危端口监听和可疑外联连接。
3. 增加重点关注项：汇总高危 IP、高危端口监听和可疑外联连接，方便优先排查。

六、输出文件说明
1. 4624_登录成功日志.csv：Windows 登录成功日志
2. 4625_登录失败日志.csv：Windows 登录失败日志
3. 来源IP统计.csv：统计每个来源 IP 的成功和失败次数
4. 高危IP筛选.csv：自动筛选疑似爆破或异常登录 IP
5. 本地用户.csv：当前主机本地用户
6. 管理员组成员.csv：本地管理员组成员
7. 启动项.csv：系统启动项
8. 计划任务.csv：系统计划任务
9. 当前网络连接.csv：当前 TCP 网络连接
10. 全部危险端口记录.csv：所有命中危险端口规则的连接或监听记录
11. 高危端口监听.csv：处于 Listen 状态的本地危险端口
12. 可疑外联连接.csv：连接公网高风险服务端口的可疑外联记录
13. 危险端口警报.csv：兼容 v0.1 的危险端口记录文件
14. 重点关注项.csv：优先排查对象汇总
15. 采集摘要.txt：本次采集摘要

七、注意
该工具只做自动化初筛，不能直接作为最终研判结论。
高危 IP、危险端口和可疑外联需要结合实际业务、登录时间、用户名、进程路径、资产用途进一步判断。
"@

$Summary | Out-File "$OutputDir\采集摘要.txt" -Encoding UTF8

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "[+] 信息采集完成！" -ForegroundColor Green
Write-Host "[+] 登录成功日志数量：$SuccessCountTotal" -ForegroundColor Green
Write-Host "[+] 登录失败日志数量：$FailedCountTotal" -ForegroundColor Green
Write-Host "[+] 高危 IP 数量：$HighRiskIpCount" -ForegroundColor Green
Write-Host "[+] 全部危险端口记录数量：$AllDangerPortCount" -ForegroundColor Green
Write-Host "[+] 高危端口监听数量：$HighRiskListeningCount" -ForegroundColor Green
Write-Host "[+] 可疑外联连接数量：$SuspiciousOutboundCount" -ForegroundColor Green
Write-Host "[+] 重点关注项数量：$FocusItemCount" -ForegroundColor Green
Write-Host "[+] 结果目录：$OutputDir" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
